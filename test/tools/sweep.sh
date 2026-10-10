#!/usr/bin/env bash
# ============================================================================
# test/tools/sweep.sh — run albauth against real applications behind a real
# OIDC proxy, and report which ones still work.
#
# Why this exists: albauth's unit tests cannot tell you that a change broke
# Grafana, because the thing that breaks is never albauth's own logic — it is
# an assumption about how some application answers. Every regression found so
# far came from a real application: an HTML page judged an expired session, a
# binary body corrupted by a string conversion, a 401 that meant "wrong token"
# rather than "logged out", a CSRF token that needed the session cookie back.
#
# The stack is headless end to end: dex issues static passwords, so the login
# is a scripted HTTP exchange rather than a browser, and the resulting cookie
# is handed to albauth with `auth import`.
#
# Usage:
#   ./sweep.sh                 # bring the stack up if needed, then sweep
#   ./sweep.sh --heavy         # include the slow starters (superset, jenkins…)
#   ./sweep.sh --down          # tear the stack down
#
# Exit 0 means every checked tool answered as expected.
# ============================================================================
set -uo pipefail
cd "$(dirname "$0")"
ROOT="$(cd ../.. && pwd)"

# Compose comes in two shapes: the `docker compose` CLI plugin, and the
# standalone `docker-compose` binary. Use whichever works, so the sweep runs
# on a machine with either — and say so plainly when there is neither.
if docker compose version >/dev/null 2>&1; then
  DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1 && docker-compose version >/dev/null 2>&1; then
  DC=(docker-compose)
else
  echo "neither 'docker compose' nor 'docker-compose' works; install one of them" >&2
  exit 1
fi

HEAVY=0
for arg in "$@"; do
  case "$arg" in
    --heavy) HEAVY=1 ;;
    --down)  "${DC[@]}" -f compose.yml --profile heavy down -v; exit $? ;;
    --help|-h) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

IDP=http://localhost:5556
PROXY=http://localhost:8000
EMAIL=tester@example.com
PASSWORD=password

# Keep every trace of the sweep out of the caller's real albauth setup: its own
# config, its own session store, its own browser profile.
#
# HOME is redirected per albauth call rather than exported, because `docker
# compose` is a CLI plugin loaded from the real $HOME (and a standalone
# docker-compose may sit behind a version-manager shim) and disappears without it.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
SANDBOX="$WORK/home"
mkdir -p "$SANDBOX"
ALB="$WORK/albauth"
alb() { HOME="$SANDBOX" "$ALB" "$@"; }

FAILURES=()
pass() { printf '  \033[32m✓\033[0m %-26s %s\n' "$1" "${2:-}"; }
fail() { FAILURES+=("$1"); printf '  \033[31m✗\033[0m %-26s %s\n' "$1" "${2:-}"; }
step() { printf '\n[%s]\n' "$1"; }

# --------------------------------------------------------------- 1. the stack
step "stack"
COMPOSE=("${DC[@]}" -f compose.yml)
[ "$HEAVY" = 1 ] && COMPOSE+=(--profile heavy)
if ! UP=$("${COMPOSE[@]}" up -d 2>&1); then
  echo "could not start the stack:" >&2
  echo "$UP" | tail -15 >&2
  exit 1
fi
pass "containers up" "$( "${COMPOSE[@]}" ps --services 2>/dev/null | tr '\n' ' ')"

# Wait for the proxy layer, which everything else depends on.
for _ in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$PROXY/oauth2/start?rd=%2F" 2>/dev/null)
  [ "$code" = "302" ] && break
  sleep 1
done
[ "${code:-}" = "302" ] && pass "proxy layer answering" || { fail "proxy layer never came up"; exit 1; }

# ---------------------------------------------------------------- 2. albauth
step "albauth"
( cd "$ROOT" && go build -o "$ALB" ./cmd/albauth ) || { fail "build failed"; exit 1; }
pass "built" "$(alb version)"

# ------------------------------------------------------------------ 3. login
# A scripted OIDC login: start → dex → credentials → approval → callback. The
# cookie that falls out is the same one a browser would have got.
step "login (headless)"
JAR="$WORK/jar.txt"
hop() { curl -s -b "$JAR" -c "$JAR" -o /dev/null -w '%{redirect_url}' "$@"; }
abs() { case "$1" in http*) echo "$1" ;; *) echo "$IDP$1" ;; esac; }

URL=$(hop "$PROXY/oauth2/start?rd=%2F")
for _ in 1 2 3; do
  case "$URL" in *"/login"*) break ;; esac
  URL=$(abs "$(hop "$URL")")
done
URL=$(abs "$(hop --data-urlencode "login=$EMAIL" --data-urlencode "password=$PASSWORD" "$URL")")
for _ in 1 2 3; do
  [ -z "$URL" ] && break
  URL=$(abs "$(hop "$URL")")
done
COOKIE=$(awk '/_oauth2_proxy/{print $6"="$7}' "$JAR" | head -1)
if [ -z "$COOKIE" ]; then
  fail "no session cookie" "the scripted login did not complete"
  exit 1
fi
pass "session cookie" "${COOKIE%%=*} (${#COOKIE} bytes)"

# ------------------------------------------------------------------ 4. tools
# One domain per application, because albauth refuses to let two domains claim
# the same host — and rightly so.
#   name | port | headers (the application's own layer-2 credential)
DOMAINS=(
  "echo|8000|"
  "grafana|8001|Authorization=Basic YWRtaW46YWRtaW4="
  "vault|8004|X-Vault-Token=root-token-abc"
  "rabbitmq|8005|Authorization=Basic Z3Vlc3Q6Z3Vlc3Q="
  "loki|8006|"
  "prometheus|8007|"
  "s3|8008|"
)
# What to fetch from each, and what albauth must answer. Several checks may
# share a domain: the response shapes are what catch regressions, not the
# number of applications.
#   label | domain | path | expect | header
#
# expect is a shell pattern for the status albauth returns (2*, 302, 401…),
# or !token for "the result must not contain token" (e.g. !auth_loop). It
# defaults to 2*. A non-2xx expectation is how the sweep proves albauth hands
# an application's own answer back instead of mistaking it for a lost session.
#
# header, optional, is a Name=Value sent with this request only. albauth lets a
# request header override the domain's own, which is how one check can present
# a wrong application credential without a second domain for the same host.
CHECKS=(
  "echo json|echo|/json"
  "echo html|echo|/html"
  "echo binary|echo|/bytes/64"
  "echo same-host redirect|echo|/redirect-to?url=/get&status_code=302|302"
  "echo presigned redirect|echo|/redirect-to?url=https://example.com/bucket/obj%3FX-Amz-Signature%3Dx&status_code=302|302"
  "grafana|grafana|/api/health"
  "grafana html 404|grafana|/no-such-page|404"
  "grafana wrong token|grafana|/api/org|401|Authorization=Bearer glsa_not_a_real_token_0000"
  "vault|vault|/v1/sys/health"
  "rabbitmq|rabbitmq|/api/overview"
  "loki|loki|/ready"
  "prometheus|prometheus|/-/healthy"
  "prometheus redirect+body|prometheus|/|302"
  "seaweedfs s3 listing|s3|/"
)
if [ "$HEAVY" = 1 ]; then
  DOMAINS+=(
    "hasura|8002|x-hasura-admin-secret=supersecret123"
    "metabase|8003|"
    "superset|8009|"
    "jenkins|8010|"
  )
  CHECKS+=(
    "hasura|hasura|/v1/version"
    "metabase|metabase|/api/health"
    "superset|superset|/health"
    "jenkins|jenkins|/login"
  )
fi

step "configuring domains"
for entry in "${DOMAINS[@]}"; do
  IFS='|' read -r name port header <<<"$entry"
  args=(config add-domain "$name" --base-url "http://localhost:$port" --login-timeout-seconds 10)
  [ -n "$header" ] && args+=(--header "$header")
  if out=$(alb "${args[@]}" 2>&1); then
    # The probe is expected to work the proxy out on its own. If it stops doing
    # that, every new user has to discover these settings by hand, so treat it
    # as a failure of the sweep rather than a detail.
    if grep -q "login starts at /oauth2/start" <<<"$out"; then
      pass "$name configured" "proxy detected"
    else
      fail "$name configured" "the probe did not detect the forward-auth proxy"
    fi
  else
    fail "$name configure" "$(head -3 <<<"$out" | tr '\n' ' ')"
  fi
  if ! imp=$(printf '%s\n' "$COOKIE" | alb auth import "$name" 2>&1); then
    fail "$name import" "$(tail -2 <<<"$imp" | tr '\n' ' ')"
  fi
done

# Applications come up slower than their containers do, and a sweep that
# reports "loki: 503" because Loki was still starting teaches people to ignore
# it. Wait for each endpoint with curl first, then measure through albauth.
step "waiting for applications"
# Does a status code meet an expectation? A !token expectation is about the
# body of albauth's answer, so for waiting purposes any real answer will do.
meets() {
  case "$2" in
    '!'*) case "$1" in 000|502|503|504) return 1 ;; *) return 0 ;; esac ;;
  esac
  # shellcheck disable=SC2254 # $2 is a pattern on purpose
  case "$1" in $2) return 0 ;; *) return 1 ;; esac
}
for entry in "${CHECKS[@]}"; do
  IFS='|' read -r label domain path expect override <<<"$entry"
  expect="${expect:-2*}"
  port=""; dheader=""
  for d in "${DOMAINS[@]}"; do
    IFS='|' read -r dname dport dhdr <<<"$d"
    [ "$dname" = "$domain" ] && { port="$dport"; dheader="$dhdr"; }
  done
  # The application's own credential goes in too, or an app that answers 401
  # without it looks like it never started. A per-check header replaces it.
  [ -n "$override" ] && dheader="$override"
  hdr=()
  [ -n "$dheader" ] && hdr=(-H "${dheader/=/: }")
  for _ in $(seq 1 60); do
    code=$(curl -s -o /dev/null -w '%{http_code}' -H "Cookie: $COOKIE" ${hdr[@]+"${hdr[@]}"} \
      "http://localhost:$port$path" 2>/dev/null)
    meets "$code" "$expect" && break
    sleep 2
  done
  meets "$code" "$expect" ||
    printf '  \033[33m!\033[0m %-26s %s\n' "$label" "still answering $code; measuring anyway"
done

step "requests"
for entry in "${CHECKS[@]}"; do
  IFS='|' read -r label domain path expect override <<<"$entry"
  expect="${expect:-2*}"
  args="{\"url\": \"$path\", \"domain\": \"$domain\""
  if [ -n "$override" ]; then
    args+=", \"headers\": {\"${override%%=*}\": \"${override#*=}\"}"
  fi
  args+="}"
  result=$(ALBAUTH_HOME="$SANDBOX" python3 mcp_call.py "$ALB" http_request "$args" 2>&1 |
    head -3 | tr '\n' ' ')
  case "$expect" in
    '!'*)
      token="${expect#!}"
      case "$result" in
        *"$token"*) fail "$label" "expected no $token: $result" ;;
        *)          pass "$label" "$result" ;;
      esac ;;
    *)
      # shellcheck disable=SC2254 # $expect is a pattern on purpose
      case "$result" in
        status=$expect\ *) pass "$label" "$result" ;;
        *)                 fail "$label" "expected status=$expect: $result" ;;
      esac ;;
  esac
done

# ----------------------------------------------------------------- 5. verdict
step "verdict"
if [ ${#FAILURES[@]} -eq 0 ]; then
  echo "  ALL TOOLS PASSED"
  exit 0
fi
printf '  %d FAILURE(S):\n' "${#FAILURES[@]}"
printf '    - %s\n' "${FAILURES[@]}"
exit 1
