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

HEAVY=0
for arg in "$@"; do
  case "$arg" in
    --heavy) HEAVY=1 ;;
    --down)  docker compose -f compose.yml --profile heavy down -v; exit 0 ;;
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
# compose` is a CLI plugin loaded from the real $HOME and disappears without it.
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
COMPOSE=(docker compose -f compose.yml)
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
  "minio|8008|"
)
# What to fetch from each. Several checks may share a domain: the response
# shapes are what catch regressions, not the number of applications.
#   label | domain | path
CHECKS=(
  "echo json|echo|/json"
  "echo html|echo|/html"
  "echo binary|echo|/bytes/64"
  "grafana|grafana|/api/health"
  "vault|vault|/v1/sys/health"
  "rabbitmq|rabbitmq|/api/overview"
  "loki|loki|/ready"
  "prometheus|prometheus|/-/healthy"
  "minio|minio|/minio/health/live"
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
for entry in "${CHECKS[@]}"; do
  IFS='|' read -r label domain path <<<"$entry"
  port=""; dheader=""
  for d in "${DOMAINS[@]}"; do
    IFS='|' read -r dname dport dhdr <<<"$d"
    [ "$dname" = "$domain" ] && { port="$dport"; dheader="$dhdr"; }
  done
  # The application's own credential goes in too, or an app that answers 401
  # without it looks like it never started.
  hdr=()
  [ -n "$dheader" ] && hdr=(-H "${dheader/=/: }")
  for _ in $(seq 1 60); do
    code=$(curl -s -o /dev/null -w '%{http_code}' -H "Cookie: $COOKIE" ${hdr[@]+"${hdr[@]}"} \
      "http://localhost:$port$path" 2>/dev/null)
    case "$code" in 2*) break ;; esac
    sleep 2
  done
  case "$code" in
    2*) : ;;
    *)  printf '  \033[33m!\033[0m %-26s %s\n' "$label" "still answering $code; measuring anyway" ;;
  esac
done

step "requests"
for entry in "${CHECKS[@]}"; do
  IFS='|' read -r label domain path <<<"$entry"
  result=$(ALBAUTH_HOME="$SANDBOX" python3 mcp_call.py "$ALB" http_request \
    "{\"url\": \"$path\", \"domain\": \"$domain\"}" 2>&1 | head -3 | tr '\n' ' ')
  case "$result" in
    status=2*) pass "$label" "$result" ;;
    *)         fail "$label" "$result" ;;
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
