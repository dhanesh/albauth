#!/usr/bin/env bash
# Sign in to the tool-sweep stack without a browser and hand the session to
# albauth: oauth2-proxy → dex → static password → callback → `auth import`.
# The same exchange test/tools/sweep.sh does; it stands in for the browser
# window `albauth auth login` would open.
#
#   demo/cast/headless-login.sh <domain>
set -euo pipefail
DOMAIN="${1:?usage: headless-login.sh <domain>}"
IDP=http://localhost:5556
PROXY=http://localhost:8000
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

hop() { curl -s -b "$JAR" -c "$JAR" -o /dev/null -w '%{redirect_url}' "$@"; }
abs() { case "$1" in http*) echo "$1" ;; *) echo "$IDP$1" ;; esac; }

URL=$(hop "$PROXY/oauth2/start?rd=%2F")
for _ in 1 2 3; do
  case "$URL" in *"/login"*) break ;; esac
  URL=$(abs "$(hop "$URL")")
done
URL=$(abs "$(hop --data-urlencode "login=tester@example.com" --data-urlencode "password=password" "$URL")")
for _ in 1 2 3; do
  [ -z "$URL" ] && break
  URL=$(abs "$(hop "$URL")")
done

COOKIE=$(awk '/_oauth2_proxy/{print $6"="$7}' "$JAR" | head -1)
[ -n "$COOKIE" ] || { echo "login did not complete" >&2; exit 1; }
printf '%s\n' "$COOKIE" | albauth auth import "$DOMAIN" 2>&1 | tail -1
