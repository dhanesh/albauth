#!/usr/bin/env bash
# Re-record demo.cast, the asciinema recording on the project site.
#
#   demo/cast/record.sh [out.cast]
#
# Needs the tool-sweep stack (test/tools) running — only the proxy layer and
# Grafana: `docker-compose -f test/tools/compose.yml up -d traefik grafana` —
# plus asciinema, jq and an albauth on PATH (the released build, so the demo
# shows what people install). Everything albauth writes goes to a throwaway
# HOME, never to your own config or keychain.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE/demo.cast}"

for _ in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8001/api/user || true)
  [ "$code" = "401" ] && break
  sleep 1
done
[ "$code" = "401" ] || { echo "the proxy stack is not answering on :8001" >&2; exit 1; }

SANDBOX="$(mktemp -d /tmp/albauth-demo.XXXX)"
trap 'rm -rf "$SANDBOX"' EXIT
mkdir -p "$SANDBOX/home"
# File storage keeps the keychain, and its permission prompts, out of the take.
printf '[settings]\nstorage = "file"\n' > "$SANDBOX/home/.albauth.toml"

HOME="$SANDBOX/home" PS1='$ ' asciinema rec --overwrite --quiet \
  --window-size 104x26 --idle-time-limit 3 \
  --title "albauth: an API behind oauth2-proxy, called over MCP" \
  -c "$HERE/scene.sh" "$OUT"
# The header records the scene's absolute path and the recording shell, which
# say nothing about albauth and something about whoever recorded it.
{ head -1 "$OUT" | jq -c 'del(.command, .env)'; tail -n +2 "$OUT"; } > "$OUT.tmp"
mv "$OUT.tmp" "$OUT"
echo "wrote $OUT"
