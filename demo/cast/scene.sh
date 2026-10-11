#!/usr/bin/env bash
# The scene recorded into the demo on https://dhanesh.github.io/albauth/.
# Run by record.sh inside `asciinema rec`; not meant to be run on its own.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PATH="$HERE:$HERE/..:$PATH"

# Type a command out, then run it for real.
run() {
  printf '\033[1;32m$\033[0m '
  local s="$1" i
  for ((i = 0; i < ${#s}; i++)); do printf '%s' "${s:i:1}"; sleep 0.03; done
  sleep 0.4; printf '\n'
  eval "$1"
  sleep "${2:-1.5}"
}
say() { printf '\033[2m# %s\033[0m\n' "$1"; sleep 1; }

clear
say "Grafana sits behind oauth2-proxy and Traefik forwardAuth. A plain request gets turned away:"
run "curl -si http://localhost:8001/api/user | head -1"
say "Add it. albauth probes the domain and works out how its login behaves."
say "The Authorization header is Grafana's own credential: the second layer, behind the proxy."
run "albauth config add-domain grafana --base-url http://localhost:8001 --header 'Authorization=Basic YWRtaW46YWRtaW4='" 2.5
say "Log in once. Normally 'albauth auth login grafana' opens a browser; here dex signs in headlessly."
run "headless-login.sh grafana"
run "albauth auth status"
say "Now the model calls the API over MCP, as any client would (real stdio JSON-RPC):"
run "mcp-call.sh http_request '{\"url\":\"/api/user\",\"domain\":\"grafana\"}' | jq '{status, authenticated, body: (.body | fromjson | {login, email})}'" 4
say "200, through both layers, with no login prompt."
sleep 2
