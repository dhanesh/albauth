#!/usr/bin/env bash
# Drive one MCP tool call over albauth's stdio transport and print the result.
#
# This is the same conversation an MCP client has: initialize, then tools/call.
# It exists so the demo shows real protocol traffic rather than a mock-up.
#
#   demo/mcp-call.sh http_request '{"url":"/v1/users","domain":"local-alb"}'
set -euo pipefail
TOOL="${1:?usage: mcp-call.sh <tool> [json-args]}"
ARGS="${2:-{\}}"

{
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}'
  printf '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"%s","arguments":%s}}\n' "$TOOL" "$ARGS"
  sleep 2
} | albauth serve 2>/dev/null \
  | grep '"id":2' \
  | python3 -c '
import json, sys
envelope = json.load(sys.stdin)
text = envelope["result"]["content"][0]["text"]
try:
    print(json.dumps(json.loads(text), indent=2))
except json.JSONDecodeError:
    print(text)
'
