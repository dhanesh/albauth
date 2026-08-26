#!/usr/bin/env python3
"""Issue one MCP tool call against `albauth serve` and print the result.

albauth has no CLI for making requests — the whole point is the MCP surface —
so the sweep has to speak JSON-RPC over stdio the way a real client does.
That also means the sweep exercises the same code path an agent would.
"""
import json
import os
import subprocess
import sys


def call(binary: str, tool: str, arguments: dict) -> dict:
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                    "clientInfo": {"name": "albauth-sweep", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": tool, "arguments": arguments}},
    ]
    env = os.environ.copy()
    # The sweep sandboxes albauth's config and session store by moving HOME.
    # It is passed for the child only: this script itself may be running from a
    # version-manager shim that needs the real HOME to resolve an interpreter.
    if env.get("ALBAUTH_HOME"):
        env["HOME"] = env.pop("ALBAUTH_HOME")
    proc = subprocess.Popen([binary, "serve"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, env=env)
    try:
        out, err = proc.communicate("".join(json.dumps(r) + "\n" for r in requests), timeout=60)
    except subprocess.TimeoutExpired:
        # Almost always albauth waiting on an interactive login the sweep can
        # never satisfy. Report it rather than stalling the whole run.
        proc.kill()
        return {"error": {"message": "albauth did not answer within 60s "
                                     "(waiting for an interactive login?)"}}
    for line in out.splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get("id") == 2:
            return msg
    return {"error": {"message": "no response from albauth serve", "stderr": err[-400:]}}


def main() -> int:
    binary, tool = sys.argv[1], sys.argv[2]
    arguments = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    msg = call(binary, tool, arguments)

    if "error" in msg:
        print("ERROR " + json.dumps(msg["error"])[:300])
        return 1
    text = msg.get("result", {}).get("content", [{}])[0].get("text", "")
    if msg.get("result", {}).get("isError"):
        print("ERROR " + text[:300])
        return 1
    try:
        # strict=False: response bodies legitimately contain raw control bytes.
        body = json.loads(text, strict=False)
    except ValueError:
        print(text[:300])
        return 0
    if "status" in body:
        print(f"status={body['status']} "
              f"type={body.get('headers', {}).get('content-type', '-').split(';')[0]} "
              f"relogin={body.get('relogin_performed')} "
              f"base64={body.get('body_base64', False)}")
    else:
        print(json.dumps(body)[:300])
    return 0


if __name__ == "__main__":
    sys.exit(main())
