# session-storage: Sessions are stored and reported

- id: session-storage
- proven: 537e1adcf92edaa17d255de3096e8e0a519c50bf
- anchors: internal/session

## What it is

A user imports or logs in once and the session survives restarts: in the OS
keychain where it can hold the session, otherwise in a 0600 file.
`albauth auth status` and the `auth_status` tool report which store holds it.

## How to reach it

- `albauth auth import <domain>` (headless), `albauth auth login <domain>`.
- `albauth auth status`, MCP tool `auth_status`.

## Drive it

```sh
$H import --instance "$INSTANCE" alb-api --big > .verify-run/$INSTANCE/import.json
$H session --instance "$INSTANCE" alb-api > .verify-run/$INSTANCE/session.json
$H call --instance "$INSTANCE" 'auth_status={"domain":"alb-api"}' 'http_request={"url":"{host:alb-api}/json"}' > .verify-run/$INSTANCE/status.json
```

Exit code 0 for each. Expected: `session.json` lists two cookies,
`AWSELBAuthSessionCookie-0` (len 4000) and `-1` (len 1200), with
`valid_at_proxy: true`; `status.json` shows `authenticated: true` and the
request returns 200.

## Proof

The two-chunk session is persisted (the file under the instance HOME) and
works at the proxy.

## Gotchas

- The harness config uses `storage = "file"`. The macOS keychain path (and its
  ~3 KB limit) is not reachable from a sandboxed HOME: the keychain fallback is
  proven by the darwin-only Go test named in the plan, which calls the real
  go-keyring refusal without writing to the keychain.
