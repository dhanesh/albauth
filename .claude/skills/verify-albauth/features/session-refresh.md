# session-refresh: A refreshed proxy session is kept

- id: session-refresh
- proven: e0fe861eb551f560c26d70606cdbfce6db70c061
- anchors: internal/httpx/jar.go

## What it is

When the login proxy reissues its session cookie on a response, albauth stores
the new value, so the session lives as long as the proxy keeps renewing it.

## How to reach it

- MCP tool `http_request` to any route whose response sets a cookie in the
  domain's session cookie family.

## Drive it

```sh
H session --instance "$INSTANCE" alb-api > .verify-run/$INSTANCE/before.json
H call --instance "$INSTANCE" 'http_request={"url":"{host:alb-api}/rotate"}' > .verify-run/$INSTANCE/rotate.json
H session --instance "$INSTANCE" alb-api > .verify-run/$INSTANCE/after.json
```

Exit code 0 for each. Expected: `rotate.json` status 200 with no `set-cookie`
header in `data.headers`; the cookie sha256 in `after.json` differs from
`before.json`, and `after.json` shows `valid_at_proxy: true`.

## Proof

The stored session changed to the proxy's new value (the file side effect),
while the value never reached the tool result.

## Gotchas

- Only a response judged authenticated is taken into the store; the response
  that triggers a re-login is not, so a fixture route that sets a new cookie
  must also answer 200 to the session it was sent.
- The jar still drops session-family cookies; the store is where the new value
  lives, so `/rotate` followed by `/json` must send it exactly once.
- A response that sets the same value and attributes again writes nothing, so
  the sha256 only changes when the proxy really issued a new value.
