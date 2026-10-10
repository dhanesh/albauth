# response-passthrough: Application responses come back as results

- id: response-passthrough
- proven: no
- anchors: internal/auth/detect.go

## What it is

An agent calls an API through albauth and gets the application's real answer —
including error pages, redirects and presigned-download links — as a normal
result with its status, headers and body. Only the login proxy's own "no
session" answers make albauth log in again.

## How to reach it

- MCP tool `http_request` with an absolute `url`, or a path plus `domain`.

## Drive it

```sh
H fixture --instance "$INSTANCE" alb-api reset
H call --instance "$INSTANCE" \
  'http_request={"url":"{host:alb-api}/html/404"}' \
  'http_request={"url":"{host:alb-api}/html/502"}' \
  'http_request={"url":"{host:alb-api}/redirect/same/302"}' \
  'http_request={"url":"{host:alb-api}/redirect/cross/302"}' \
  'http_request={"url":"{host:alb-api}/json"}' > .verify-run/$INSTANCE/call.json
H fixture --instance "$INSTANCE" alb-api hits > .verify-run/$INSTANCE/hits.json
```

Exit code 0 for both. Expected output in `call.json`: every call has
`"isError": false`; `data.status` is 404, 502, 302, 302 and 200 in order;
every `data.relogin_performed` is `false`; the redirects carry their
`location` header. In `hits.json` each route shows exactly 1.

## Proof

The statuses above, plus the side effect: the fixture saw each route once (no
retry) and `GET /` (the login probe) not at all, so no browser login ran.

## Gotchas

- Before the F1/F3 fixes, the 404, 502 and both redirects came back as
  `"isError": true` with `"error": "auth_loop"`, and the fixture showed 2 hits
  each plus `GET /` — a Chrome window opened for every one. If you see that,
  the binary is stale.
- A cross-host redirect still re-logs in when its query carries both
  `client_id` and `response_type`: that is an authorization request to an IdP
  not listed in `idp_hostnames` (see session-relogin).
- A 401 or 403 HTML page is still the proxy's sign-in page by design: see
  session-relogin.
