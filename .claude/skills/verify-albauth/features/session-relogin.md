# session-relogin: Expired sessions re-authenticate once

- id: session-relogin
- proven: e0fe861eb551f560c26d70606cdbfce6db70c061
- anchors: internal/httpx/do.go

## What it is

When the login proxy says the session is gone, albauth logs in again (a real
browser, usually click-free) and retries the request once, so the agent gets
the answer without noticing. A write is resent only when the proxy's redirect
to the identity provider proves the application never saw it. On a domain
that sets `session_check_path` (for oauth2-proxy, `/oauth2/auth`) a 401 is
checked against that proxy endpoint first, so the application refusing a token
is returned as the application's own 401.

## How to reach it

- MCP tool `http_request` (any method) on a configured domain after the
  proxy revokes the session.

## Drive it

```sh
H fixture --instance "$INSTANCE" alb-api expire
H fixture --instance "$INSTANCE" alb-api reset
H call --instance "$INSTANCE" 'http_request={"url":"{host:alb-api}/json"}' > .verify-run/$INSTANCE/relogin.json
H fixture --instance "$INSTANCE" alb-api expire
H call --instance "$INSTANCE" 'http_request={"url":"{host:alb-api}/html/500","method":"POST","body":"{}"}' > .verify-run/$INSTANCE/post.json
H fixture --instance "$INSTANCE" alb-api hits > .verify-run/$INSTANCE/hits.json
H fixture --instance "$INSTANCE" alb-api reset
H call --instance "$INSTANCE" 'http_request={"url":"{host:alb-api}/html/403","method":"POST","body":"{}"}' > .verify-run/$INSTANCE/post403.json
H fixture --instance "$INSTANCE" alb-api hits > .verify-run/$INSTANCE/hits403.json
C=.verify-run/$INSTANCE/config.toml
awk '{print} /^name = "o2-api"$/{print "session_check_path = \"/oauth2/auth\""}' "$C" > "$C.new" && mv "$C.new" "$C"
H call --instance "$INSTANCE" 'http_request={"url":"{host:o2-api}/app401"}' > .verify-run/$INSTANCE/app401.json
H session --instance "$INSTANCE" alb-api > .verify-run/$INSTANCE/session.json
```

Exit code 0 for each. Expected: `relogin.json` has status 200 and
`relogin_performed: true`; `post.json` has status 500 (the fixture's IdP
redirect proved the proxy intercepted the first attempt, so one resend after
login is correct); `hits.json` shows `POST /html/500` exactly 1;
`post403.json` is `isError: true` with `"error": "resend_required"` (an HTML
403 is not an IdP redirect, so the write is not resent) and `hits403.json`
shows `POST /html/403` exactly 1 and a re-login (`GET /` at least 1); `app401.json`
has status 401 with the application's `invalid application token` body,
`isError: false`; `session.json` shows `valid_at_proxy: true`.

## Proof

The re-login (a new cookie sha256 in `session.json`, `relogin_performed: true`)
and its side effect (the application saw each write once).

## Gotchas

- Each re-login opens a Chrome window for about a second.
- The harness config sets `treat_401_as_expired` and `/oauth2/start` for the
  oauth2 domain but not `session_check_path`; the `awk` step above inserts it
  (as `prove.py app-refusal` does). Without it, `app401.json` is `auth_loop`
  after a browser login.
