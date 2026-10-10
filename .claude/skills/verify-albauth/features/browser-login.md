# browser-login: Logging in with the browser

- id: browser-login
- proven: 301064edf87ab2502be9fa7b6137764c03b544ba
- anchors: internal/browser, internal/auth/login.go

## What it is

`albauth auth login <domain>` (or the `auth_login` tool) opens Chrome at the
domain's login path, waits for the user to finish the identity provider's
flow, and keeps the proxy's session cookie — only once the page has really
settled on the API host with a non-error status, and only cookies that are the
session itself (not a CSRF cookie that shares its prefix). `force: true`
starts over with a new session.

## How to reach it

- `albauth auth login <domain> [--force]`; MCP tool `auth_login`
  `{"domain": …, "force": true}`.

## Drive it

```sh
H fixture --instance "$INSTANCE" alb-api 'hold?seconds=40'
H call --instance "$INSTANCE" 'auth_login={"domain":"alb-api","force":true}' > .verify-run/$INSTANCE/force1.json
H session --instance "$INSTANCE" alb-api > .verify-run/$INSTANCE/first.json
H call --instance "$INSTANCE" 'auth_login={"domain":"alb-api","force":true}' > .verify-run/$INSTANCE/force2.json
H session --instance "$INSTANCE" alb-api > .verify-run/$INSTANCE/second.json
```

Exit code 0 for each, both calls `"isError": false`. Expected: the cookie sha256 in
`second.json` differs from `first.json`, and `second.json` shows
`valid_at_proxy: true` (the first forced login leaves a live cookie in the
browser profile; a real force must not reuse it).

The `hold` makes the first login wait 40 s on the fixture's identity provider
after the cookie is set. Chrome writes cookies to disk on a timer of about
30 s, so without the hold the window closes before the cookie reaches the
profile, and a force that clears nothing would still pass.

For the sign-in-page case, point `o2-api` at oauth2-proxy's sign-in page and log in:

```sh
sed -i.bak 's#^login_probe_path = "/oauth2/start"#login_probe_path = "/oauth2/sign_in"#' .verify-run/$INSTANCE/config.toml
H call --instance "$INSTANCE" 'auth_login={"domain":"o2-api","force":true}' > .verify-run/$INSTANCE/signin.json
H session --instance "$INSTANCE" o2-api > .verify-run/$INSTANCE/signin-session.json
```

Exit code 0. Expected: the only stored cookie name is `_oauth2_proxy` — never
`_oauth2_proxy_csrf` — and `valid_at_proxy: true`. `scripts/prove.py force` and
`scripts/prove.py signin-page` run both checks in one command each.

## Proof

The stored cookie names and the change of value, plus the proxy accepting the
new session.

## Gotchas

- Chrome opens for a moment; the fixture IdP approves at once.
- Before the F4 fix the `signin` login stores `_oauth2_proxy_csrf`, and before
  the force fix the sha256 does not change.
