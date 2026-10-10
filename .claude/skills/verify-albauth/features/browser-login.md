# browser-login: Logging in with the browser

- id: browser-login
- proven: no
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
$H session --instance "$INSTANCE" o2-api > .verify-run/$INSTANCE/before.json
$H cli --instance "$INSTANCE" -- config add-domain signin --base-url {host:o2-api} --no-probe \
  --cookie-prefix _oauth2_proxy --login-probe-path /oauth2/sign_in
$H cli --instance "$INSTANCE" -- auth login o2-api --force > .verify-run/$INSTANCE/force.json
$H session --instance "$INSTANCE" o2-api > .verify-run/$INSTANCE/after.json
```

Replace `{host:o2-api}` with the `o2-api` URL from `launch` output (the `cli`
subcommand does not expand it). Exit code 0 for each; `force.json` has
`"exit": 0`. Expected: `after.json` has a different cookie sha256 from
`before.json` and `valid_at_proxy: true`. For the sign-in-page case run
`$H cli --instance "$INSTANCE" -- auth login signin` then
`$H session --instance "$INSTANCE" signin`: the only stored cookie name is
`_oauth2_proxy` — never `_oauth2_proxy_csrf`.

## Proof

The stored cookie names and the change of value, plus the proxy accepting the
new session.

## Gotchas

- Chrome opens for a moment; the fixture IdP approves at once.
- Before the F4 fix the `signin` login stores `_oauth2_proxy_csrf`, and before
  the force fix the sha256 does not change.
