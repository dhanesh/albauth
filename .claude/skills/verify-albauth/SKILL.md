---
name: verify-albauth
description: >-
  Prove a change to albauth works by driving the real binary the way an MCP
  client and a user do: build it, run `albauth serve` over stdio against a local
  stand-in for the login proxy, identity provider and application, and record
  SHA-bound evidence of what came back. Use when a change touches request
  handling, session detection, cookie handling, browser login, storage,
  redaction or domain setup, or when factory-conductor's evidence gate asks for
  proof of an albauth feature.
---

# verify-albauth

albauth is a stdio MCP server (plus a small CLI) that calls HTTP APIs sitting
behind a login proxy — an AWS ALB `authenticate-oidc` rule, oauth2-proxy,
Traefik `forwardAuth` — by replaying a session cookie captured from one real
browser login. Its user-facing surface is the five-plus MCP tools
(`http_request`, `auth_login`, `auth_status`, `auth_logout`, `list_domains`,
and any added since) and the `albauth auth …` / `albauth config …` commands.

This skill drives that surface through `scripts/harness.py`. Each instance
builds the binary from the checkout under test, sandboxes `HOME` and
`ALBAUTH_CONFIG`, and starts `scripts/fixture.py` three times: an ALB-style
proxy (domain `alb-api`), an oauth2-proxy-style proxy (domain `o2-api`) and a
third ALB-style host that is deliberately **not** configured. The fixture's
identity provider approves every login at once, so a real Chrome login
completes with nobody at the keyboard. Every harness command prints JSON.

The fixture is the stand-in for systems albauth does not own (the proxy, the
IdP, the application): that is the production boundary, so mocking it is
allowed. albauth itself is always the real binary, driven only through its MCP
tools and CLI.

Session variables, used by every command below:

```sh
SKILL=.claude/skills/verify-albauth            # this skill's directory, from the repo root
INSTANCE=v1                                    # any short name; one per concurrent verifier
VERIFIER=<your agent id>                       # under factory-conductor: the id the verifier brief gives you;
                                               # working alone: a stable name for this session,
                                               # never the author of the change being proven
H="python3 $SKILL/scripts/harness.py"
```

Run every command from the root of the checkout under test (a factory-conductor
task worktree is a checkout root). Under factory-conductor, also
`export VERIFY_EVIDENCE_DIR=<run root>/.verify` so records land where the
conductor reads them.

For the real-world layers that this skill does not replace — the oauth2-proxy
and real-application sweep (`./test/tools/sweep.sh`, Colima) and the real-ALB
MiniStack suite (`test/ministack/`, real Chrome + Cognito) — see the repo's
`CLAUDE.md` and `test/ministack/README.md`.

## Launch

```sh
$H launch --instance "$INSTANCE"
```

What it does, per instance:

- claims three ports with `scripts/verify_evidence.py port --instance "$INSTANCE"` (and the
  suffixed claims `$INSTANCE.o2`, `$INSTANCE.unconfigured`): `alb-api`, `o2-api` and the
  unconfigured host;
- builds `./cmd/albauth` into `.verify-run/$INSTANCE/albauth`;
- writes `.verify-run/$INSTANCE/config.toml` (storage `file`) and uses
  `.verify-run/$INSTANCE/home` as `HOME`, so the data store (`sessions.json`) and the
  auth session (browser profiles under `home/Library/Application Support/albauth/browser/`)
  belong to this instance alone;
- starts the three fixtures and imports a fresh session into both configured
  domains with `albauth auth import`.

Ready when it prints `"ready": true` and exits 0. It waits at most 15 s for the
fixtures' `/__fixture/health` to answer with this instance's name, then exits 2
with the hosts still pending. `go build` can add up to a minute on a cold cache.

## Doctor

```sh
$H doctor --instance "$INSTANCE"
python3 $SKILL/scripts/verify_evidence.py doctor --instance "$INSTANCE" --ok \
  --check fixtures=pass --check binary=pass --check config=pass
```

`doctor` is read-only: it asks each fixture's health route (it must name this
instance, which proves this instance owns the port), runs `albauth version` and
`albauth config validate`. Exit 0 and `"ok": true` means the instance is worth
driving. Record `--fail` with the failing `--check` names when it is not, and
relaunch (Cleanup first).

## Drive

The recipes per feature are in `features/`. The building blocks:

```sh
# One or more MCP tool calls in a single `albauth serve`, answered in order.
# "{host:alb-api}" expands to that fixture's URL. Exit 0 when every call answered.
$H call --instance "$INSTANCE" 'http_request={"url":"{host:alb-api}/json"}'

# The fixture's own view: how often the application was hit, by method and route.
$H fixture --instance "$INSTANCE" alb-api reset
$H fixture --instance "$INSTANCE" alb-api hits

# Revoke every session at the proxy (what an expiry looks like from outside).
$H fixture --instance "$INSTANCE" alb-api expire

# The stored session: cookie names, lengths, sha256 prefixes — never values —
# and whether the proxy still accepts it.
$H session --instance "$INSTANCE" alb-api

# Any albauth CLI command, with this instance's HOME and config.
$H cli --instance "$INSTANCE" -- auth status
```

Fixture routes behind the session (prefix the domain's host): `/json` (200 JSON),
`/html/<code>` (that status, `text/html`, any method), `/redirect/same/<code>` and
`/redirect/cross/<code>` (Go-style HTML body; add `?bare=1` for none; `cross`
points at a presigned-S3-style URL), `/rotate` (200 plus a fresh session cookie
under the same name), `/app401` (the application's own 401 unless header
`X-App-Token: good`). oauth2 mode also serves `/oauth2/start`, `/oauth2/auth`
(202 or 401), `/oauth2/callback` and `/oauth2/sign_in` (a 403 HTML page that sets
`_oauth2_proxy_csrf`). A request with no valid session gets the proxy's answer:
ALB mode a 302 to `localhost:<port>/idp/authorize?client_id=…&response_type=code…`,
oauth2 mode a 401.

A re-login opens a real Chrome window for one or two seconds: the fixture IdP
approves at once and the window closes itself. That is the user path, not a
failure.

## Evidence

- Exercise the real user path. Never internal setters, never test-only endpoints.
- Capture the action *and* the resulting state, not just a final screenshot.
- Verify side effects (rows inserted, files written, messages sent, webhooks fired) alongside what is visible.
- Mocks only where a production boundary already isolates the external system.
- Where the safe path is a dry-run or test mode, verify what it *actually* skips by observing files, network and git refs, not by trusting its name. Some dry-runs still touch the network or open a browser.
- Evidence goes to `.verify/<instance>/<feature-id>/<sha>/`, one directory per feature per head, recorded with `scripts/verify_evidence.py record`.
- Harness output is JSON wherever the harness can emit it, so a verifier can read it without a human.
- Cleanup removes instances, never evidence.

Save each harness output you rely on to a file under `.verify-run/$INSTANCE/`
and pass it as an artifact:

```sh
$H call --instance "$INSTANCE" 'http_request={"url":"{host:alb-api}/html/404"}' > .verify-run/$INSTANCE/call.json
$H fixture --instance "$INSTANCE" alb-api hits > .verify-run/$INSTANCE/hits.json
python3 $SKILL/scripts/verify_evidence.py record --instance "$INSTANCE" \
  --feature response-passthrough --verifier "$VERIFIER" --result pass \
  --action "http_request GET {host:alb-api}/html/404" \
  --observed "status 404 returned as a result, relogin_performed false" \
  --side-effect "fixture hits: GET /html/404 = 1 (no retry)" \
  --artifact .verify-run/$INSTANCE/call.json --artifact .verify-run/$INSTANCE/hits.json
```

## Cleanup

```sh
$H cleanup --instance "$INSTANCE"
```

Stops this instance's fixtures by the process-group ids in
`.verify-run/$INSTANCE/fixture-*.pid`, releases its port claim and removes
`.verify-run/$INSTANCE/`. It never kills by process name and never touches
`.verify/`, where the evidence lives.
