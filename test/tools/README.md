# The tool sweep

Runs albauth against real applications behind a real OIDC proxy, and reports
which ones still work.

```bash
./sweep.sh            # the quick set (~1 min once images are pulled)
./sweep.sh --heavy    # adds Superset, Jenkins, Metabase, Hasura
./sweep.sh --down     # tear the stack down
```

Exit 0 means every check passed.

## Why this exists

albauth's unit tests cannot tell you that a change broke Grafana. What breaks
is never albauth's own logic in isolation — it is an assumption about how some
application answers. Every regression found so far came from a real
application, not from a test:

| What broke | How it looked |
|---|---|
| An HTML page judged an expired session | A 200 response turned into `auth_loop`, after a pointless browser window |
| A binary body run through a string conversion | Corrupted downloads, silently |
| A bare 401 treated as "logged out" | A wrong API token spawned a browser instead of reporting the refusal |
| A CSRF token that needed its session cookie back | Jenkins and Superset writes rejected |
| A session cookie under an unexpected name | The browser login visibly succeeded while albauth waited forever |

Each of those passed every unit test at the time.

## What it stands up

Layer 1 is the proxy: **dex** issues identities, **oauth2-proxy** validates
them, **Traefik** enforces it with `forwardAuth`. That is the same shape as an
AWS ALB `authenticate-oidc` rule, minus AWS — and it is deliberately not AWS,
because albauth should not be an AWS-only tool.

Layer 2 is each application's own credential — a Grafana token, a Vault token,
RabbitMQ's basic auth. Getting past the proxy is not the same as being allowed
in, and the sweep covers both.

Every application sits on its own port of `localhost`. Cookies ignore ports, so
one login authenticates all of them, which is what keeps the sweep a single
pass.

## It is headless

dex is configured with a static password, so the login is a scripted HTTP
exchange — start, credentials, approval, callback — and the cookie that falls
out is handed to albauth with `auth import`. No browser, no real IdP account,
nothing to rotate. That is what makes it runnable in CI and on every change.

## Adding a case

Add a line to `DOMAINS` (an application and its credential) and one to `CHECKS`
(what to fetch). Several checks may share a domain — the response *shapes* are
what catch regressions, not the number of applications. Prefer a check that
exercises something new: a content type nothing else returns, a redirect, an
endpoint that 401s for its own reasons.

## The sweep is not a substitute for `scripts/verify.sh`

`verify.sh` is the acceptance gate: build, unit tests, coverage, docs. The
sweep is the reality check. Both, in that order.
