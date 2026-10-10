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
| An HTML error page or a redirect read as "logged out" | A 404 page or a same-host 302 turned into a login instead of being returned |
| Any cross-host redirect treated as a login | A presigned S3 download link opened a browser window |
| An application's own 401 behind oauth2-proxy | A wrong API token came back as `auth_loop` instead of the app's refusal |

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
(what to fetch, and what albauth must answer):

```
label | domain | path | expect | header
```

- `expect` is a shell pattern for the status albauth returns — `2*`, `302`,
  `401` — or `!token`, meaning the result must not contain `token` (for example
  `!auth_loop`). It defaults to `2*` when left out. The readiness wait uses it
  too, so a check that expects a 404 does not sit waiting for a 200.
- `header`, optional, is one `Name=Value` sent with that request only. albauth
  lets a request header override the domain's own, which is how a check can
  present a wrong application credential without a second domain for the same
  host (albauth refuses two domains on one host, and rightly so).

Several checks may share a domain — the response *shapes* are what catch
regressions, not the number of applications. Prefer a check that exercises
something new: a content type nothing else returns, a redirect, an endpoint
that 401s for its own reasons.

## The negative cases

Most checks expect a 2xx. These expect something else, because each one is an
answer albauth once mistook for a lost session:

| Check | Expects | Why it exists |
|---|---|---|
| `grafana html 404` | `404` | An HTML body on an error status must come back as a result, not be judged an expired session. go-httpbin's `/status/404` is `text/plain` with no body, so Grafana's own HTML 404 page is used instead. |
| `echo same-host redirect` | `302` | A redirect inside the application (`/redirect-to?url=/get`) is the app's answer; albauth does not follow redirects and must not log in over one. |
| `prometheus redirect+body` | `302` | The same, with an HTML body: Prometheus answers `/` with Go's `http.Redirect`, which writes `<a href="/graph">Found</a>.` go-httpbin's redirects have empty bodies. |
| `echo presigned redirect` | `302` | A cross-host redirect to a presigned object URL (`…?X-Amz-Signature=…`) is a download link, not a login. Only an OAuth authorization request counts as a login redirect. |
| `grafana wrong token` | `401` | A wrong application token behind oauth2-proxy. The config probe sets `session_check_path=/oauth2/auth`, so albauth can tell the proxy session is fine and returns Grafana's own 401 instead of `auth_loop`. A bearer token is used rather than a wrong password so repeated runs never trip Grafana's brute-force lockout. |

## Running it

The sweep needs a Docker-compatible runtime (this project uses Colima) and
Compose. It uses `docker compose` when that works, and falls back to a
standalone `docker-compose` binary otherwise — for every call: up, `ps` and
`--down`. With neither it stops and says so.

The S3-compatible store is SeaweedFS (`chrislusf/seaweedfs`, running
`weed server -s3`). It replaced MinIO, whose pinned image can no longer be
pulled. With no `-s3.config` it needs no S3 credentials, so its check is an
unsigned bucket listing of `/`, which answers 200 with an XML body — a content
type nothing else in the sweep returns.

## The sweep is not a substitute for `scripts/verify.sh`

`verify.sh` is the acceptance gate: build, unit tests, coverage, docs. The
sweep is the reality check. Both, in that order.
