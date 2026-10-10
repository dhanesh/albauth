# What albauth works with

albauth does one narrow thing: it attaches a load-balancer session cookie, plus
whatever static headers you configure, to an ordinary HTTP request. Whether a
given tool works therefore comes down to one question — **can its own
authentication be expressed as a header or a cookie that does not change between
requests?**

If yes, it works. If the credential is computed per request, or the protocol is
not request/response, it does not.

The tables below separate what was **measured** from what is **inferred**. Every
tool in the first table was run in a container behind a load balancer with a
real `authenticate-oidc` listener rule, and driven through albauth end to end.
Everything in the second table shares a mechanism with one of those, but was not
itself run.

---

## Verified

Each of these was started, put behind an ALB with `authenticate-oidc`, logged in
through the identity provider, and queried through albauth's `http_request`.

| Tool | Version | Its own auth | Without it | Through albauth |
|---|---|---|---|---|
| Grafana | 11.3.0 | `Authorization: Bearer glsa_…` | 401 | 200 — datasources, orgs, search |
| Hasura | v2.42 | `x-hasura-admin-secret` | 401 / access-denied | 200 — GraphQL, introspection, metadata |
| Metabase | v0.50.21 | `X-API-KEY` | 401 | 200 — databases, collections, current user |
| Metabase | v0.50.21 | `Cookie: metabase.SESSION` | 401 | 200 — resolved the right identity |
| Vault | 1.18 | `X-Vault-Token` | 403 | 200 — mounts, health |
| RabbitMQ | 3.13 | `Authorization: Basic …` | 401 | 200 — overview, queues |
| Loki | 3.2 | `X-Scope-OrgID` | 200 | 200 — labels |
| Prometheus | 2.55 | none | 200 | 200 — buildinfo, label values |
| Jenkins | LTS JDK17 | `Authorization: Basic …` + crumb | 403 | 200 — reads and writes |
| Superset | 4.0.2 | `Authorization: Bearer` + `X-CSRFToken` | 401 | 200 — reads and writes |
| MinIO | 2024-11 | AWS SigV4 | 403 | **403 — not supported** |

The Metabase rows matter most: the same request carried the application's own
session cookie *and* the load balancer's, and Metabase resolved the correct user
from its own. Go's cookie handling appends rather than replaces, so the two
coexist.

### The transport, separately

Confirmed against an echo target, so the observation is of what actually
arrived rather than of a tool's behaviour:

- Header names of every shape — `X-API-KEY`, `x-hasura-admin-secret`,
  `X-Vault-Token`, `Authorization: Basic`, all present and unaltered
- `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, each with a request body and its
  `Content-Type` preserved
- A GraphQL POST body round-tripped byte for byte
- Query parameters, merged with any already in the URL
- An application `Cookie` header merged with the session cookie, not replacing it
- Binary responses returned intact as base64 with `body_base64: true`
- Oversized responses truncated with the real total reported

---

## Proxies are detected for you

`albauth config add-domain <name> --base-url <url>` probes the URL before it
writes anything, and configures what it finds:

| What the probe sees | What it writes |
|---|---|
| A redirect to another host | `idp_hostnames` |
| A `401`, and a login route at `/oauth2/start` or `/oauth2/sign_in` | `login_probe_path`, `cookie_name_prefix`, `treat_401_as_expired` |

The second row is oauth2-proxy, on its own or behind Traefik `forwardAuth`.
Those three settings are the ones nobody guesses on a first run, and getting
`cookie_name_prefix` wrong is particularly unkind: the browser login visibly
succeeds while albauth waits for a cookie family that never arrives.

Any flag you pass yourself wins over the probe.

## Inferred from a shared mechanism

Not run. Listed because their authentication is the same shape as something in
the table above, so there is no reason for them to behave differently — but
"no reason to differ" is not the same as "tested".

**Bearer token** — same shape as Grafana:
Argo CD · Sentry · Keycloak admin API · Directus · Elasticsearch and OpenSearch
(`ApiKey`) · Tempo · Mimir · Jaeger · Temporal · Buildkite · Kubernetes API

**A custom header** — same shape as Hasura, Vault and Loki:
n8n (`X-N8N-API-KEY`) · Portainer (`X-API-Key`) · Typesense
(`X-TYPESENSE-API-KEY`) · Meilisearch · ClickHouse · Supabase (`apikey`) ·
Appwrite (`X-Appwrite-Key`) · Strapi · Algolia · Weaviate · Airbyte

**Basic auth** — same shape as RabbitMQ:
Jenkins · Airflow · SonarQube · Nexus · Artifactory · pgAdmin · Kibana ·
Alertmanager · Consul · Nomad · Kafka UI · Redpanda Console · Traefik dashboard

**A session cookie** — same shape as Metabase:
Rundeck · Retool · most tools' web UIs, if you are willing to paste a
session cookie and refresh it when it expires

**No authentication of its own** — same shape as Prometheus:
Tempo · Jaeger UI · Alertmanager · Swagger UI · internal dashboards. For these
the load balancer is the only layer, and albauth alone is enough.

---

## Does not work

**Signature-based authentication (AWS SigV4).** Verified against MinIO: health
endpoints answer, but anything requiring a signature returns 403. SigV4 signs
the method, path, query, payload hash and timestamp of each individual request,
so there is no fixed `Authorization` value to configure. This rules out
S3-compatible storage and AWS's own APIs. Use the AWS SDK directly for those —
it is not what albauth is for.

**WebSockets.** Hasura subscriptions, Grafana Live, log tailing, Temporal's
streaming APIs. `http_request` is request/response; there is no upgrade path.

**Server-sent events and streaming responses.** The body is read to completion
before returning, so a long-lived stream blocks until `timeout_seconds` and then
fails. This includes LLM proxies that stream tokens.

**Credentials that rotate.** Headers are static configuration. A token with a
short life has to be replaced by hand; there is no refresh.

**Query-parameter API keys.** They can be passed per request via the `query`
argument, but cannot live in the config the way a header can.

**mTLS.** Client certificates are not configurable.

## CSRF-protected tools

Measured against Jenkins and Superset. Both were run behind the load balancer
and driven through albauth.

| Tool | Reads | Writes |
|---|---|---|
| Jenkins (LTS, JDK17) | 200 — `/api/json` with `Authorization: Basic` | **403 — "No valid crumb was included in the request"** |
| Superset 4.0.2 | 200 — dashboards, charts, databases with `Authorization: Bearer` | **400 — "The CSRF session token is missing."** |

The cause is the same in both, and it is not the token itself. albauth can
fetch the token perfectly well: Jenkins' `/crumbIssuer/api/json` and Superset's
`/api/v1/security/csrf_token/` both return one. The problem is that the
response issuing the token **also sets a session cookie**, and the token is only
valid when presented with it. albauth strips `Set-Cookie` from what it returns,
deliberately — it is the one header that would carry a session value back into
a model's context — so without somewhere to keep that cookie, the second
request arrived with a valid-looking token and no session to match it.

Verified rather than assumed: fetching a Jenkins crumb with no cookie jar and
posting it with no cookie jar fails the same way outside albauth entirely.

**What this means in practice.** Every read-only API on a CSRF-protected tool
works. Creating a job, saving a dashboard, triggering a build — anything that
mutates — does not.

**Fixed.** albauth now keeps a per-domain cookie jar, so a token issued by one
response is still paired with its session on the next request. Jenkins'
`createItem` and Superset's dashboard creation both return 200 through albauth.

The jar is deliberately narrow:

- **One jar per domain**, so two domains never share a session.
- **In memory only.** Application session cookies are credentials; they are
  never written to disk, and they die with the process.
- **The load balancer's own cookies are excluded.** Those live in the session
  store, survive restarts, and are re-acquired by logging in. Letting the jar
  keep them too would mean sending each of them twice.
- **Cleared on logout**, so signing out of the load balancer does not leave the
  application still believing the caller is signed in.
- **Backed by the public suffix list**, which stops a response setting a cookie
  scoped to a registry suffix that the jar would then attach to unrelated hosts.
  Go's own documentation calls a nil list insecure.
- **`Set-Cookie` is still stripped from every response.** A caller benefits from
  the session without ever seeing it.

The one real consequence is that requests are no longer independent of one
another. That is inherent to the feature — it is the whole point — but it means
a stale application session can outlive its usefulness within a long-running
server. `auth_logout` clears it.

---

## Two behaviours worth knowing whatever the tool

**A `200` is not proof that authentication succeeded.** Hasura's `/v1/graphql`
answers `200` with `{"errors":[{"extensions":{"code":"access-denied"}}]}`.
Nothing can infer that from the status code. Read the body.

**A `401` from the application is not an expired session.** albauth does not
treat it as one by default — see `treat_401_as_expired` in
[configuration.md](configuration.md). Turning it on for a domain whose
application does its own authentication will produce a browser window and a
long stall on requests that could never have succeeded.

**An HTML page is not a login page just because it is HTML.** A response
carrying `text/html` is the application's own content — plenty of these tools
serve it — and albauth passes it through, error pages included: an HTML `404`
or `500` from the application, or a `502`/`503` from a gateway in front of it,
comes back as a result with `relogin_performed: false` and is not retried. A
login page leaking through arrives as a redirect, or as an HTML `401`/`403`
answering a JSON request, which is what the expiry rules look for.

Why `401` and `403` still count: they are the statuses a proxy uses when it
answers "no session" with a page of its own rather than a redirect —
oauth2-proxy's sign-in page, a `forwardAuth` service's refusal, an ALB rule set
to deny unauthenticated requests. That page is the same whichever proxy sends
it, and it never comes from an API that was asked for JSON and had a session to
answer with. So it costs exactly one re-login and one retry; if the retry gets
the same page, the result is `auth_loop` rather than a second browser window.
The price is that an application which itself answers a JSON request with an
HTML `403` sees one re-login before `auth_loop` tells you the refusal is real.

A write — any method but `GET`, `HEAD` or `OPTIONS` — is not retried on such a
page, because it cannot be told apart from the application refusing after it
acted. albauth runs the re-login and answers `resend_required`; the write
reached the application once. Only a redirect to the identity provider, which
the proxy sends before the application sees anything, lets albauth resend a
write by itself.

---

## It is not only for AWS load balancers

The name says ALB because that is what it was built for, but nothing in the
mechanism is AWS-specific. albauth attaches a session cookie and static headers
to a request; anything that authenticates with a cookie and refuses
unauthenticated traffic works, given the right two settings.

Verified end to end, with a real browser completing a real OIDC login against
[Dex](https://dexidp.io):

| In front of the app | Unauthenticated response | Settings needed | Result |
|---|---|---|---|
| AWS ALB `authenticate-oidc` | 302 to the identity provider | defaults | verified against production |
| oauth2-proxy (reverse proxy) | 302 for a browser, **401** for `Accept: application/json` | `cookie_name_prefix = "_oauth2_proxy"`, `treat_401_as_expired = true` | 200, upstream saw `X-Forwarded-Email` |
| Traefik + oauth2-proxy `forwardAuth` | **401 always**, never a redirect | as above, plus `login_probe_path = "/oauth2/start"` | 200, upstream saw `X-Auth-Request-Email` |

Two settings carry all of it:

- **`cookie_name_prefix`** — whatever your proxy names its session cookie.
  `AWSELBAuthSessionCookie` for ALB, `_oauth2_proxy` for oauth2-proxy.
- **`treat_401_as_expired`** — because the meaning of a `401` genuinely depends
  on what is in front of the app. Behind an ALB it is usually the application
  refusing the caller, and re-authenticating cannot help. Behind oauth2-proxy or
  Traefik `forwardAuth` it is the proxy itself, and re-authenticating is exactly
  the right response. Neither default would be correct for both, which is why it
  is configurable.

And one that is easy to miss: **`login_probe_path` must point at something that
actually starts a login.** Under Traefik `forwardAuth` the application path
answers `401` and never redirects, so a browser opened there would sit on an
error page forever. `/oauth2/start` is what begins the flow.

**Traefik has no OIDC of its own** in the open-source distribution — it
delegates through `forwardAuth` to something like oauth2-proxy, so what is
really being tested is that delegate.

**Authelia** was attempted and not completed: it refuses to start with
`authelia_url` or `default_redirection_url` on plain HTTP, so a local test needs
TLS. Its session cookie is `authelia_session` and it redirects unauthenticated
requests, which is the oauth2-proxy shape, so it should need only
`cookie_name_prefix = "authelia_session"` — but that is reasoning, not a
measurement, and is listed here as such. **Authentik** and **Pomerium** were not
tried.

---

## Reproducing this

The rig is a container per tool behind a MiniStack load balancer running a real
`authenticate-oidc` rule; see [../test/ministack/README.md](../test/ministack/README.md).

One caveat on fidelity: **the applications are real, the load balancer is an
emulator.** It reproduces the redirect, the callback, the chunked session cookie
and the identity headers, but it is not AWS. It also does not currently preserve
the `Host` header to targets, which real ALB does — a difference that matters to
anything host-sensitive, SigV4 among them.

A second quirk to know when using the rig: the emulator answers its own
`/health` before the load-balancer rules run, so a probe path of `/health`
silently returns the emulator's service list instead of reaching your target.
Use something the emulator does not claim — `/api/health` and `/login/` both
work.
