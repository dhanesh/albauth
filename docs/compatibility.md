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
Superset · Rundeck · Retool · most tools' web UIs, if you are willing to paste a
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

## Untested, and honestly uncertain

**CSRF-token flows** — Jenkins' crumb, Superset's `X-CSRFToken`. These need a
`GET` to fetch a token followed by a `POST` carrying it. albauth can issue both
requests, so a caller that chains them should work, but the token is per-session
and this was not tried.

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

---

## Reproducing this

The rig is a container per tool behind a MiniStack load balancer running a real
`authenticate-oidc` rule; see [../test/ministack/README.md](../test/ministack/README.md).

One caveat on fidelity: **the applications are real, the load balancer is an
emulator.** It reproduces the redirect, the callback, the chunked session cookie
and the identity headers, but it is not AWS. It also does not currently preserve
the `Host` header to targets, which real ALB does — a difference that matters to
anything host-sensitive, SigV4 among them.
