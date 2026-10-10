# `albauth` — Build Specification

A single-binary, locally-run MCP server that transparently handles AWS ALB
`authenticate-oidc` sessions, so an MCP client can call protected API URLs
without knowing anything about the auth layer sitting in front of them.

Target implementer: Claude Code. This document is the source of truth.

---

## 1. Problem

Internal APIs sit behind an AWS Application Load Balancer with an
`authenticate-oidc` listener rule. Any unauthenticated request is 302'd to the
IdP (Okta / Entra / Auth0 / Cognito). Once the browser completes the flow, the
ALB sets an `AWSELBAuthSessionCookie-*` cookie on the ALB's own hostname and
forwards subsequent requests to the target with an `X-Amzn-Oidc-Data` header.

An MCP client (Claude Code, Claude Desktop, etc.) can't complete that flow. It
gets a 302 to the IdP and dies there.

`albauth` sits in between: it performs one interactive browser login per domain,
captures the ALB session cookie, persists it, and replays it on every
subsequent request. The user logs in once; the model calls the API freely.

## 2. Goals

- Single statically-linked binary. No runtime, no daemon, no container.
- Runs as a **stdio MCP server**.
- Configured with a list of domains; requests to those domains are auto-authenticated.
- One interactive browser login per domain, then silent until cookie expiry.
- Silent re-login on expiry (re-opens browser only when unavoidable).
- Cookie stored in OS keychain where available, `0600` file otherwise.

## 3. Non-Goals

- **No DNS interception, no local TLS termination, no hosts-file rewriting.**
  Domain routing is explicit in config. (Considered and rejected: DNS-level
  capture requires terminating TLS locally for the target domain, which means a
  self-signed cert plus trust-store surgery on every machine — enormous pain to
  save one config line.)
- No general-purpose HTTP proxy mode in v1.
- No credential storage. `albauth` never sees or handles the user's password or
  MFA. It only ever holds the ALB-issued session cookie.
- No support for non-ALB auth schemes in v1 (no bearer tokens, no mTLS, no
  basic auth passthrough).

## 4. Language: Go

**Decision: Go.**

Rationale (Rust was seriously considered and is defensible, but loses here):

| Concern | Go | Rust |
|---|---|---|
| Redirect-following HTTP client with a persistent cookie jar | `net/http` + `net/http/cookiejar`, stdlib, zero deps | assemble `reqwest` + `reqwest_cookie_store` + `cookie_store` |
| Browser automation (CDP) | `chromedp` — mature, sync-ish API | `chromiumoxide` — good but heavier async ergonomics |
| Cross-platform secret storage | `zalando/go-keyring` — one interface, three backends | `keyring-rs` — comparable, fine |
| Local callback listener | stdlib `net/http` | needs `axum`/`tiny_http` |
| Static single binary | `CGO_ENABLED=0 go build` | `--target *-musl` |
| MCP SDK maturity | `mark3labs/mcp-go` or official Go SDK | `rmcp` |

The whole program is a cookie shuttle wrapped in an HTTP client. Go's stdlib
gives you ~90% of that for free. Rust would mean fighting async lifetimes for
no gain. Revisit only if this needs to live inside an existing Rust workspace.

**Go 1.22+. `CGO_ENABLED=0`. Cross-compile for darwin/arm64, darwin/amd64,
linux/amd64, linux/arm64, windows/amd64.**

---

## 5. The Hard Part: Acquiring the Cookie

This is the crux of the design and the part most likely to be got wrong. Read
this section carefully before writing code.

**The ALB session cookie is set on the ALB's own hostname, by the browser,
after the user completes an interactive IdP flow.** A Go HTTP client cannot
complete that flow itself:

- Approaches that **do not work**:
  - Loopback OAuth callback capture (PKCE against the IdP directly). You'd get
    an ID token, but the ALB doesn't accept ID tokens — it only accepts *its
    own* `AWSELBAuthSessionCookie`. Dead end.
  - Driving the redirect chain in a plain Go `http.Client`. The IdP leg
    requires a real browser session (password, MFA, device trust, SSO cookies).
    Scraping IdP login forms is brittle and will break.
  - Running a local reverse proxy the browser points at. The ALB's
    `redirect_uri` points at the real ALB hostname, so the browser leaves the
    proxy and the cookie is set out-of-band on the real domain.

- Approach that **does work — primary implementation**:
  **Drive a real, headed browser via CDP (`chromedp`), then read the cookie
  out of it.** The user sees a normal browser window, does their normal SSO,
  and `albauth` reads `AWSELBAuthSessionCookie*` from the browser's cookie store
  once the redirect chain settles back on the target domain.

- **Fallback for headless / no-Chrome environments:** manual cookie import
  (`albauth auth import`), documented in §10.

### 5.1 Login state machine (`chromedp` path)

```
START
  │
  ├─ launch chromedp with a PERSISTENT user-data-dir at
  │  <state_dir>/browser/<domain-name>/   (so IdP SSO session survives
  │  between logins and re-auth is often click-free)
  │  Headed (Flag("headless", false)). Window is visible on purpose.
  │
  ├─ navigate to  <base_url><login_probe_path>
  │
  ├─ POLL every 500ms, up to login_timeout_seconds (default 180):
  │     current URL host == host(base_url)
  │       AND network.GetCookies returns ≥1 cookie in the session
  │           family: name == cookie_name_prefix, or cookie_name_prefix
  │           + "-" + digits, or cookie_name_prefix + "_" + digits
  │       AND HTTP status of the settled page is < 400
  │           (the final response status of the top-level document the
  │           tab is showing, re-read on every navigation — redirect, meta
  │           refresh or script; unknown counts as not settled, so a proxy's
  │           on-host 401/403 sign-in or deny page never settles the login).
  │           The status is the responseStatus of the document's Navigation
  │           Timing entry, which needs Chrome/Chromium 109+; older browsers
  │           report none, so every login ends in login_timeout.
  │  │
  │  ├─ SATISFIED → capture all cookies for host(base_url) in that
  │  │              family (there may be several: ALB chunks large
  │  │              sessions into -0, -1, -2, …; oauth2-proxy into _0,
  │  │              _1, …). A name that merely starts with the prefix —
  │  │              _oauth2_proxy_csrf, AWSELBAuthSessionCookieFoo — is
  │  │              not in the family and is never captured.
  │  │              Record each cookie's Name, Value, Domain, Path,
  │  │              Expires, Secure, HttpOnly.
  │  │              Close browser. Persist (§7). → SUCCESS
  │  │
  │  └─ TIMEOUT   → close browser, return McpError
  │                 "login_timeout: browser flow did not complete within Ns"
  │
  └─ chromedp cannot find a browser binary
       → return McpError "no_browser: install Chrome/Chromium or use
          `albauth auth import`"  (include the import instructions inline)
```

Notes:
- Do **not** run headless. The point is for the human to complete MFA.
- Reuse the persistent profile dir. On second and later logins the IdP session
  usually still exists, the redirect chain completes in ~1s with no
  interaction, and the window closes on its own. This is what makes silent
  re-auth feel silent.
- Only one login may be in flight per domain at a time. Guard with a per-domain
  `sync.Mutex`; concurrent `http_request` calls that hit a 302 must block on the
  same login rather than each spawning a browser.

### 5.2 Detecting that a session has expired

A request is treated as **unauthenticated** if any of:

1. Response status is `302`/`303` **and** the `Location` header host is in
   `idp_hostnames`, **or** its path is `/oauth2/idpresponse`.
2. Response status is `302`/`303` **and** `Location` host != host of the
   request URL **and** the `Location` query carries both `client_id` and
   `response_type` — an OAuth 2.0 / OIDC authorization request (both
   parameters are REQUIRED by RFC 6749 §4.1.1). This catches identity
   providers not listed in `idp_hostnames`. Any other cross-host redirect — a
   presigned S3 URL, a CDN, another service — is the application's answer and
   is returned to the caller unchanged, with `relogin_performed: false` and no
   login.
3. Response status is `401` on a domain with `treat_401_as_expired = true`
   (off by default: a `401` is usually the application refusing a credential),
   unless the domain's `session_check_path` says the session is still good —
   see below.
4. Response body's `Content-Type` is `text/html` **and** the request `Accept`
   was `application/json` **and** the status is `401` or `403` (a proxy's
   sign-in page answering in place of a redirect). The status qualifier
   matters: every other status carrying HTML is the application's own answer
   — a page it serves with a 2xx, or its own `404`/`500`, or a gateway's
   `502`/`503` — and is returned to the caller unchanged, with
   `relogin_performed: false` and no retry. Without it a working session is
   misjudged as expired, costing a browser window and then failing the request.
   `401` and `403` stay in because they are what a proxy sends when it answers
   "no session" with a page instead of a redirect (oauth2-proxy's sign-in page,
   a `forwardAuth` refusal), whichever proxy it is; such a page costs exactly
   one re-login and, for a `GET`/`HEAD`/`OPTIONS`, one retry, and a second one
   is `auth_loop`. A write is not retried (see below).

`idp_hostnames` is therefore optional for correctness: an identity provider it
does not list — or a domain that sets none at all — is still caught by rule 2,
because the proxy's redirect to it is an authorization request. It stays
recommended: rule 1 also matches a redirect to the provider that does not
carry both parameters, and naming the provider makes the detection precise and
the logs readable.

A **same-host** redirect — `301`, `302`, `303`, `307` or `308`, with or without
a body, whether `Location` is relative or absolute — matches none of these
rules unless it points at `/oauth2/idpresponse`. It is the application's own
answer and is returned to the caller unchanged: its status, its `Location`,
`relogin_performed: false`, no login.

**Session check (rule 3 only).** A `401` cannot say by itself whether the
proxy or the application sent it. When a domain sets `session_check_path`
and a response is judged by rule 3, albauth first sends
`GET <base_url><session_check_path>` carrying **only** the session cookies —
no `[domain.headers]`, no caller headers, no application cookies — without
following redirects, under the domain's `timeout_seconds`. If the check
answers `2xx`, the proxy still accepts the session and the `401` is the
application refusing the request: the original `401` (status, headers, body)
is returned as a normal result with `relogin_performed: false`, no re-login
and no resend. Any other outcome — another status, a redirect, a transport
error, a timeout — falls back to the re-login below, so a wrong or unreachable
check path can never keep a dead session in use. oauth2-proxy's
`/oauth2/auth` (`202` for a live session, `401` otherwise) is the endpoint
this is for, and `albauth config add-domain` writes it whenever its probe
finds an oauth2-proxy login at `/oauth2/start` or `/oauth2/sign_in` (never for
a redirecting proxy such as an ALB; an explicit `--session-check-path` wins).
A domain without `session_check_path` behaves as if this paragraph did not
exist.

On detection: discard cached cookie for that domain, run the login state
machine, retry the original request **exactly once**. If it fails again,
surface the error — never loop.

The retry is a resend, so it depends on the method. `GET`, `HEAD` and
`OPTIONS` are always retried. Any other method is retried **only** when the
first attempt was judged by rule 1 or rule 2 — a redirect to the identity
provider, which means the proxy intercepted the request and the application
never saw it. A write judged by rule 3 or rule 4 may have been the application
itself answering after it acted, so it reaches the application **at most
once**: albauth still runs the re-login (so the next call is authenticated)
and then returns `resend_required` instead of sending it again. The caller
decides whether repeating the write is safe.

The HTTP client used for API calls must have
`CheckRedirect: func(...) error { return http.ErrUseLastResponse }` so
redirects are visible to this logic rather than silently followed.

### 5.3 A session the proxy refreshes

A proxy may reissue its session on an ordinary response — oauth2-proxy with
`--cookie-refresh`, an ALB re-issuing its chunks — by setting a new value under
the same name. A response judged **authenticated** (§5.2) that carries
`Set-Cookie` entries in the domain's session cookie family (name equal to
`cookie_name_prefix` or a numbered chunk of it, as in §5.1; an empty prefix
names no family) updates the stored
session, under the domain's login lock and against the session stored at that
moment:

- a cookie of a stored name is replaced in place: value, expiry (`Max-Age`
  wins over `Expires`; neither means no expiry), path and flags, and domain
  when the response names one;
- a new name — an extra chunk — is appended (domain defaults to the request
  host, path to `/`);
- a cookie the response deletes (`Max-Age=0`, or an `Expires` already past) is
  dropped; a session left with no cookies is deleted, so the next call logs in.

New values are registered as log secrets before the session is written. A
response that sets no session-family cookie, or sets one identical to the
stored cookie, does not touch the store. The response that triggers a re-login
is never taken into the store, so a proxy clearing its cookie on the way to the
identity provider cannot make the re-login mistake the change for a concurrent
login. A failure to store the update is logged to stderr and the request still
returns its result: the old session stays in place for as long as the proxy
accepts it. The application cookie jar still refuses session-family cookies,
so each is sent once, from the store, and `Set-Cookie` is still stripped from
the result (§8.1).

---

## 6. Configuration

Path resolution order:
1. `--config <path>` flag
2. `$ALBAUTH_CONFIG`
3. `$XDG_CONFIG_HOME/albauth/config.toml`, else `~/.config/albauth/config.toml`
   (macOS: same; Windows: `%APPDATA%\albauth\config.toml`)

Format: TOML.

```toml
# ~/.config/albauth/config.toml

[[domain]]
# Required. Stable identifier. Used as the keyring key and in tool args.
name = "internal-api"

# Required. Scheme + host (+ optional port). No trailing slash.
base_url = "https://api.example.com"

# Optional. Glob patterns this domain claims. Used to route a bare URL passed
# to http_request to the right domain. Defaults to [host(base_url)].
match = ["api.example.com", "*.internal.example.com"]

# Optional. Path hit to trigger/verify the OIDC flow. Should be cheap and
# behind the same ALB rule. Default "/".
login_probe_path = "/healthz"

# Optional. Default "AWSELBAuthSessionCookie". The session cookie's exact
# name; it also matches numbered chunks NAME-<digits> / NAME_<digits>, and
# nothing else (not a loose prefix: _oauth2_proxy_csrf is not _oauth2_proxy).
cookie_name_prefix = "AWSELBAuthSessionCookie"

# Optional but recommended. Hostnames of the IdP. Used for expiry detection
# (§5.2 rule 1); an unlisted IdP is still caught by rule 2. Default [].
idp_hostnames = ["example.okta.com", "login.microsoftonline.com"]

# Optional. Methods the model is allowed to issue against this domain.
# Default ["GET"]. Set explicitly to allow writes — fail closed.
allow_methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]

# Optional. Count a 401 as an expired session (§5.2 rule 3). Default false.
# Turn on for a proxy that answers "no session" with a 401 (oauth2-proxy).
treat_401_as_expired = false

# Optional. Proxy endpoint that answers 2xx while the session is live
# (oauth2-proxy: "/oauth2/auth"). Asked before a rule-3 401 triggers a
# re-login; a 2xx returns the 401 as the application's answer (§5.2).
# Must start with "/". Default: none (no check).
# session_check_path = "/oauth2/auth"

# Optional. Per-request timeout. Default 30.
timeout_seconds = 30

# Optional. Seconds to wait for the interactive browser login. Default 180.
login_timeout_seconds = 180

# Optional. Extra headers added to every request to this domain.
[domain.headers]
"X-Client" = "albauth"

[[domain]]
name = "admin-console"
base_url = "https://admin.example.com"
allow_methods = ["GET"]
```

Global section (all optional):

```toml
[settings]
# "keyring" | "file" | "auto". Default "auto" (keyring, fall back to file).
storage = "auto"

# Max response body returned to the model, in bytes. Default 1048576 (1 MiB).
# Larger bodies are truncated with a clear marker.
max_response_bytes = 1048576

# "error" | "warn" | "info" | "debug". Written to stderr ONLY. Default "info".
log_level = "info"
```

**Validation at startup.** Fail fast with a readable error listing every
problem, not just the first:
- `name` non-empty, unique, matches `^[a-z0-9][a-z0-9._-]*$`
- `base_url` parses, scheme is `https` (allow `http` only if host is
  `localhost`/`127.0.0.1`, for testing)
- `allow_methods` entries are valid HTTP methods, uppercased
- `match` globs compile
- no two domains claim overlapping `match` patterns (ambiguous routing → error)

---

## 7. Cookie Storage

### 7.1 Backend selection

```
storage = "auto":
  try keyring (zalando/go-keyring)
    ├─ Set+Get round-trip succeeds → use keyring
    └─ error (no Secret Service on headless Linux, locked keychain, etc.)
         → use file, and emit a ONE-TIME warning to stderr:
           "albauth: OS keychain unavailable (<err>); storing session cookies
            at <path> with mode 0600. Set storage = \"file\" in config to
            silence this."
  with keyring in use, per domain on Set:
    └─ keyring refuses the session as too big (go-keyring ErrSetDataTooBig:
       macOS caps the `security` command at 4096 bytes, ~3 KB of session
       JSON; Windows a credential at 2560 bytes) — refused before writing
         → write that domain's session to the 0600 file, delete any stale
           keychain entry for it, and emit a ONE-TIME warning per domain:
           "albauth: session for domain "<name>" is too large for the OS
            keychain; storing it at <path> with mode 0600. Set storage =
            \"file\" in config to silence this."
    Get reads the keychain, then the file; Delete removes both; a session
    that fits again goes back to the keychain and leaves the file.
storage = "keyring": use keyring, hard-fail if unavailable; a session too big
                     for it is storage_unavailable with a hint naming
                     storage = "auto" or "file"
storage = "file":    use file, no warning
```

`storage_backend` (auth_status) and `albauth auth status` name the backend that
holds each domain's session: `file` for a domain kept in the file under
`"auto"`, else the store's backend.

Dependency: `github.com/zalando/go-keyring`. Backends: macOS Keychain, Windows
Credential Manager, Linux Secret Service over D-Bus. On Linux with no Secret
Service running it returns an error rather than doing anything clever — that is
exactly where the file fallback engages.

- Keyring service name: `albauth`
- Keyring key: the domain `name`
- Value: the JSON blob below

### 7.2 File backend

- Path: `$XDG_STATE_HOME/albauth/sessions.json`, else
  `~/.local/state/albauth/sessions.json`
  (macOS: `~/Library/Application Support/albauth/sessions.json`;
  Windows: `%LOCALAPPDATA%\albauth\sessions.json`)
- Directory mode `0700`, file mode `0600`. **Verify mode on read**; if the file
  is group- or world-readable, refuse to load it and tell the user to fix it.
- Write atomically: write to `sessions.json.tmp` in the same dir, `fsync`,
  `rename`.

### 7.3 Stored shape

```json
{
  "version": 1,
  "domains": {
    "internal-api": {
      "cookies": [
        {
          "name": "AWSELBAuthSessionCookie-0",
          "value": "...",
          "domain": "api.example.com",
          "path": "/",
          "expires": "2026-08-26T09:12:44Z",
          "secure": true,
          "http_only": true
        }
      ],
      "acquired_at": "2026-08-25T09:12:44Z",
      "last_used_at": "2026-08-25T11:03:02Z"
    }
  }
}
```

Treat a cookie as expired if `expires` is in the past **minus a 60s skew
buffer**. Expired → run login before the request rather than after a failure.

Only cookies in the domain's session family are stored: a name equal to
`cookie_name_prefix`, or that name followed by `-` or `_` and digits (§5.1).
The browser capture, `auth import`, the post-login filter, the refresh
write-back (§5.3) and the application cookie jar's refusal to hold session
cookies all use this one rule, so they agree on what the session is.

The stored cookies are not frozen at login: a session cookie the proxy
reissues on an authenticated response replaces the stored one (§5.3), so a
proxy that keeps renewing its session keeps albauth's copy current.

### 7.4 Redaction

Cookie values must never appear in logs, MCP tool results, or error messages.
Log them as `AWSELBAuthSessionCookie-0=<redacted:len=1184>`. Add a
`redact.go` helper and use it everywhere; add a test that greps rendered log
output for a known cookie value.

---

## 8. MCP Interface

Transport: **stdio**. Server name `albauth`, version from build ldflags.

**Critical:** stdout is the MCP channel. All logging goes to **stderr**. Any
stray `fmt.Println` will corrupt the protocol — enforce with a lint rule or a
custom logger that only accepts an `io.Writer` bound to stderr.

Suggested SDK: `github.com/mark3labs/mcp-go` (or the official
`modelcontextprotocol/go-sdk` if preferred — the tool surface below is
SDK-agnostic).

### 8.1 `http_request`

The workhorse. **v1 is a single generic request tool** — no OpenAPI-derived
typed tools. Typed tools are nicer for the model but require a spec per domain
and a code-generation step; that's v2. Note the tradeoff and move on.

```json
{
  "name": "http_request",
  "description": "Make an authenticated HTTP request to a configured domain behind AWS ALB OIDC. Authentication is handled transparently; on first use for a domain a browser window will open for login.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "url": {
        "type": "string",
        "description": "Full URL (https://api.example.com/v1/users) or a path (/v1/users) when 'domain' is given."
      },
      "domain": {
        "type": "string",
        "description": "Configured domain name. Optional if 'url' is absolute and matches a configured domain."
      },
      "method": {
        "type": "string",
        "enum": ["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"],
        "default": "GET"
      },
      "query": {
        "type": "object",
        "additionalProperties": { "type": "string" },
        "description": "Query parameters, appended to the URL."
      },
      "headers": {
        "type": "object",
        "additionalProperties": { "type": "string" }
      },
      "body": {
        "type": "string",
        "description": "Raw request body. For JSON, pass a JSON string and set Content-Type."
      }
    },
    "required": ["url"]
  }
}
```

Resolution rules:
- absolute `url` → match its host against every domain's `match` globs. No
  match → error `unknown_domain` listing configured domains.
- relative `url` → `domain` is required; join against that domain's `base_url`.
- both given and inconsistent → error `domain_mismatch`.
- `method` not in that domain's `allow_methods` → error `method_not_allowed`,
  naming the config key to change.

Result content (a single `text` block containing JSON):

```json
{
  "status": 200,
  "headers": { "content-type": "application/json" },
  "body": "…",
  "truncated": false,
  "authenticated": true,
  "relogin_performed": false
}
```

- Strip `Set-Cookie` from returned headers. A session cookie the proxy
  reissued is kept in the session store instead (§5.3); its value never
  appears in the result.
- If body exceeds `max_response_bytes`, truncate and set `"truncated": true`,
  appending `\n…[truncated: N bytes total]` to the body.
- Non-2xx is **not** a tool error — return the status and body so the model can
  reason about it. Only transport/auth/config failures are tool errors.

### 8.2 `auth_login`

```json
{
  "name": "auth_login",
  "description": "Open a browser to authenticate against a configured domain. Normally unnecessary — http_request triggers this automatically.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "domain": { "type": "string" },
      "force":  { "type": "boolean", "default": false,
                  "description": "Discard any existing session and re-authenticate." }
    },
    "required": ["domain"]
  }
}
```

Returns `{ "domain": "...", "authenticated": true, "expires_at": "..." }`.

### 8.3 `auth_status`

```json
{
  "name": "auth_status",
  "description": "Report authentication state for one or all configured domains.",
  "inputSchema": {
    "type": "object",
    "properties": { "domain": { "type": "string" } }
  }
}
```

Returns an array of
`{ "domain", "base_url", "authenticated", "expires_at", "acquired_at", "storage_backend", "allow_methods" }`.
Never include cookie values.

### 8.4 `auth_logout`

```json
{
  "name": "auth_logout",
  "description": "Delete the stored session for a domain. Does not log the user out of the IdP.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "domain": { "type": "string" },
      "clear_browser_profile": { "type": "boolean", "default": false,
        "description": "Also delete the persistent browser profile, forcing a full IdP login next time." }
    },
    "required": ["domain"]
  }
}
```

### 8.5 `list_domains`

No arguments. Returns the configured domains with `name`, `base_url`, `match`,
`allow_methods`. Lets the model discover what it can reach without reading
config off disk.

---

## 9. Error Model

Every tool error returns a JSON text block:

```json
{ "error": "login_timeout", "message": "…", "hint": "…" }
```

| Code | When | Hint should say |
|---|---|---|
| `unknown_domain` | URL host matches no config | list configured domains |
| `domain_mismatch` | `url` host ≠ `domain`'s host | — |
| `method_not_allowed` | method not in `allow_methods` | name the config key |
| `no_browser` | chromedp found no Chrome/Chromium | install Chrome, or use `albauth auth import` |
| `login_timeout` | browser flow exceeded timeout | raise `login_timeout_seconds` |
| `login_failed` | flow settled but no ALB cookie appeared | check `idp_hostnames` and ALB listener rule |
| `auth_loop` | still unauthenticated after one re-login + retry | session may be immediately invalidated; check ALB rule scope |
| `resend_required` | a write (not `GET`/`HEAD`/`OPTIONS`) was judged unauthenticated by a `401` or an HTML `401`/`403`, not an IdP redirect; the re-login ran but the write was not sent again | session was refreshed; the write may already have been applied — resend only if repeating it is safe |
| `storage_unavailable` | keyring required but absent, or session too large for it | set `storage = "file"` (or `"auto"` when too large) |
| `storage_insecure` | session file mode not 0600 | `chmod 600 <path>` |
| `upstream_timeout` | request exceeded `timeout_seconds` | — |
| `config_invalid` | startup validation failed | list every problem |

---

## 10. CLI Surface

The binary is primarily an MCP server, but needs a few subcommands for setup
and for the headless fallback.

```
albauth serve                     # default when no subcommand; stdio MCP server
albauth auth login <domain>       # run the browser flow interactively
albauth auth status [<domain>]    # human-readable table
albauth auth logout <domain> [--clear-browser-profile]
albauth auth import <domain>      # headless fallback, see below
albauth config validate           # parse + validate, print result, exit 0/1
albauth config path               # print resolved config path
albauth version
```

Global flags: `--config <path>`, `--log-level <level>`.

### `albauth auth import <domain>`

For machines with no browser (CI, remote dev box, container). Prints:

```
On a machine with a browser:
  1. Log in to https://api.example.com in Chrome or Firefox.
  2. Open DevTools → Application → Cookies → https://api.example.com
  3. Copy the value of every cookie named AWSELBAuthSessionCookie, AWSELBAuthSessionCookie-N or AWSELBAuthSessionCookie_N
     (N a number: a large session is split into chunks -0, -1, ...)

Paste them here as NAME=VALUE, one per line. Blank line to finish:
```

Reads from stdin **with terminal echo disabled** (`golang.org/x/term`),
validates that at least one name is in the session family (`cookie_name_prefix`
or a numbered chunk of it, §5.1) and keeps only those, and persists via
the normal storage path. Since ALB cookies carry no readable expiry when copied
this way, set `expires` to `acquired_at + 8h` as a heuristic and let normal
expiry detection (§5.2) catch it early if wrong.

---

## 11. Package Layout

```
cmd/albauth/main.go          # flag parsing, subcommand dispatch, wiring
internal/config/            # TOML load, defaults, validation, path resolution
  config.go
  validate.go
internal/session/           # storage abstraction
  store.go                  # interface: Get/Set/Delete(domain) 
  keyring.go                # zalando/go-keyring backend
  file.go                   # 0600 JSON backend, atomic write, mode check
  model.go                  # Session, Cookie structs, expiry logic
internal/auth/
  login.go                  # chromedp state machine (§5.1)
  detect.go                 # unauthenticated-response detection (§5.2)
  import.go                 # manual cookie import
internal/httpx/
  client.go                 # per-domain client, cookie jar, no-follow redirects
  do.go                     # request → detect → relogin → retry-once
internal/mcpserver/
  server.go                 # tool registration, stdio wiring
  tools.go                  # the five tool handlers
internal/logx/
  log.go                    # stderr-only logger
  redact.go                 # cookie redaction helper
```

### Dependencies (keep this list short)

- `github.com/mark3labs/mcp-go` — MCP server
- `github.com/chromedp/chromedp` — browser automation
- `github.com/zalando/go-keyring` — cross-platform secret storage
- `github.com/BurntSushi/toml` — config
- `golang.org/x/term` — echo-off stdin for `auth import`
- stdlib for everything else

---

## 12. Testing

**Unit**
- Config validation: every rule in §6 has a failing-input test.
- `detect.go`: table test covering all four detection rules in §5.2 plus
  legitimate same-host 302s (must NOT be treated as auth failures).
- Session expiry incl. the 60s skew buffer.
- File store: mode enforcement, atomic write, corrupt-JSON recovery.
- Redaction: assert no known cookie value appears in rendered log output.

**Integration (`httptest`-based fake ALB)**
Build a test server that mimics ALB: no cookie → 302 to a fake IdP host; a
`/oauth2/idpresponse` that sets `AWSELBAuthSessionCookie-0` and `-1`; cookie
present → 200 JSON. Test:
- unauthenticated → login triggered → retry succeeds
- expired cookie → single re-login → success, `relogin_performed: true`
- persistently rejected cookie → `auth_loop`, exactly one retry, no infinite loop
- chunked cookies (`-0`, `-1`) both captured and both replayed
- concurrent `http_request` calls during expiry → one login, not N

For these, stub the login step behind the `auth.Loginer` interface so tests
don't need Chrome. Keep a single build-tagged (`//go:build manual`) test that
exercises the real chromedp path.

**Manual smoke test**
`albauth auth login <domain>` against a real ALB, then `auth status`, then an
`http_request` through the MCP server. Document this in the README.

---

## 13. Acceptance Criteria

1. `go build` produces a single static binary per target with `CGO_ENABLED=0`.
2. With a valid config and zero prior state, the first `http_request` opens a
   browser, the user logs in, and the tool returns the API response — no manual
   cookie handling anywhere.
3. The second and all subsequent `http_request` calls make no browser window
   appear and complete in normal request latency.
4. After the session expires, the next `http_request` re-authenticates (usually
   without user interaction thanks to the persistent browser profile) and
   returns the response with `relogin_performed: true`.
5. Cookie values never appear on stdout, in stderr logs, or in any tool result.
6. On a headless Linux box with no Secret Service and no Chrome, `auth import`
   is a complete path to a working setup, and the file-backend warning fires
   exactly once.
7. stdout carries only MCP protocol traffic. Verified by piping stdout to a
   strict JSON-RPC parser during the integration suite.
8. `albauth config validate` reports every config error at once, not just the first.

---

## 14. Deferred to v2

- OpenAPI-driven typed tools per endpoint (one tool per operation, real
  parameter schemas). Much better for model ergonomics; needs a spec per domain
  and codegen.
- Local HTTP forward-proxy mode for non-MCP clients (`HTTPS_PROXY=localhost:PORT`),
  with a generated CA — this is the *only* legitimate way to do the
  transparent-interception idea, and it's a big chunk of work.
- Firefox / WebKit CDP alternatives.
- Response caching with ETag support.
- Reading cookies out of an existing browser profile on disk (kooky-style) as a
  third acquisition path.
