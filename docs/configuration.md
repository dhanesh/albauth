# Configuration

albauth reads one TOML file. A copy with every key and its default is in
[`config.example.toml`](../config.example.toml).

## Where the file lives

Resolved in this order; the first that yields a path wins:

1. `--config <path>`
2. `$ALBAUTH_CONFIG`
3. `$XDG_CONFIG_HOME/albauth/config.toml`, else `~/.config/albauth/config.toml`
   (Windows: `%APPDATA%\albauth\config.toml`)

`albauth config path` prints the resolved path without needing the file to exist.

## Minimum viable config

```toml
[[domain]]
name = "internal-api"
base_url = "https://api.example.com"
```

Everything else has a default.

## `[[domain]]`

One block per host behind a listener rule. Repeat the block for more.

### `name` — required

The stable identifier for this domain: the keychain key, the `domain` argument
in tool calls, and the argument on the command line.

Must match `^[a-z0-9][a-z0-9._-]*$` — lower case, starting with a letter or
digit. Must be unique across the file.

```toml
name = "internal-api"
```

### `base_url` — required

Scheme plus host, plus a port if it is not the default. **No trailing slash.**

Must be `https`. Plain `http` is allowed only for loopback, which exists so you
can point albauth at a local test server. Loopback means `localhost`, a loopback
IP, or **any name under the reserved `.localhost` TLD** (RFC 6761 §6.3) — the
shape local AWS emulators and development proxies hand out per service.

```toml
base_url = "https://api.example.com"
base_url = "https://api.example.com:8443"
base_url = "http://localhost:8080"             # allowed: loopback
base_url = "http://127.0.0.1:8080"             # allowed: loopback
base_url = "http://mylb.alb.localhost:4566"    # allowed: .localhost is loopback
base_url = "http://localhost.example.com"      # REJECTED: not a .localhost name
```

### `match` — optional

Glob patterns for the hosts this domain claims. Used to route an absolute URL
passed to `http_request` to the right domain.

Default: the host of `base_url`.

```toml
match = ["api.example.com", "*.internal.example.com"]
```

Patterns use shell glob syntax: `*` matches any run of characters, `?` matches
one. Matching is case-insensitive.

**Two domains may not claim overlapping patterns.** If `api.example.com` and
`*.example.com` are claimed by different domains, a request to
`api.example.com` could route either way, so albauth refuses to start rather
than pick one. Overlap *within* one domain is fine — it still routes one way.

### `login_probe_path` — optional

The path opened in the browser to start the login flow. Should be cheap and
behind the same listener rule as the rest of the domain.

Default: `"/"`. Must start with `/`.

```toml
login_probe_path = "/healthz"
```

### `cookie_name_prefix` — optional

The cookie family the load balancer issues. Every cookie whose name starts with
this is captured, stored and replayed — which is what makes chunked sessions
(`-0`, `-1`, `-2`, …) work.

Default: `"AWSELBAuthSessionCookie"`. Change it only if your load balancer is
configured with a non-standard cookie name.

### `idp_hostnames` — optional, recommended

The hostnames of your identity provider. A redirect to one of these is the
clearest possible signal that the session has expired.

Default: `[]`.

```toml
idp_hostnames = ["login.example.net", "sso.example.org"]
```

Without it albauth still detects expiry — it falls back to treating *any*
cross-host redirect off an API endpoint as one — but naming the provider makes
the detection precise and the logs readable. Find the hostname by opening your
API URL in a private browser window and reading where you land.

### `allow_methods` — optional

Which HTTP methods the model may issue against this domain.

Default: `["GET"]`. **This fails closed on purpose**: a model cannot write to a
domain until you say it may. Values are case-insensitive and normalised to upper
case; anything outside `GET POST PUT PATCH DELETE HEAD OPTIONS` is a config
error.

```toml
allow_methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
```

A method not on the list is refused before any request leaves the machine, with
an error naming this key.

### `timeout_seconds` — optional

Per-request timeout. Default `30`. Must be positive.

### `login_timeout_seconds` — optional

How long to wait for the interactive browser flow to complete. Default `180`.
Must be positive.

Raise it if your identity provider involves a slow step — a hardware token, an
approval on another device.

### `[domain.headers]` — optional

Headers added to every request to this domain. Useful for a client identifier
or a tenancy header your API expects.

```toml
[domain.headers]
"X-Client" = "albauth"
"X-Tenant" = "engineering"
```

A header supplied in a tool call overrides one set here.

## `[settings]`

Global, all optional.

### `storage`

Where session cookies are kept.

| Value | Behaviour |
|---|---|
| `"auto"` (default) | Try the OS keychain. If it is unreachable, use a `0600` file and warn once. |
| `"keyring"` | The OS keychain only. If none is available, that is a hard failure. |
| `"file"` | A `0600` file only, with no warning. |

Backends are macOS Keychain, Windows Credential Manager, and Linux Secret
Service over D-Bus. On a headless Linux box with no Secret Service running,
`"auto"` falls back to the file backend — which is exactly what the fallback is
for.

The file lives at `$XDG_STATE_HOME/albauth/sessions.json`, else
`~/.local/state/albauth/sessions.json` (macOS:
`~/Library/Application Support/albauth/sessions.json`; Windows:
`%LOCALAPPDATA%\albauth\sessions.json`). It is written atomically, and it is
**refused on read** if its permissions have been widened past `0600`.

### `max_response_bytes`

The largest response body handed back to the model. Default `1048576` (1 MiB).

Longer bodies are truncated, marked `"truncated": true`, and given a marker
naming the real total. Set to `0` for no limit — but a model reading a
hundred-megabyte response is rarely what you want.

### `log_level`

`error`, `warn`, `info` (default), or `debug`.

All logging goes to **stderr**. stdout is the MCP protocol channel and carries
nothing else; there is an end-to-end test that parses every line the server
writes to stdout as JSON-RPC to keep it that way.

Override at run time with `--log-level`.

## Validation

```bash
albauth config validate
```

Reports **every** problem in the file at once, not just the first:

```
albauth: invalid config /home/you/.config/albauth/config.toml (4 problem(s)):
  - domain "BAD NAME": name must match ^[a-z0-9][a-z0-9._-]*$
  - domain "BAD NAME": base_url must not have a trailing slash (got "ftp://api.example.com/")
  - domain "BAD NAME": base_url scheme must be https (got "ftp")
  - domain "BAD NAME": allow_methods[0]: "TRACE" is not a supported HTTP method
```

The rules checked:

- `name` present, unique, and matching the pattern
- `base_url` parseable, with a host, `https` (or loopback `http`), no trailing slash
- `login_probe_path` starts with `/`
- `cookie_name_prefix` not empty
- `timeout_seconds` and `login_timeout_seconds` positive
- every `allow_methods` entry a supported method
- every `match` pattern a valid glob
- no two domains claiming overlapping `match` patterns
- `settings.storage` one of `auto`, `keyring`, `file`
- `settings.max_response_bytes` not negative
- `settings.log_level` a known level
- at least one `[[domain]]` block

## A worked example

```toml
[[domain]]
name = "internal-api"
base_url = "https://api.example.com"
match = ["api.example.com", "*.api.internal.example.com"]
login_probe_path = "/healthz"
idp_hostnames = ["login.example.net"]
allow_methods = ["GET", "POST", "PATCH"]
timeout_seconds = 45
login_timeout_seconds = 300          # a hardware token takes a while

[domain.headers]
"X-Client" = "albauth"

[[domain]]
name = "admin-console"
base_url = "https://admin.example.com"
idp_hostnames = ["login.example.net"]
# allow_methods omitted: read-only

[settings]
storage = "auto"
max_response_bytes = 4194304          # 4 MiB; these APIs return large pages
log_level = "info"
```
