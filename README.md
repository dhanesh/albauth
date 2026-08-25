# albmcp

An MCP server that lets a model call HTTP APIs sitting behind an AWS
Application Load Balancer with an `authenticate-oidc` listener rule.

You log in once, in a real browser. After that the model calls the API as if
the authentication layer were not there.

---

## The problem it solves

An ALB with an `authenticate-oidc` rule redirects every unauthenticated request
to your identity provider. A browser can complete that flow; an MCP client
cannot. It follows the redirect, lands on a login page, and stops.

The cookie the load balancer wants (`AWSELBAuthSessionCookie-*`) is issued by
the load balancer itself, on its own hostname, only after a browser has finished
the identity-provider flow. There is no way around that:

- Doing the OAuth dance yourself gets you an ID token. The load balancer does
  not accept ID tokens — only its own cookie.
- Scripting the login form breaks on password prompts, MFA, and device trust.
- Pointing the browser at a local proxy does not help, because the callback URL
  points at the real load balancer, so the cookie is set out of band.

`albmcp` does the only thing that works: it opens a real browser window, lets
*you* complete the login, reads the resulting cookie out of the browser, stores
it in your OS keychain, and replays it on every request the model makes.

## Quick start

### 1. Install

Requires Go 1.26 or newer. This project pins its toolchain with
[mise](https://mise.jdx.dev):

```bash
mise install          # installs the pinned Go toolchain
mise run build        # builds ./dist/albmcp
```

Without mise, a plain Go toolchain works too:

```bash
CGO_ENABLED=0 go build -o dist/albmcp ./cmd/albmcp
```

The result is a single statically linked binary with no runtime dependencies.
Put it somewhere on your `PATH`.

### 2. Write a config

Find where the config belongs, and create it:

```bash
albmcp config path
# ~/.config/albmcp/config.toml

mkdir -p "$(dirname "$(albmcp config path)")"
cp config.example.toml "$(albmcp config path)"
```

The minimum viable config is two lines per domain:

```toml
[[domain]]
name = "internal-api"
base_url = "https://api.example.com"
```

Then check it:

```bash
albmcp config validate
# config /home/you/.config/albmcp/config.toml is valid: 1 domain(s) configured
```

Validation reports **every** problem at once, so one round of edits fixes the
whole file. See [docs/configuration.md](docs/configuration.md) for every key.

### 3. Log in once

```bash
albmcp auth login internal-api
```

A browser window opens. Complete your normal login. The window closes by
itself, and the session is stored:

```bash
albmcp auth status
# DOMAIN        BASE URL                  STATE          EXPIRES               STORAGE
# internal-api  https://api.example.com   authenticated  2026-08-26T20:12:44Z  keyring
```

This step is optional — the first `http_request` triggers it automatically.
Doing it up front just means the browser opens when you are expecting it.

### 4. Point your MCP client at it

Claude Code:

```bash
claude mcp add albmcp -- /path/to/albmcp serve
```

Claude Desktop, or any client using the standard config file:

```json
{
  "mcpServers": {
    "albmcp": {
      "command": "/path/to/albmcp",
      "args": ["serve"]
    }
  }
}
```

### 5. Use it

The model now has five tools. In practice it only needs one:

```
http_request { "url": "/v1/users", "domain": "internal-api" }
```

which returns

```json
{
  "status": 200,
  "headers": { "content-type": "application/json" },
  "body": "{\"users\":[…]}",
  "truncated": false,
  "authenticated": true,
  "relogin_performed": false
}
```

## Tools

| Tool | What it does |
|---|---|
| `http_request` | The workhorse. Makes an authenticated request; handles login and re-login on its own. |
| `auth_login` | Force a login for a domain. Rarely needed. |
| `auth_status` | Report authentication state. Never includes cookie values. |
| `auth_logout` | Delete a stored session, optionally the browser profile too. |
| `list_domains` | List reachable domains, so the model can discover what it can call without reading your config. |

`http_request` accepts `url`, `domain`, `method`, `query`, `headers` and `body`.
An absolute URL routes by host; a path needs `domain`. A non-2xx status comes
back as a normal result with its status and body — only transport, auth and
config failures are tool errors.

## Command line

```
albmcp serve                     # stdio MCP server (the default)
albmcp auth login <domain>       # run the browser flow, --force to redo it
albmcp auth status [<domain>]    # human-readable table
albmcp auth logout <domain> [--clear-browser-profile]
albmcp auth import <domain>      # headless fallback, see below
albmcp config validate           # parse and validate, exit 0 or 1
albmcp config path               # print the resolved config path
albmcp version
```

Global flags: `--config <path>`, `--log-level error|warn|info|debug`.

## No browser on this machine?

CI, a remote development box, a container: `auth import` takes cookies you
copied from a browser elsewhere.

```bash
albmcp auth import internal-api
```

It prints instructions, then reads `NAME=VALUE` lines from your terminal **with
echo disabled**, so the values never appear on screen or in your shell history.
A blank line finishes.

Cookies copied this way carry no readable expiry, so albmcp assumes eight hours.
If that guess is wrong, the normal expiry detection catches it on the next
request. See [docs/getting-started.md](docs/getting-started.md#headless-machines).

## How it stays out of your way

- **One login per domain.** After that, requests go straight through.
- **Silent re-login.** The browser profile is persistent, so when the session
  expires your identity provider usually still recognises you: the window opens,
  the redirect chain completes in about a second, and it closes again untouched.
- **One browser, not N.** A burst of concurrent requests hitting an expired
  session produces a single login, not one per request.
- **Exactly one retry.** If a freshly acquired session is rejected too, that is
  a problem with the listener rule, not the cookie. albmcp says so (`auth_loop`)
  instead of opening browser windows forever.

## Security

- **albmcp never sees your password or your MFA.** You type those into your
  identity provider's own page, in a real browser. All albmcp ever holds is the
  session cookie the load balancer issued.
- **Cookie values never leave the machine's storage.** They are not in tool
  results, not in `auth_status`, not on stdout, and not in logs — every log line
  is scrubbed, and there is a test asserting exactly that.
- **Sessions are stored in the OS keychain** (macOS Keychain, Windows Credential
  Manager, Linux Secret Service). Where no keychain is reachable, a `0600` file
  is used instead and you are told once. A session file whose permissions have
  been widened is refused, not read.
- **Writes are opt-in.** `allow_methods` defaults to `["GET"]`. A model cannot
  POST, PUT or DELETE against a domain until you say it may.

## Coverage

`go test ./...` covers every package at **100% of statements**, with two
documented exceptions:

- `internal/browser` — the Chrome DevTools Protocol driver. Every statement in
  it needs a running browser, so it is kept deliberately small and free of
  decision logic; everything testable lives behind the `auth.Loginer` interface.
  It is exercised by the build-tagged manual test:
  `go test -tags manual ./test/manual/...`
- `cmd/albmcp` — a `main` that does nothing but call `cli.Run` and exit with
  its code. The end-to-end suite runs the compiled binary, so this path is
  covered in practice, just not by the unit coverage profile.

Run the whole acceptance gate — formatting, vet, a static cross-compile for all
five targets, unit tests, the coverage floor, the end-to-end suite, the
stdout-purity check and the documentation checks — with:

```bash
mise run verify      # or: ./scripts/verify.sh
```

## Documentation

- [Getting started](docs/getting-started.md) — first run, MCP client setup, the headless path
- [Configuration](docs/configuration.md) — every key, with defaults and validation rules
- [Troubleshooting](docs/troubleshooting.md) — every error code and what to do about it

## Not in scope

No DNS interception, no local TLS termination, no hosts-file edits: domain
routing is explicit in the config, on purpose. Capturing traffic at the DNS
level would mean terminating TLS locally for your real domain, which means a
self-signed certificate and trust-store surgery on every machine — a great deal
of pain to save one line of configuration.

Also not here: a general-purpose HTTP proxy mode, and support for auth schemes
other than ALB OIDC (no bearer tokens, no mTLS, no basic auth passthrough).

## Licence

MIT. See [LICENSE](LICENSE).
