# Getting started

This walks through a first setup end to end: build, configure, log in, and wire
albmcp into an MCP client. Budget about ten minutes.

## Before you start

You need:

- **Go 1.26 or newer** to build. The pin lives in `mise.toml`; `mise install`
  fetches the right toolchain. A plain Go install works too.
- **Chrome or Chromium** on the machine where you will log in. If there is no
  browser here, skip to [Headless machines](#headless-machines).
- **A URL behind an ALB `authenticate-oidc` rule** and an account that can log
  in to it.

You do *not* need AWS credentials, IAM permissions, or anything from whoever
runs the load balancer. albmcp only replays a cookie your own browser earned.

## 1. Build

```bash
mise install
mise run build
```

That produces `dist/albmcp`, a single statically linked binary. Move it onto
your `PATH`:

```bash
install -m 0755 dist/albmcp ~/.local/bin/albmcp
albmcp version
```

Without mise:

```bash
CGO_ENABLED=0 go build -o dist/albmcp ./cmd/albmcp
```

## 2. Create the config

albmcp looks for its config in this order:

1. `--config <path>`
2. `$ALBMCP_CONFIG`
3. `$XDG_CONFIG_HOME/albmcp/config.toml`, else `~/.config/albmcp/config.toml`
   (Windows: `%APPDATA%\albmcp\config.toml`)

Ask it where that lands and put a file there:

```bash
CONFIG="$(albmcp config path)"
mkdir -p "$(dirname "$CONFIG")"
cat > "$CONFIG" <<'TOML'
[[domain]]
name = "internal-api"
base_url = "https://api.example.com"
idp_hostnames = ["login.example.net"]
TOML
```

`name` and `base_url` are the only required keys.

`idp_hostnames` is optional but worth setting: it is the clearest signal that a
session has expired. Find it by opening your API URL in a private browser window
and reading the hostname you land on. Without it albmcp still works — it falls
back to treating any cross-host redirect as an expiry — but the detection is
less precise.

Check the file before going further:

```bash
albmcp config validate
```

If something is wrong, this lists **every** problem at once rather than stopping
at the first, so you can fix the whole file in one pass. Every key is documented
in [configuration.md](configuration.md).

## 3. Log in

```bash
albmcp auth login internal-api
```

A browser window opens at your API. Log in exactly as you normally would —
password, MFA, whatever your provider asks for. albmcp is not involved in any of
that; it is watching for the redirect chain to settle back on your API host with
a session cookie in place. When it does, the window closes and the session is
saved.

```bash
albmcp auth status
```

```
DOMAIN        BASE URL                  STATE          EXPIRES               STORAGE
internal-api  https://api.example.com   authenticated  2026-08-26T20:12:44Z  keyring
```

`STORAGE` tells you where the session went: `keyring` for your OS keychain,
`file` for a `0600` file. If it says `file` and you expected `keyring`, the
warning on stderr explains why.

This step is optional. The first `http_request` does the same thing
automatically. Running it by hand just means the browser window opens when you
are looking at the screen rather than in the middle of a conversation.

## 4. Connect an MCP client

### Claude Code

```bash
claude mcp add albmcp -- "$(command -v albmcp)" serve
```

### Claude Desktop and other clients

Add to the client's MCP configuration:

```json
{
  "mcpServers": {
    "albmcp": {
      "command": "/absolute/path/to/albmcp",
      "args": ["serve"]
    }
  }
}
```

Use an absolute path. MCP clients rarely inherit your shell's `PATH`.

If your client does not pass through the environment, point it at the config
explicitly:

```json
{
  "mcpServers": {
    "albmcp": {
      "command": "/absolute/path/to/albmcp",
      "args": ["serve", "--config", "/absolute/path/to/config.toml"]
    }
  }
}
```

## 5. Try it

Ask the model to list what it can reach — that calls `list_domains` — and then
to fetch something:

> Using albmcp, GET /v1/users from internal-api.

You should get the API's JSON back. If instead you get an error, every one of
them carries a code and a hint; [troubleshooting.md](troubleshooting.md) has a
page per code.

## What happens next

- **Later requests are just requests.** The stored cookie is replayed; no
  browser appears.
- **When the session expires**, the next request opens the browser again. Because
  the browser profile is persistent, your identity provider usually still
  recognises you: the window opens, completes in about a second, and closes
  without you touching it. The result carries `"relogin_performed": true`.
- **If a fresh session is rejected too**, albmcp stops after exactly one retry
  and returns `auth_loop`. That means the listener rule is scoped differently
  from what you are requesting — not a cookie problem.

## Headless machines

CI, a remote development box, a container: anywhere without a browser.

On a machine that **does** have a browser, log in to the API normally, then open
developer tools → Application → Cookies, and copy every cookie whose name starts
with `AWSELBAuthSessionCookie`. There is usually more than one: the load
balancer splits a large session across `-0`, `-1`, and so on, and **you need all
of them**.

On the headless machine:

```bash
albmcp auth import internal-api
```

It prints the instructions above, then reads `NAME=VALUE` lines from your
terminal with echo disabled, so nothing appears on screen or in your shell
history. A blank line ends the input.

```
AWSELBAuthSessionCookie-0=<paste>
AWSELBAuthSessionCookie-1=<paste>
<blank line>
```

Cookies copied this way carry no readable expiry, so albmcp assumes eight hours.
That is deliberately conservative: if the guess is wrong, the next request
detects it and tells you rather than failing confusingly. Re-run `auth import`
when it expires.

If there is also no OS keychain on that machine — common on a headless Linux box
with no Secret Service on the D-Bus session — albmcp falls back to a `0600` file
and warns once. Set `storage = "file"` in the config to accept that silently.

## Verifying a change

If you are modifying albmcp itself:

```bash
mise run verify
```

That runs the whole gate: formatting, `go vet`, a static cross-compile for all
five targets, unit tests with the 100% coverage floor, the end-to-end suite, the
stdout-purity check, and the documentation checks. It is the same script CI
runs, and it either exits 0 or tells you every check that failed.

The one thing it cannot run is the real browser flow. Exercise that by hand:

```bash
ALBMCP_MANUAL_BASE_URL=https://api.example.com \
  go test -tags manual -v -timeout 5m ./test/manual/...
```
