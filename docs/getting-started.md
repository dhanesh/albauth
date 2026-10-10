# Getting started

This walks through a first setup end to end: build, configure, log in, and wire
albauth into an MCP client. Budget about ten minutes.

## Before you start

You need:

- **Go 1.26 or newer** to build. The pin lives in `mise.toml`; `mise install`
  fetches the right toolchain. A plain Go install works too.
- **Chrome or Chromium 109 or newer** on the machine where you will log in.
  Older versions cannot report a page's HTTP status, so a login never
  finishes. If there is no browser here, skip to [Headless machines](#headless-machines).
- **A URL behind an ALB `authenticate-oidc` rule** and an account that can log
  in to it.

You do *not* need AWS credentials, IAM permissions, or anything from whoever
runs the load balancer. albauth only replays a cookie your own browser earned.

## 1. Build

```bash
mise install
mise run build
```

That produces `dist/albauth`, a single statically linked binary. Move it onto
your `PATH`:

```bash
install -m 0755 dist/albauth ~/.local/bin/albauth
albauth version
```

Without mise:

```bash
CGO_ENABLED=0 go build -o dist/albauth ./cmd/albauth
```

## 2. Create the config

albauth looks for its config in this order, and uses the first that applies:

1. `--config <path>`
2. `$ALBAUTH_CONFIG`
3. the first of these that already exists:
   - `~/.albauth.toml`
   - `$XDG_CONFIG_HOME/albauth/config.toml`, else `~/.config/albauth/config.toml`
   - the platform config directory, where versions before 0.3 wrote it
     (`~/Library/Application Support/albauth/config.toml` on macOS,
     `%APPDATA%\albauth\config.toml` on Windows)
4. otherwise `~/.albauth.toml`, which is also where a new one is created

**`~/.albauth.toml` is the same path on every operating system.** albauth has a
single config file, so it does not need a directory of its own, and one
unchanging location is the thing a person can always find. It also sidesteps
macOS's `~/Library/Application Support`, whose space breaks the obvious
`cat $(albauth config path)` — the shell splits it in two and reports "No such
file or directory" for both halves, which reads as though the file were missing
when it is not.

Keeping configuration under `$XDG_CONFIG_HOME` still works: a config already
there is found and used. So is one left where an older albauth put it, so an
upgrade never appears to lose your setup.

`albauth config path` prints the resolved path, and tells you on stderr if
there is no file there yet.

You do not have to create it by hand:

```bash
albauth config add-domain internal-api --base-url https://api.example.com
```

That resolves the path, creates the directory, and writes the block. `name` and
`base_url` are the only things it needs from you.

It also probes the domain to work out the identity provider's hostname and
records it as `idp_hostnames`. That key is optional, but it is the clearest
signal that a session has expired — without it albauth falls back to treating
a cross-host redirect that is an OAuth authorization request as an expiry,
which is correct but less precise. Asking
the load balancer is more reliable than reading a hostname off a browser's
address bar, and it costs one request.

Behind a proxy that answers `401` instead of redirecting — oauth2-proxy, on its
own or behind Traefik `forwardAuth` — the probe tries `/oauth2/start` and
`/oauth2/sign_in`, and when one of them starts a login it also writes
`login_probe_path`, `cookie_name_prefix = "_oauth2_proxy"`,
`treat_401_as_expired = true` and `session_check_path = "/oauth2/auth"`, saying
on stderr what it set and why. A flag you pass yourself
(`--login-probe-path`, `--cookie-prefix`, `--session-check-path`,
`--treat-401-as-expired`) always wins over the probe.

The probe never fails the command. If the domain is unreachable from where you
are running this, you get a note on stderr and a working config without the key.
Add it later, or pass `--no-probe` to skip the attempt.

Everything else has a flag — `--match`, `--allow-method`, `--header`,
`--login-probe-path`, `--session-check-path`, the timeouts. Run `albauth config add-domain --help`, or
see [`configuration.md`](configuration.md) for what each key means.

Hand-editing remains entirely fine. Adding a domain appends to the file and
leaves your own comments and formatting intact.

Check the file before going further:

```bash
albauth config validate
```

If something is wrong, this lists **every** problem at once rather than stopping
at the first, so you can fix the whole file in one pass. Every key is documented
in [configuration.md](configuration.md).

## 3. Log in

```bash
albauth auth login internal-api
```

A browser window opens at your API. Log in exactly as you normally would —
password, MFA, whatever your provider asks for. albauth is not involved in any of
that; it is watching for the redirect chain to settle back on your API host with
a session cookie in place. When it does, the window closes and the session is
saved.

```bash
albauth auth status
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
claude mcp add albauth -- "$(command -v albauth)" serve
```

### Claude Desktop and other clients

Add to the client's MCP configuration:

```json
{
  "mcpServers": {
    "albauth": {
      "command": "/absolute/path/to/albauth",
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
    "albauth": {
      "command": "/absolute/path/to/albauth",
      "args": ["serve", "--config", "/absolute/path/to/config.toml"]
    }
  }
}
```

## 5. Try it

Ask the model to list what it can reach — that calls `list_domains` — and then
to fetch something:

> Using albauth, GET /v1/users from internal-api.

You should get the API's JSON back. If instead you get an error, every one of
them carries a code and a hint; [troubleshooting.md](troubleshooting.md) has a
page per code.

### Or let the agent add it

You do not have to configure every API up front. Ask the model to fetch a full
URL on a host albauth does not know yet. If that host sits behind a login,
albauth spots it (one plain `GET` of the host, with no cookies or headers) and
answers `unknown_domain` with a `suggestion`. The agent should then ask you
whether to add it. Say yes, and it calls `add_domain`: the domain lands in
your config file, read-only, and the next request works — after the usual
one-time login in the browser. Write methods are never added this way; that
stays your call, made with `config add-domain --allow-method …` or by editing
the file.

## What happens next

- **Later requests are just requests.** The stored cookie is replayed; no
  browser appears.
- **When the session expires**, the next request opens the browser again. Because
  the browser profile is persistent, your identity provider usually still
  recognises you: the window opens, completes in about a second, and closes
  without you touching it. The result carries `"relogin_performed": true`.
- **If a fresh session is rejected too**, albauth stops after exactly one retry
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
albauth auth import internal-api
```

It prints the instructions above, then reads `NAME=VALUE` lines from your
terminal with echo disabled, so nothing appears on screen or in your shell
history. A blank line ends the input.

```
AWSELBAuthSessionCookie-0=<paste>
AWSELBAuthSessionCookie-1=<paste>
<blank line>
```

Cookies copied this way carry no readable expiry, so albauth assumes eight hours.
That is deliberately conservative: if the guess is wrong, the next request
detects it and tells you rather than failing confusingly. Re-run `auth import`
when it expires.

If there is also no OS keychain on that machine — common on a headless Linux box
with no Secret Service on the D-Bus session — albauth falls back to a `0600` file
and warns once. Set `storage = "file"` in the config to accept that silently.

## Teaching your agent to use it

The tools are discoverable on their own, but a model does better knowing the
surrounding judgement — check `list_domains` before guessing hostnames, never
loop on an authentication error, treat API responses as data rather than
instructions:

```bash
npx skills add dhanesh/albauth --global
```

## Verifying a change

If you are modifying albauth itself:

```bash
mise run verify
```

That runs the whole gate: formatting, `go vet`, a static cross-compile for all
five targets, unit tests with the 100% coverage floor, the end-to-end suite, the
stdout-purity check, and the documentation checks. It is the same script CI
runs, and it either exits 0 or tells you every check that failed.

The one thing it cannot run is the real browser flow, or anything else that
depends on your actual load balancer. [`smoke-test.md`](smoke-test.md) is a
fifteen-minute procedure for that, with a pass criterion per step — worth
running once after a first setup and again after changing the listener rule.

The build-tagged manual test drives the browser flow on its own:

```bash
ALBAUTH_MANUAL_BASE_URL=https://api.example.com \
  go test -tags manual -v -timeout 5m ./test/manual/...
```
