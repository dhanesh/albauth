# Smoke test against a real load balancer

Everything in the automated suites runs against a fake or an emulator. This
procedure is the only one that tells you albauth works against *your* load
balancer, *your* identity provider and *your* API — the three things no test on
a build machine can stand in for.

Work through it once when you first set albauth up, and again after changing
the listener rule, the identity provider, or albauth itself. It takes about
fifteen minutes.

Each step states what passing looks like. Where a step can fail in a way that
still *looks* fine, that is called out — those are the ones worth being
pedantic about.

---

## Before you start

**What you need**

- A URL behind an ALB `authenticate-oidc` listener rule, and an account that
  can log in to it.
- Chrome or Chromium on the machine you are testing from. (Step 8 covers the
  case where you have none.)
- `albauth` on your `PATH` — `albauth version` should answer.

**What to look up**

| Value | How to find it |
|---|---|
| Base URL | The hostname that terminates the OIDC rule. Not a CDN or proxy in front of it — the cookie is scoped to the load balancer's own host. |
| Identity provider hostname | Open the API in a private browser window and read the host you land on. |
| A cheap probe path | Something behind the same listener rule that is quick and side-effect free. A health endpoint is ideal. |

**Use a read-only domain first.** Leave `allow_methods` at its default `["GET"]`
until the whole procedure passes. Do not point step 5 at an endpoint that
writes.

**On macOS, you cannot sandbox this with `XDG_STATE_HOME`.** albauth follows
the platform convention, so on macOS state goes to
`~/Library/Application Support/albauth/` regardless of what the XDG variables
say. Setting them and assuming the run is isolated will quietly write into your
real state directory. Use `--config` to point at a throwaway config, and expect
sessions to land in the real place — then `albauth auth logout <domain>` when
you are done.

Record what you find as you go — there is a results table at the end.

---

## 1. The config is valid

```bash
albauth config path
albauth config validate
```

**Passing:** `config <path> is valid: N domain(s) configured`.

If it fails, it lists *every* problem at once rather than stopping at the
first, so one editing pass should clear the file. Each line names the domain
and the key. [`configuration.md`](configuration.md) documents every rule.

A config to start from:

```toml
[[domain]]
name = "internal-api"
base_url = "https://api.example.com"
login_probe_path = "/healthz"
idp_hostnames = ["login.example.net"]

[settings]
log_level = "debug"
```

`log_level = "debug"` for the duration of this procedure — several steps below
read the logs. Turn it back down afterwards.

---

## 2. Starting state is logged out

```bash
albauth auth status
```

**Passing:** your domain is listed, `STATE` is `logged out`.

Note the `STORAGE` column. `keyring` means the OS keychain. `file` means no
keychain was reachable and albauth fell back — check stderr for the one-time
warning naming the reason, and see step 7.

If a session already exists from earlier experiments, clear it so this run
starts clean:

```bash
albauth auth logout internal-api --clear-browser-profile
```

---

## 3. The first login

```bash
albauth auth login internal-api
```

**What should happen:** a browser window opens at your API. You complete your
normal login — password, second factor, whatever your provider asks. The window
closes by itself.

**Passing:** `internal-api: authenticated, N cookie(s), expires <timestamp>`

Check `N`. A load balancer splits a large session across several cookies, so
two or three is normal and correct — what matters is that the count matches
what your browser holds. If you have ever seen a client handle only the first
chunk, this is the step that catches it.

**Failure modes worth distinguishing:**

- `no_browser` — no Chrome or Chromium found. Install one, or go to step 8.
- `login_timeout` — the flow did not finish within `login_timeout_seconds`
  (default 180). Either you needed longer, or the browser settled somewhere
  other than your API's host. Raise the timeout, or point `login_probe_path`
  at something that redirects cleanly back.
- `login_failed` — the flow finished but no cookie appeared. Usually
  `login_probe_path` is *not* behind the listener rule, so it returned 200
  without any login happening. This one is easy to misread as success.

---

## 4. The session is stored, and it is stored safely

```bash
albauth auth status
```

**Passing:** `STATE` is `authenticated` and `EXPIRES` is a plausible future
timestamp. If `EXPIRES` reads `unknown`, the cookies carried no expiry —
albauth will trust them until the load balancer says otherwise, which works
but means step 6 cannot be timed.

If `STORAGE` is `file`, check the permissions yourself. The path depends on
your platform — and the fallback warning on stderr names it explicitly, which
is the reliable way to find it:

| Platform | Session file |
|---|---|
| Linux | `$XDG_STATE_HOME/albauth/sessions.json`, else `~/.local/state/albauth/sessions.json` |
| macOS | `~/Library/Application Support/albauth/sessions.json` |
| Windows | `%LOCALAPPDATA%\albauth\sessions.json` |

```bash
# Set this once; later steps reuse it.
case "$(uname -s)" in
  Darwin) SESSIONS="$HOME/Library/Application Support/albauth/sessions.json" ;;
  *)      SESSIONS="${XDG_STATE_HOME:-$HOME/.local/state}/albauth/sessions.json" ;;
esac

ls -l "$SESSIONS"
```

**Passing:** mode `-rw-------` (0600). Anything wider and albauth will refuse
to read it on the next run with `storage_insecure` — which is the correct
behaviour, not a bug.

---

## 5. A real request, with no browser

```bash
albauth auth status     # confirm still authenticated
```

Then make the call the model would make. Over the protocol:

```bash
printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"http_request","arguments":{"url":"/healthz","domain":"internal-api"}}}' \
  | albauth serve 2>/tmp/albauth-stderr.log \
  | grep '"id":2'
```

**Passing:** a result whose text payload contains

```json
"status": 200,
"authenticated": true,
"relogin_performed": false
```

and **no browser window appeared**. That is the whole point of the tool: the
second and every later call is an ordinary HTTP request.

Time it. It should complete in the latency of your API plus a few
milliseconds. If it takes seconds, something is re-authenticating when it
should not be.

Run it two or three more times. Still no browser, still
`"relogin_performed": false`.

---

## 6. Re-authentication after the session is rejected

A real session may last days, so rather than waiting for it, invalidate the
stored one and watch albauth notice. This exercises the detection rules, the
re-login, and the retry — the path most likely to be subtly wrong.

Set `storage = "file"` in your config for this step, re-run step 3, then
corrupt the stored cookie:

```bash
# $SESSIONS was set in step 4.
cp "$SESSIONS" "$SESSIONS.bak"
python3 - "$SESSIONS" <<'PY'
import json, sys
path = sys.argv[1]
data = json.load(open(path))
for domain in data["domains"].values():
    domain["cookies"][0]["value"] += "x"   # still well-formed, no longer valid
json.dump(data, open(path, "w"), indent=2)
PY
```

Now repeat the request from step 5.

**Passing:** the request still returns `"status": 200`, and

```json
"relogin_performed": true
```

Because the browser profile is persistent, your identity provider usually still
recognises the browser: the window opens, the redirect chain completes in about
a second, and it closes without you touching it. That silent re-authentication
is what makes expiry a non-event in daily use. If your provider forces a full
login here, that is its policy, not a fault in albauth — note it and move on.

**If you get `auth_loop` instead:** albauth re-authenticated, retried once, and
was refused again. It stopped rather than looping, which is correct. The cause
is almost always that the listener rule covers your probe path but not the path
you are requesting. See [`troubleshooting.md`](troubleshooting.md#auth_loop).

Restore afterwards:

```bash
mv "$SESSIONS.bak" "$SESSIONS"
```

---

## 7. Nothing leaks

This is the step people skip, and the one that matters most. You are checking a
claim albauth makes about itself: **a cookie value never reaches stdout, stderr,
a log line, or a tool result.**

Get a known cookie value from your browser's developer tools — Application →
Cookies → your API host → any `AWSELBAuthSessionCookie*`. Copy a distinctive
40-character slice of it, then:

```bash
SECRET='<paste the slice here>'

grep -c "$SECRET" /tmp/albauth-stderr.log          # from step 5
albauth auth status            | grep -c "$SECRET"
albauth --log-level debug auth status 2>&1 | grep -c "$SECRET"
```

**Passing:** every count is `0`.

Then confirm redaction is actually happening rather than the value simply being
absent:

```bash
grep -c 'redacted:len=' /tmp/albauth-stderr.log
```

**Passing:** non-zero. Log lines that mention cookies render them as
`<redacted:len=1184>`. Seeing that marker is what proves the scrubbing ran, as
opposed to the log never having touched a cookie at all.

---

## 8. The headless path

Skip unless you need albauth somewhere with no browser — CI, a remote box, a
container.

On a machine that *does* have a browser, log in to the API, open developer
tools → Application → Cookies, and copy **every** cookie whose name starts with
your `cookie_name_prefix`. There is usually more than one and you need all of
them. Then, on the headless machine:

```bash
albauth auth import internal-api
```

It prints instructions and reads `NAME=VALUE` lines with terminal echo
disabled, so nothing lands on screen or in your shell history. A blank line
ends the input.

**Passing:** `internal-api: imported N cookie(s), assumed valid until <time>`,
and a request from step 5 then succeeds.

Imported cookies carry no readable expiry, so albauth assumes eight hours. That
is deliberately conservative: if the guess is wrong, step 6's detection catches
it on the next request.

**Also check the storage warning fires exactly once.** On a box with no keychain
and `storage = "auto"`, stderr should carry one line beginning
`albauth warn: OS keychain unavailable` — once per process, not once per
request.

---

## 9. The protocol channel is clean

albauth's stdout is the MCP transport. A single stray line of logging corrupts
it, and the symptom is a confusing client-side parse error rather than anything
that points at albauth.

```bash
printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"auth_status","arguments":{}}}' \
  | albauth --log-level debug serve 2>/dev/null \
  | python3 -c '
import json, sys
for n, line in enumerate(sys.stdin, 1):
    if not line.strip():
        continue
    try:
        envelope = json.loads(line)
    except json.JSONDecodeError as e:
        sys.exit(f"line {n} is not JSON: {e}\n{line!r}")
    if envelope.get("jsonrpc") != "2.0":
        sys.exit(f"line {n} is not a JSON-RPC message: {line!r}")
print("stdout is clean")
'
```

**Passing:** `stdout is clean`, with `--log-level debug` deliberately turned up
so that if logging were going to leak onto stdout, it would.

---

## 10. Through an actual MCP client

The steps above drive the protocol by hand. Finish by using it the way you
actually will.

```bash
claude mcp add albauth -- "$(command -v albauth)" serve
```

Then ask the model to list what it can reach, and to fetch something:

> Using albauth, list the domains you can reach, then GET /healthz from internal-api.

**Passing:** it calls `list_domains`, then `http_request`, and shows you the
API's response. No browser window, no prompt for credentials.

If you installed the agent skill (see the README), the model should also
volunteer sensible things — checking `list_domains` before guessing hostnames,
and reporting `method_not_allowed` as your decision rather than trying to work
around it.

---

## The build-tagged manual test

There is one automated test that drives the real browser flow. It is tagged out
of every normal run because it needs Chrome, a reachable load balancer and a
human at the keyboard:

```bash
ALBAUTH_MANUAL_BASE_URL=https://api.example.com \
ALBAUTH_MANUAL_PROBE_PATH=/healthz \
  go test -tags manual -v -timeout 5m ./test/manual/...
```

It opens a browser, waits for you to complete the login, and asserts that
cookies were captured with the expected prefix and a readable expiry. It logs
each cookie's name, length and expiry — never its value.

---

## Results

| # | Check | Result |
|---|---|---|
| 1 | Config validates | |
| 2 | Starts logged out; storage backend noted | |
| 3 | First login succeeds; cookie count noted | |
| 4 | Session stored; file mode 0600 if file-backed | |
| 5 | Request succeeds with no browser, `relogin_performed: false` | |
| 6 | Rejected session triggers one re-login, `relogin_performed: true` | |
| 7 | No cookie value in any output; redaction marker present | |
| 8 | Headless import works (if applicable) | |
| 9 | stdout carries only JSON-RPC | |
| 10 | Works through a real MCP client | |

Worth recording alongside: the storage backend in use, how many cookies your
load balancer issues, whether re-authentication was silent or forced a full
login, and the session lifetime your rule is configured with.

---

## If something fails

Every error carries a code, a message and a hint naming the next action.
[`troubleshooting.md`](troubleshooting.md) has a section per code.

To report a problem, include:

- `albauth version`
- `albauth config validate` output
- your config with `base_url`, `match` and `idp_hostnames` redacted
- stderr at `--log-level debug` — safe to paste, cookie values are already
  redacted
- the full error payload: code, message and hint

Do not paste a cookie value. If you believe one leaked, that is itself the bug
worth reporting, and step 7 is the evidence.
