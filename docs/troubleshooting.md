# Troubleshooting

Every failure albauth reports carries a code, a message, and a hint:

```json
{
  "error": "login_timeout",
  "message": "browser flow for \"internal-api\" did not complete within 180s",
  "hint": "raise login_timeout_seconds for this domain"
}
```

This page is one section per code, in the order you are likely to meet them.

---

## `config_invalid`

**The config file did not parse or did not validate.**

Run `albauth config validate`. It lists every problem at once, so one editing
pass fixes the file. Each line names the domain and the key.

Common causes:

- A trailing slash on `base_url` — write `https://api.example.com`, not
  `https://api.example.com/`.
- `http` against a public host. Only `https` is allowed, except for `localhost`
  and loopback addresses.
- A `name` with capitals, spaces, or a leading punctuation character. It must
  match `^[a-z0-9][a-z0-9._-]*$`.
- Two domains claiming overlapping `match` patterns. Routing would be
  ambiguous, so albauth refuses to guess. Narrow one of the patterns.

If the config file is not being found at all, `albauth config path` prints where
it is looking.

---

## `unknown_domain`

**No configured domain claims that host, or no domain has that name.**

The hint lists every configured domain.

- Calling with an absolute URL? Its host must match one of a domain's `match`
  patterns. `match` defaults to just the host of `base_url`, so a request to
  `other.example.com` will not route to a domain whose `base_url` is
  `api.example.com` unless you add it.
- Calling with a `domain` argument? Check the spelling against
  `albauth list_domains` or `albauth auth status`.

---

## `domain_mismatch`

**You passed both an absolute `url` and a `domain`, and they disagree.**

The URL's host resolves to one configured domain, but a different one was named.
Drop the `domain` argument — an absolute URL routes on its own — or fix
whichever one is wrong.

---

## `method_not_allowed`

**The method is not in that domain's `allow_methods`.**

This is deliberate: `allow_methods` defaults to `["GET"]`, so a model cannot
write to a domain until you allow it. Nothing left the machine.

```toml
[[domain]]
name = "internal-api"
allow_methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
```

Allow only what that domain genuinely needs.

---

## `no_browser`

**No Chrome or Chromium binary was found.**

Two ways forward:

1. **Install one.** Chrome, Chromium, or any Chromium-based browser that ships
   the DevTools protocol.
2. **Import a cookie instead.** On a machine that does have a browser, log in to
   the API, open developer tools → Application → Cookies, and copy every cookie
   whose name starts with `AWSELBAuthSessionCookie` — there is usually more than
   one, and you need all of them. Then, here:

   ```bash
   albauth auth import internal-api
   ```

   Input is read with echo disabled, so the values do not reach your screen or
   your shell history. See
   [getting-started.md](getting-started.md#headless-machines).

---

## `login_timeout`

**The browser opened, but the flow did not finish in time.**

albauth waits `login_timeout_seconds` (default 180) for the redirect chain to
settle back on your API host with a session cookie in place.

- **You needed longer.** A hardware token or an approval on another device can
  take a while. Raise the timeout:

  ```toml
  login_timeout_seconds = 300
  ```

- **The flow finished somewhere unexpected.** albauth waits for the browser to
  land back on the host of `base_url`. If your provider ends on a different host
  — a landing page, a tenant selector — set `login_probe_path` to something that
  redirects cleanly back to the API host.

- **You did not notice the window.** It opens headed, on purpose, because only
  you can complete an identity-provider login. Check other desktops and spaces.

---

## `login_failed`

**The flow settled, but no cookie with the configured prefix appeared.**

The browser got back to your API host without the load balancer issuing a
session cookie. Usually one of:

- **`login_probe_path` is not behind the listener rule.** If the path you probe
  is unauthenticated, it returns 200 without a login ever happening. Point it at
  something the rule actually covers.
- **`cookie_name_prefix` is wrong.** The default is
  `AWSELBAuthSessionCookie`. Check the actual cookie name in developer tools.
- **The listener rule is scoped to a different path.** Confirm that the rule
  covers `login_probe_path` as well as the paths you intend to call.

---

## `auth_loop`

**Still unauthenticated after one re-login and one retry.**

albauth retries exactly once, on purpose. If a session it just acquired is
rejected too, the problem is not the cookie, and retrying would open browser
windows forever.

What to check:

- **Listener rule scope.** The rule may cover the path you probe for login but
  not the path you are requesting, so the session is valid for one and not the
  other. Line up `login_probe_path` with the paths you actually call.
- **A cookie set on the wrong host.** If your API is behind a CDN or a second
  proxy, the cookie may be scoped to a hostname you are not sending it to.
  `base_url` must be the hostname that terminates the OIDC rule.
- **The session really is being invalidated immediately.** Some identity
  provider configurations revoke on every new authorisation. `albauth auth login
  <domain> --force` followed by a manual `curl` with the cookie will tell you
  which side is dropping it.

The error message names the detection reason for both attempts, which narrows it
quickly: `redirect_to_idp` means the load balancer never accepted the session;
`status_401` means it reached the application, which rejected it.

---

## `storage_unavailable`

**`storage = "keyring"` but no OS keychain could be reached.**

Typically a headless Linux box with no Secret Service on the D-Bus session.

Either start a keyring daemon, or accept the file backend:

```toml
[settings]
storage = "file"
```

The file backend writes `0600` into your state directory. With
`storage = "auto"` this fallback happens on its own, with a single warning.

---

## `storage_insecure`

**The session file's permissions are wider than `0600`.**

albauth refuses to read a session file that other users on the machine can read,
rather than quietly loading credentials out of it.

```bash
chmod 600 ~/.local/state/albauth/sessions.json
```

The exact path is in the error message. If you do not know how the permissions
were widened — an editor, a backup tool, a careless `chmod -R` — treat the
session as compromised: `albauth auth logout <domain>` and log in again.

---

## `upstream_timeout`

**The request exceeded `timeout_seconds` (default 30).**

Authentication is fine; the API itself is slow.

```toml
[[domain]]
timeout_seconds = 120
```

Note this is separate from `login_timeout_seconds`, which bounds the browser
flow.

---

## `upstream_error`

**The request could not be made at all.**

DNS failure, connection refused, TLS failure, or a network the machine cannot
reach. Check with `curl -v` from the same machine — if `curl` cannot reach it,
albauth will not either.

---

## `invalid_request`

**A tool argument was missing or the wrong type.**

- `url` is required.
- A relative `url` needs a `domain`.
- `query` and `headers` must be objects whose values are all strings. A number
  needs quoting: `{"page": "2"}`, not `{"page": 2}`.

---

## Things that are not errors

**A non-2xx status.** A 404, a 422 or a 500 comes back as a normal result with
its status and body, so the model can read the API's own error message. Only
transport, authentication and configuration failures are tool errors. That
includes an HTML error page answering a JSON request — an application's 404 or
500, a gateway's 502 or 503: it is returned once, unretried, with
`relogin_performed: false`. Only an HTML `401` or `403` reads as the proxy's
sign-in page.

**A same-host redirect.** A 302 from `/v1/users` to `/v2/users` is a legitimate
application redirect and does not trigger a login. Only a redirect to a
configured identity provider host, to `/oauth2/idpresponse`, or to a *different*
host is treated as an expired session.

---

## Diagnostics

**Turn up the logging.** Everything goes to stderr, so it will not disturb the
protocol stream:

```bash
albauth --log-level debug auth status
```

For an MCP client, add it to the args:

```json
{ "command": "/path/to/albauth", "args": ["serve", "--log-level", "debug"] }
```

**Check state without a client:**

```bash
albauth config validate     # is the config sound?
albauth config path         # which file is being read?
albauth auth status         # what sessions exist, and where are they stored?
```

**Start clean.** This deletes the stored session *and* the persistent browser
profile, forcing a full identity-provider login next time:

```bash
albauth auth logout internal-api --clear-browser-profile
albauth auth login internal-api
```

**Cookie values are never printed.** If you are looking for one in the logs to
debug, you will not find it — every log line is scrubbed and rendered as
`<redacted:len=N>`. That is deliberate, and there is a test asserting it. Read
the cookie out of the browser's developer tools instead.

---

## Reporting a problem

Include:

- `albauth version`
- `albauth config validate` output
- The config file **with `base_url`, `match` and `idp_hostnames` redacted**
- stderr at `--log-level debug` (safe to paste: cookie values are already
  redacted)
- The full error payload — code, message and hint
