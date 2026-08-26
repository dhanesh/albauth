# Working on albauth

Read this before changing anything. It is short, and it exists because the
mistakes it prevents have all been made here at least once.

## What albauth is

A tool for calling HTTP APIs that sit behind a login — an AWS ALB
`authenticate-oidc` rule, oauth2-proxy, Traefik `forwardAuth` — where a normal
request gets a redirect to an identity provider instead of an answer. It logs
in once with a browser, keeps the session, and reuses it.

Two things follow from that, and both are easy to break:

- **It is not AWS-only.** The ALB is the best-known case, not the only one.
  A change that assumes an ALB — its cookie names, its redirect behaviour, its
  401s — breaks every other proxy silently.
- **There are two layers.** Getting past the proxy is not the same as being
  allowed in. The application behind it usually wants its own credential, which
  is what `[domain.headers]` is for. A 401 after a successful login is normally
  the *application* refusing you, not a broken session.

## The rule: run the tool sweep before you call a change done

```bash
./test/tools/sweep.sh          # ~1 min, headless, no AWS account needed
```

**Any change to request handling, session detection, cookie handling, or the
config probe must pass the sweep.** Not because the unit tests are weak — they
hold at 100% coverage — but because they cannot see the thing that actually
breaks.

Every regression this project has had came from a real application rather than
from a test: an HTML page judged an expired session, a binary body corrupted by
a string conversion, a bare 401 that spawned a browser instead of reporting a
refusal, a CSRF token that needed its session cookie back, a session cookie
under a name albauth was not watching for. Each of those passed every unit test
at the time it shipped.

`test/tools/README.md` explains what the sweep stands up and how to add a case.
Add one whenever you fix a bug a real application found — that is how the sweep
gets better at its job.

## The order of checks

1. `./scripts/verify.sh` — the acceptance gate. Build, unit tests, 100%
   coverage per package, e2e, docs. This is the only authority on "done".
2. `./test/tools/sweep.sh` — the reality check, against real applications.

Both, in that order. A green `verify.sh` with a red sweep is not done.

## Things that are deliberate, not accidental

- **stdout carries JSON-RPC and nothing else.** Every log goes to stderr. A
  stray `fmt.Println` corrupts the MCP stream and the client simply dies.
- **`treat_401_as_expired` is off by default.** A 401 is usually the
  application refusing a token. Turning it on globally means a wrong API key
  opens a browser window.
- **Writes are opt-in per domain** via `allow_methods`. It fails closed.
- **The HTTP client does not follow redirects.** The detection rules depend on
  seeing the 302 itself.
- **`serve` starts even with no config at all.** Someone who has just installed
  albauth has no domains yet; if the server exits, their client reports a dead
  server and the agent has no tools left to help them set one up.

## When you change behaviour a user can see

Update, in the same change: `docs/`, `skill/albauth/SKILL.md` (the agent-facing
instructions), and `spec.md` if the rule itself moved. `verify.sh` fails if the
skill stops covering a tool, a response field, or the onboarding path.
