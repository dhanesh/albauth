# Testing against a real Application Load Balancer, locally

The suite in this directory is the only one that exercises `internal/browser` —
albmcp's Chrome DevTools Protocol driver. Every other test replaces it with a
stub, because it needs a running browser and a load balancer that actually
performs an OIDC handshake.

Nothing here is mocked except the cloud itself:

- a real Chrome, driven by albmcp's own code
- a real redirect to an identity provider
- a real HTML login form, filled in by the test standing in for a human
- a real back-channel authorization-code exchange
- a real `AWSELBAuthSessionCookie`, minted by the load balancer

## What you need

**A container runtime.** [colima](https://github.com/abiosoft/colima) works well
on macOS:

```bash
brew install colima
colima start --cpu 4 --memory 6
```

**MiniStack with the `authenticate-oidc` action.** Upstream
[MiniStack](https://github.com/ministackorg/ministack) emulates ALB's control
plane and data plane, but its listener rules support only `forward`, `redirect`
and `fixed-response`. It parses an `authenticate-oidc` action's type and then
discards the configuration, so an ALB built on it forwards every request
unauthenticated — a test against it would pass while proving nothing.

The action is implemented in a branch:

```bash
git clone https://github.com/ministackorg/ministack.git
cd ministack && git checkout feat/alb-authenticate-oidc

docker run -d --name ministack -p 4566:4566 \
  -e GATEWAY_PORT=4566 -e LOG_LEVEL=INFO -e S3_PERSIST=0 \
  -v "$PWD/ministack:/opt/ministack/ministack:ro" \
  ministackorg/ministack:latest
```

Mounting the source over the published image means edits take effect on
`docker restart ministack`, with no rebuild.

**Chrome or Chromium**, for the browser to drive.

## Running it

```bash
./test/ministack/setup.sh            # provisions Cognito, a Lambda target and the ALB
go test -tags ministack -v -timeout 5m ./test/ministack/...
```

`setup.sh` writes `fixture.json` describing what it built, and refuses to finish
unless an unauthenticated request actually redirects — so a MiniStack without
the patch fails loudly at setup rather than silently passing the tests.

The tests skip, rather than fail, when `fixture.json` is absent. Point them
elsewhere with `ALBMCP_MINISTACK_FIXTURE=/path/to/fixture.json`.

MiniStack keeps its state in memory, so re-run `setup.sh` after restarting it.

## What the tests establish

`TestBrowserLoginCapturesARealALBSession` — a human completes the provider
login once, then albmcp's own driver takes over the same browser profile,
captures the session, and that session authenticates a real API call. The
target reports back the `X-Amzn-Oidc-*` headers, which the load balancer only
attaches to a request it has authenticated — so the request demonstrably went
*through* the auth layer rather than around it.

`TestUnauthenticatedRequestIsDetectedAgainstARealALB` — the expiry detection
rules run against a genuine load balancer redirect. A missing session must
surface as a coded error, never as the identity provider's login page returned
to the model as though it were data.

## Two things this cannot prove

**Silent re-authentication.** albmcp reuses a persistent browser profile so
that, once the identity provider's own SSO session exists, re-authentication
completes without interaction. MiniStack's Cognito sets no browser session
cookie, so it shows the login form every time and there is no SSO to inherit.
The mechanism is exercised — the profile is reused and the load balancer
session is found in it — but the provider-side half is not.

**A real provider's redirect chain.** Tenant selectors, consent screens, device
trust and MFA all add hops that this Cognito does not. If albmcp's poller is
going to be confused by a provider, it will be by one of those. Run
`test/manual` against your own load balancer to cover that.
