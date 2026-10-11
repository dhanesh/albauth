# Regenerating the demo

The GIF in the README is recorded from a live system, not staged. Reproducing
it means standing up the same one:

1. **A local load balancer with a real `authenticate-oidc` rule.** Follow
   [`../test/ministack/README.md`](../test/ministack/README.md) to start
   MiniStack and run `../test/ministack/setup.sh`.

2. **A demo environment with a session.** The recording uses its own config and
   state directory so it never touches yours:

   ```bash
   DEMO=/tmp/albauth-demo
   mkdir -p "$DEMO/config/albauth" "$DEMO/state"
   cat > "$DEMO/config/albauth/config.toml" <<'TOML'
   [[domain]]
   name = "local-alb"
   base_url = "http://albauth.alb.localhost:4566"
   idp_hostnames = ["localhost"]
   login_probe_path = "/v1/users"
   allow_methods = ["GET", "POST"]

   [settings]
   storage = "file"
   TOML
   go build -o "$DEMO/albauth" ./cmd/albauth
   ```

   Then authenticate it, either by completing the browser flow —

   ```bash
   XDG_CONFIG_HOME=$DEMO/config XDG_STATE_HOME=$DEMO/state \
     "$DEMO/albauth" auth login local-alb
   ```

   — or, for an unattended recording, by driving the login with curl and
   importing the cookies the load balancer mints. The sign-in form is at
   `/oauth2/authorize`; post the credentials from `setup.sh`'s fixture to
   `/login`, follow the callback, and pipe the resulting `Set-Cookie` values
   into `albauth auth import local-alb`.

3. **Record.**

   ```bash
   vhs demo/demo.tape        # writes docs/img/demo.gif
   ```

`mcp-call.sh` drives a single tool call over albauth's stdio transport. It is
here so the recording shows real protocol traffic rather than a mock-up of it;
it is not part of the shipped tool.

The login screenshot is captured with `chromedp` against the same emulator, at
a 660×470 viewport so the form fills the frame.

## The site recording

The terminal recording on [dhanesh.github.io/albauth](https://dhanesh.github.io/albauth/)
is an [asciinema](https://asciinema.org) cast, made in `cast/`. It runs against
the tool-sweep stack rather than the ALB emulator — Grafana behind oauth2-proxy,
dex and Traefik `forwardAuth` — to show that albauth is not AWS-only, and it uses
the released `albauth` on your `PATH` so the page shows what people install.

```bash
docker-compose -f test/tools/compose.yml up -d traefik grafana   # or `docker compose`
demo/cast/record.sh                                              # writes demo/cast/demo.cast
```

The only staged step is the sign-in: `cast/headless-login.sh` signs in to dex
with its static password, the same way `test/tools/sweep.sh` does, and imports
the cookie, standing in for the browser window `albauth auth login` would open.
Everything albauth writes goes to a throwaway `HOME`.

To update the site, convert the cast to asciicast v2 into the `gh-pages` branch
and push:

```bash
asciinema convert -f asciicast-v2 demo/cast/demo.cast <gh-pages checkout>/demo.cast
```
