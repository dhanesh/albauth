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
