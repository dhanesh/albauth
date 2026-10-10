# domain-setup: Adding a domain from the command line

- id: domain-setup
- proven: no
- anchors: internal/cli/addomain.go

## What it is

`albauth config add-domain <name> --base-url <url>` probes the URL and fills in
what a user cannot guess: the identity provider host, and for oauth2-proxy the
login path, the cookie family, `treat_401_as_expired` and the session check
path `/oauth2/auth`.

## How to reach it

- `albauth config add-domain`.

## Drive it

```sh
$H fixture --instance "$INSTANCE" o2-api expire
$H cli --instance "$INSTANCE" -- config add-domain o2-probe --base-url <o2-api URL from launch> > .verify-run/$INSTANCE/add.json
cat .verify-run/$INSTANCE/config.toml > .verify-run/$INSTANCE/config-after.toml
```

Exit code 0; `add.json` has `"exit": 0` and its stderr says
`login starts at /oauth2/start`. Expected: the new `o2-probe` block in
`config-after.toml` carries `cookie_name_prefix = "_oauth2_proxy"`,
`treat_401_as_expired = true` and `session_check_path = "/oauth2/auth"`.

## Proof

The config file written by the probe (the side effect).

## Gotchas

- `session_check_path` appears only once that requirement lands.
