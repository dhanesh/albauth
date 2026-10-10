# domain-setup: Adding a domain from the command line

- id: domain-setup
- proven: 301064edf87ab2502be9fa7b6137764c03b544ba
- anchors: internal/cli/addomain.go

## What it is

`albauth config add-domain <name> --base-url <url>` probes the URL and fills in
what a user cannot guess: the identity provider host, and for oauth2-proxy the
login path, the cookie family, `treat_401_as_expired` and the session check
path `/oauth2/auth`.

## How to reach it

- `albauth config add-domain`.

## Drive it

`launch` already configures `o2-api` on the oauth2 fixture host, and two domains
may not route one host, so remove it first:

```sh
H cli --instance "$INSTANCE" -- config remove-domain o2-api > .verify-run/$INSTANCE/remove.json
cp .verify-run/$INSTANCE/config.toml .verify-run/$INSTANCE/config-before.toml
H cli --instance "$INSTANCE" -- config add-domain o2-probe --base-url {host:o2-api} > .verify-run/$INSTANCE/add.json
cp .verify-run/$INSTANCE/config.toml .verify-run/$INSTANCE/config-after.toml
H cli --instance "$INSTANCE" -- config validate > .verify-run/$INSTANCE/validate.json
```

Exit code 0 for each; `add.json` and `validate.json` have `"exit": 0`, and
`add.json`'s stderr says `login starts at /oauth2/start`. Expected: the new
`o2-probe` block in `config-after.toml` carries `login_probe_path = "/oauth2/start"`,
`cookie_name_prefix = "_oauth2_proxy"`, `idp_hostnames = ["localhost"]`,
`treat_401_as_expired = true` and `session_check_path = "/oauth2/auth"`.
`scripts/prove.py domain-setup` runs the same check in one command.

## Proof

The config file written by the probe (the side effect).

## Gotchas

- `session_check_path = "/oauth2/auth"` is written only for a proxy found by
  the 401 follow-up at `/oauth2/start` or `/oauth2/sign_in`; an ALB-style
  redirect gets none, and an explicit `--session-check-path` wins.
- `ambiguous routing: match pattern … overlaps …` means `o2-api` was not removed:
  that is the overlap check working, not a probe failure.
