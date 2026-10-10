# log-redaction: Session values never reach the logs

- id: log-redaction
- proven: 301064edf87ab2502be9fa7b6137764c03b544ba
- anchors: internal/logx

## What it is

Whatever albauth writes to stderr, a session cookie value is never in it — for
every proxy's cookie family, not only the ALB's.

## How to reach it

- Any command with `log_level = "debug"` (the harness config sets it).

## Drive it

```sh
H call --instance "$INSTANCE" 'http_request={"url":"{host:o2-api}/rotate"}' 'http_request={"url":"{host:o2-api}/json"}' > .verify-run/$INSTANCE/o2.json
H session --instance "$INSTANCE" o2-api > .verify-run/$INSTANCE/session.json
```

Exit code 0. Expected: `o2.json`'s `stderr_tail` contains no 64-character
session value; the Go test named in the plan prints a `_oauth2_proxy=<value>`
line through the logger and finds `<redacted:len=` instead.

## Proof

stderr captured from the real binary, checked for the stored value.

## Gotchas

- Values are long random strings; check by the stored session's length and
  sha256, never by printing them.
