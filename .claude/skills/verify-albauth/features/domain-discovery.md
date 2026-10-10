# domain-discovery: Spotting a domain that needs albauth

- id: domain-discovery
- proven: e0fe861eb551f560c26d70606cdbfce6db70c061
- anchors: internal/mcpserver

## What it is

A non-technical user asks the agent to call an API albauth has not been told
about. albauth notices the login wall, says so with a ready suggestion, and —
after the user agrees in chat — the agent adds the domain with the
`add_domain` tool, read-only (GET), usable at once without a restart.

## How to reach it

- MCP tool `http_request` with an absolute URL on an unconfigured host.
- MCP tool `add_domain`.

## Drive it

```sh
H call --instance "$INSTANCE" \
  'http_request={"url":"{host:unconfigured}/json"}' \
  'add_domain={"name":"found-api","base_url":"{host:unconfigured}"}' \
  'list_domains={}' \
  'add_domain={"name":"bad-api","base_url":"{host:unconfigured}","allow_methods":["POST"]}' \
  'http_request={"url":"{host:unconfigured}/json"}' > .verify-run/$INSTANCE/discover.json
cat .verify-run/$INSTANCE/config.toml > .verify-run/$INSTANCE/config-after.toml
```

Exit code 0. Expected in `discover.json`: call 1 is `isError: true`,
`error: unknown_domain`, with a `suggestion` naming the base URL and the
detected identity provider; call 2 succeeds; call 3 lists `found-api` with
`allow_methods` `["GET"]`; call 4 is refused (`isError: true`); call 5, the
retried request, logs in and returns `status` 200. The config file gains
`found-api` and not `bad-api`.

## Proof

The suggestion, the config file change, the domain listed in the same server
process, and a 200 from it after login — no restart.

## Gotchas

- The unknown_domain probe is exactly one bare GET; a forward-auth proxy's login
  route is only looked for by `add_domain`, after the user's yes.
- After the yes the flow is two calls: `add_domain`, then the retried request.
