# Agent instructions

See [CLAUDE.md](CLAUDE.md) — it is the canonical guide for working on this
repository, and it applies to any agent, not only Claude.

The short version: run `./scripts/verify.sh` (the acceptance gate) and then
`./test/tools/sweep.sh` (albauth against real applications behind a real OIDC
proxy) before calling a change done. Unit tests cannot see the failures that
actually happen here.
