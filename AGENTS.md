# AGENTS.md - trustctl repository entrypoint

This file is the repo-local entrypoint for agents that discover instructions by
looking for `AGENTS.md` at the workspace root. In this checkout, the canonical
product contract lives one directory up at `../AGENTS.md`; read it before touching
code. That parent contract defines the architecture invariants AN-1 through AN-8,
the sprint workflow, and the rule that those invariants beat local convenience.

The short version is: PostgreSQL RLS owns tenant isolation, events are the source
of truth, all crypto stays behind `internal/crypto`, signing stays in the isolated
signer process, every mutation is idempotent, every external effect uses the
outbox, worker pools are bounded, and key material is byte-backed, locked, and
zeroed.

Package-local rules live in leaf `AGENTS.md` files. The current high-risk leaves
are:

- `internal/crypto/AGENTS.md` - AN-3 crypto boundary and AN-8 key material rules.
- `internal/signing/AGENTS.md` - AN-4 isolated signer process rules.
- `internal/protocols/AGENTS.md` - untrusted protocol parser and served-protocol rules.
- `internal/query/AGENTS.md` - tenant/RBAC semantic-query scoping rules.

Legacy `CLAUDE.md` files may remain beside those leaves for older tooling. When an
`AGENTS.md` file and a legacy file disagree, prefer `AGENTS.md` and update the
legacy file in the same change.
