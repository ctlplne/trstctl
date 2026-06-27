# AGENTS.md - trustctl repository entrypoint

This file is the repo-local entrypoint for agents that discover instructions by
looking for `AGENTS.md` at the workspace root. Read it before touching code.
The parent `../AGENTS.md` still defines the architecture invariants AN-1 through
AN-8, the sprint workflow, and the rule that those invariants beat local
convenience. This repo-local file records the open-core revision for this target:
trstctl is open-core. The core platform is source-available and free; commercial
Enterprise and Provider tiers are gated by an offline, Ed25519-signed license.
The boundary is a top-level `ee/` directory fence plus the license: one repo,
one binary lineage, never a fork. Multi-tenancy (AN-1) remains core and free.

The short version is: PostgreSQL RLS owns tenant isolation, events are the source
of truth, all crypto stays behind `internal/crypto`, signing stays in the isolated
signer process, every mutation is idempotent, every external effect uses the
outbox, worker pools are bounded, and key material is byte-backed, locked, and
zeroed.

AN-9 - Editions boundary. Commercial code lives only under `ee/`. Core may never
import `ee/`, except from `cmd/trstctl/ee_attach.go`, which must carry
`//go:build !trstctl_core`. The `trstctl_core` build uses
`cmd/trstctl/ee_attach_core.go` and links zero `ee/` packages. Activation is
license-gated at the single attach seam, never through scattered tier checks.
The one feature-to-tier table lives in `internal/license`, which stays core so
offline licensing is auditable. FIPS is artifact-gated by `make fips-build`; do
not add a runtime license gate for FIPS.

Package-local rules live in leaf `AGENTS.md` files. The current high-risk leaves
are:

- `internal/crypto/AGENTS.md` - AN-3 crypto boundary and AN-8 key material rules.
- `internal/signing/AGENTS.md` - AN-4 isolated signer process rules.
- `internal/protocols/AGENTS.md` - untrusted protocol parser and served-protocol rules.
- `internal/query/AGENTS.md` - tenant/RBAC semantic-query scoping rules.

Legacy `CLAUDE.md` files may remain beside those leaves for older tooling. When an
`AGENTS.md` file and a legacy file disagree, prefer `AGENTS.md` and update the
legacy file in the same change.

Open-core hard do-nots: do not import `ee/` from core outside the tagged seam;
do not move multi-tenancy, the crypto boundary, audit/export rights, or the
license verifier into `ee/`; do not add Redis or another datastore; do not add a
runtime `lic.Has(fips)` gate.
