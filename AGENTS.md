# AGENTS.md - trstctl repository entrypoint

This file is the repo-local entrypoint for agents that discover instructions by
looking for `AGENTS.md` at the workspace root. Read it before touching code.
Legacy `CLAUDE.md` files exist for tools that still look for that filename; when
an `AGENTS.md` file and a legacy file disagree, `AGENTS.md` wins and the legacy
file should be updated in the same change.

The parent `../AGENTS.md` still defines the architecture invariants AN-1 through
AN-9, the sprint workflow, and the rule that those invariants beat local
convenience. This repo-local file records the open-core revision for this target:
trstctl core is MPL-2.0 open-source software. Commercial Enterprise and Provider
tiers are proprietary material under `ee/` and are gated by an offline,
Ed25519-signed license. The boundary is a top-level `ee/` directory fence plus
the license: one repo, one binary lineage, never a fork. Multi-tenancy (AN-1),
the crypto boundary (AN-3), audit/export rights, and the offline license
verifier are and remain MPL core, free, and auditable.

AN-1 through AN-8 still apply exactly as written in `../AGENTS.md`. The short
version is: PostgreSQL RLS owns tenant isolation, events are the source of truth,
all crypto stays behind `internal/crypto`, signing stays in the isolated signer
process, every mutation is idempotent, every external effect uses the outbox,
worker pools are bounded, and key material is byte-backed, locked, and zeroed.

AN-9 - Editions boundary. Commercial code lives only under `ee/`. Core may never
import `ee/`; `ee/` may import core. The only exceptions are the tagged attach
seams: `cmd/trstctl/ee_attach.go`, `cmd/trstctl-signer/ee_attach.go`, and
`cmd/trstctl-agent/cosign_attach.go` (the agent's workload co-sign seam,
INT-16), each carrying `//go:build !trstctl_core` and paired with a `*_core.go`
twin under `//go:build trstctl_core`. The `licenseboundary` linter allowlists
exactly these three. The core-only build must link zero `ee/` packages.
Activation is license-gated at those attach seams, never through scattered tier
checks.
The only `lic.Has(feature)` construction checks belong in `attachEE`, one block
per feature. Do not scatter tier checks through handlers, stores, engines, or UI
glue. The one feature-to-tier table lives in `internal/license`, which stays core
so no-phone-home licensing is auditable. FIPS is artifact-gated by `make
fips-build`; do not add a runtime license gate for FIPS.

PQC boundary: all post-quantum cryptography and PQC-related features live under
`ee/` by default, including ML-KEM, ML-DSA, SLH-DSA, hybrid algorithms, PQC key
and certificate types, PQC issuance/signing paths, PQC APIs/UI, and PQC tests.
Future patented features also start under `ee/`; do not scaffold or stub them in
MPL core.

Repository map additions:

```text
ee/                  # proprietary Enterprise/Provider implementations only
internal/license/    # core offline license verifier and feature table
cmd/trstctl-license/ # vendor-side signing/inspection helper
```

Note the enforcement asymmetry from `../AGENTS.md` §3: AN-4, AN-6, and AN-7
have no linter analyzer and rely on dependency-closure and integration tests —
changes there lean on test discipline, not static checks.

Package-local rules live in leaf `AGENTS.md` files. The current high-risk leaves
are:

- `internal/crypto/AGENTS.md` - AN-3 crypto boundary and AN-8 key material rules.
- `internal/signing/AGENTS.md` - AN-4 isolated signer process rules.
- `internal/protocols/AGENTS.md` - untrusted protocol parser and served-protocol rules.
- `internal/query/AGENTS.md` - tenant/RBAC semantic-query scoping rules.
- `web/AGENTS.md` - the console's engineering contract (spaces IA, query/form
  layers, typography primitives, i18n review ratchet, test surfaces).

PCAS (Proof-Carrying Algorithm Succession) security docs live under `ee/docs/` (EE-licensed material behind the AN-9 fence):

- `ee/docs/pcas-key-custody.md` - claims 16 & 26 key custody (locked/zeroized
  buffers; HSM/module boundary).
- `ee/docs/pcas-threat-model.md` - PCAS assets, trust boundaries, adversaries,
  threat/mitigation map, and accepted residual risk (INT-22).
- `ee/docs/pcas-ceremony.md` - HSM key-ceremony and break-glass/emergency
  succession runbooks (claims 26, 17, 37).

Legacy `CLAUDE.md` files may remain beside those leaves for older tooling.

Open-core hard do-nots: do not import `ee/` from core outside the tagged seam;
do not put PQC, license-gated, or future patented logic in MPL core; do not move
multi-tenancy, the crypto boundary, audit/export rights, or the license verifier
into `ee/`; do not add Redis or another datastore; do not add a runtime
`lic.Has(fips)` gate.

Documentation style: every reader-facing page gives three layers in order —
what/why in two or three plain sentences, then the mechanism, then the exact
contract (flags, defaults, limits, failure modes). Roughly one bold per 150
words (UI labels, identifiers, true warnings). Served-vs-library status stated
once per page. No sprint/REPORT/DoD process IDs on reader pages unless a test
requires them. Many docs/*_test.go guards grep exact phrases — grep before
rewording, and never split a guarded phrase across a line wrap.
