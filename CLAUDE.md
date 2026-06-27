# CLAUDE.md - trstctl Open-Core Contract

Read `AGENTS.md` first. This legacy file exists for tooling that still looks for
`CLAUDE.md`; when the two disagree, `AGENTS.md` wins and this file should be
updated in the same change.

trstctl is open-core. The core platform is source-available and free; commercial
Enterprise and Provider tiers are gated by an offline, Ed25519-signed license.
The boundary is a top-level `ee/` directory fence plus the license: one repo,
one binary lineage, never a fork. Multi-tenancy (AN-1) is and remains core and
free.

AN-1 through AN-8 still apply exactly as written in `../AGENTS.md`: PostgreSQL
RLS tenant isolation, event-sourced state, the `internal/crypto` boundary, the
isolated signer process, mutation idempotency, outbox external effects,
bulkheads/backpressure, and byte-backed locked/zeroed key material.

AN-9 - Editions boundary. Commercial code lives only under `ee/`. Core may
never import `ee/`; `ee/` may import core. The only exception is
`cmd/trstctl/ee_attach.go`, which must carry `//go:build !trstctl_core`. The
core-only twin is `cmd/trstctl/ee_attach_core.go` under `//go:build
trstctl_core`, and the core-only build must link zero `ee/` packages.

License checks are centralized. The only `lic.Has(feature)` construction checks
belong in `attachEE`, one block per feature. Do not scatter tier checks through
handlers, stores, engines, or UI glue. The single feature-to-tier table lives in
`internal/license`, which stays core so no-phone-home licensing is auditable.

Repository map additions:

```text
ee/                  # commercial Enterprise/Provider implementations only
internal/license/    # core offline license verifier and feature table
cmd/trstctl-license/ # vendor-side signing/inspection helper
```

Hard do-nots: do not import `ee/` from core outside the tagged seam. Do not move
multi-tenancy, the crypto boundary, audit/export rights, or the license verifier
into `ee/`. Do not add a runtime license gate for FIPS; FIPS remains
artifact-gated by `make fips-build`.
