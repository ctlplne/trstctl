# AGENTS.md - ee/succession

Proprietary Enterprise/Provider package implementing Proof-Carrying Algorithm
Succession (PCAS). This is a **patented feature set**; the whole package is
`ee/` and every source file carries `SPDX-License-Identifier: LicenseRef-trstctl-EE`.
MPL core must never import this package outside the tagged attach seam
(`AGENTS.md` AN-9). `make editions-gate` proves it.

Package-local rules:

- **Edition fence.** Do not import this package from MPL core. Core touches PCAS
  only through feature-neutral seams wired at `cmd/trstctl/ee_attach.go` /
  `cmd/trstctl-signer/ee_attach.go` (`//go:build !trstctl_core`).
- **AN-2 (events are truth).** Posture is a *projection* folded from events; it is
  never written directly. `Fold`/`Replay` must stay deterministic and idempotent
  under at-least-once/duplicate delivery (INV-4) — advance only on a strictly
  greater algorithm-epoch, and keep every state write idempotent.
- **Versioned events.** Every ledger event type has an explicit `SchemaVersion`.
  Bump the version when a payload shape changes; decoding treats an unknown type
  or a newer-than-known version as a skip (`Unknown`) so replay never panics or
  mis-projects. A malformed known-version payload is a fail-closed error.
- **No crypto here.** PCAS-01 defines only the event vocabulary and posture fold.
  The dual-signed succession *record*, its canonical commitment, and all
  cryptography live in PCAS-04 (routed through the `internal/crypto` AN-3
  boundary), never in this file set.
