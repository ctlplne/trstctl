<!-- SPDX-License-Identifier: LicenseRef-trstctl-EE -->

# AGENTS.md - ee/decommission/intwire

This package owns VDEC's real-substrate integration harness. Tests here must use
real PostgreSQL/RLS, embedded file-backed NATS/JetStream, and the real
`cmd/trstctl-signer` process over UDS.

- Keep all files proprietary EE (`LicenseRef-trstctl-EE`).
- Build tests with `//go:build integration`.
- Do not replace the signer-side destruction gate, signer-side key destroy, or
  signer-side artifact path with in-process doubles on the delivered path.
- The harness may assemble public VDEC evidence, enqueue outbox work, and rebuild
  read models, but it must not add product logic.
