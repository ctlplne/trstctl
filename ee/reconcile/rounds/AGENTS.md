# AGENTS.md — ee/reconcile/rounds

This package implements XREC anti-entropy rounds and deterministic drift
projections: durable round initiation, watermark monotonicity/liveness decisions,
agreement records, staleness signals, and replay-derived witness/completion
metrics. Do not add witness generation, quarantine, remediation, or verifier
logic here; those belong to their own XREC packages/cards.

All source files in this package are proprietary EE code and must carry
`SPDX-License-Identifier: LicenseRef-trstctl-EE`.

Core interaction stays through feature-neutral seams only: event appenders,
background workers, digest sources, the generic `projections.EventProjection`
registration hook, and the tagged `attachEE` license block. Do not add
XREC-specific types to MPL core packages.
