# trstctl EE Fence

Commercial trstctl code lives under `ee/`.

Boundary rules:

- Core must not import `trstctl.com/trstctl/ee`, except from the two tagged attach seams:
  `cmd/trstctl/ee_attach.go` and `cmd/trstctl-signer/ee_attach.go`.
- Each seam must carry `//go:build !trstctl_core` and pair with a `*_core.go` twin under
  `//go:build trstctl_core`; the `licenseboundary` linter allowlists exactly these two.
- The `trstctl_core` build uses the `*_core.go` twins and links zero `ee/` packages.

Multi-tenancy, the event spine, the crypto boundary, audit/export rights, and the license verifier stay in core.

## What left this tree on 2026-09-20

The patent-pending families and PQC ship in the core under the Business Source License 1.1
and attach in every build through the untagged `cmd/trstctl/attach_families.go`,
`cmd/trstctl-signer/attach_families.go` and `cmd/trstctl-agent/cosign_attach.go`:

- PCAS: `internal/succession`, `internal/translog`, `internal/rpverify`, and
  `internal/pqcmigration` (which cites the PCAS mechanisms). Proof-Carrying Algorithm
  Succession is a patent-pending feature set: certctl LLC filed a US
  provisional application covering it in July 2026 and nothing has issued.
- AGID: `internal/agentid`.
- XREC: `internal/reconcile`.
- VDEC: `internal/decommission`.
- PQC: `internal/pqc` (the only package that imports the CIRCL PQC library),
  `internal/pqcruntime`, and `internal/kmip` (XREC depends on it; the tagged BYOK seam
  still decides when the KMIP listener runs).
- `internal/proptest`: the deterministic pseudo-random source their property tests draw from.

`ee/docs/` still holds the PCAS security docs (key custody, threat model, ceremony and
break-glass runbooks) and the generated claim-traceability page until they move with the
next documentation pass.

## Packages (`ls ee/`)

- `ee/clusterfuzz`: isolated test-only bridge packages that let the stock
  ClusterFuzzLite Go helper compile external-package Enterprise fuzz targets
  without weakening the AN-9 core-to-EE import fence.
- `ee/federation`: cross-cluster DR import worker. Core keeps the checkpoint
  store interface and leader election; the tagged attach seam supplies the
  worker factory only when `FeatureHASupport` is licensed.
- `ee/managedkeys`: BYOK/HSM managed-key lifecycle. Core keeps only the API and
  server interfaces; the tagged attach seam supplies the implementation only
  when `FeatureBYOK` is licensed.
- `ee/governance`: Enterprise compliance evidence packs and governance-policy
  source. Core keeps audit export, privacy redaction/retention, OPA policy, and
  the server/API seams; the tagged attach seam supplies reports and policy
  overrides only when `FeatureGovernance` is licensed.
- `ee/provider`: Provider/MSP plane. Core keeps licensing and the HTTP handler
  seam; the tagged attach seam supplies tenant lifecycle, provider audit, tenant
  band enforcement, and consented break-glass only when `FeatureProviderPlane` is
  licensed.
- `ee/billing`: Provider metering, quota checks, and CSV/JSONL export. Core keeps
  only the inert `internal/usage` seam; the tagged attach seam installs the
  recorder and quota checker only when `FeatureMetering` is licensed.
- `ee/whitelabel`: Provider white-label branding. Core keeps only the
  `internal/branding` resolver seam; the tagged attach seam installs per-tenant
  design tokens, product name, custom-domain login mapping, and email branding
  only when `FeatureWhiteLabel` is licensed.
- `ee/silo`: Provider siloed isolation. Core keeps only the `internal/tenancy`
  router vocabulary and pooled RLS substrate; the tagged attach seam installs
  schema/subject/object-prefix routing only when `FeatureSiloedIsolation` is
  licensed.

Remediation is part of Core. The production server mounts incident and
remediation routes without a license; RBAC (`incidents:*` plus `certs:issue`
for replacement issuance), tenant isolation, policy and idempotency still apply.
The standalone credential-compromise workflow library lives in `internal/incident`;
the served workflows use the durable Core API and outbox implementations.
