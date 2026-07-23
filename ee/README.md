# trstctl EE Fence

Commercial trstctl code lives under `ee/`.

Boundary rules:

- Core must not import `trstctl.com/trstctl/ee`, except from the three tagged attach seams:
  `cmd/trstctl/ee_attach.go`, `cmd/trstctl-signer/ee_attach.go`, and
  `cmd/trstctl-agent/cosign_attach.go`.
- Each seam must carry `//go:build !trstctl_core` and pair with a `*_core.go` twin under
  `//go:build trstctl_core`; the `licenseboundary` linter allowlists exactly these three.
- The `trstctl_core` build uses the `*_core.go` twins and links zero `ee/` packages.

Multi-tenancy, the event spine, the crypto boundary, audit/export rights, and the license verifier stay in core.

## Packages (`ls ee/`)

- `ee/incident`: credential-compromise workflow library.
- `ee/fleet`: staged, health-checked fleet re-issuance library.
- `ee/pqcmigration`: PQC migration library that reuses the fleet progress seam.
- `ee/federation`: cross-cluster DR import worker. Core keeps the checkpoint
  store interface and leader election; the tagged attach seam supplies the
  worker factory only when `FeatureHASupport` is licensed.
- `ee/managedkeys`: BYOK/HSM managed-key lifecycle. Core keeps only the API and
  server interfaces; the tagged attach seam supplies the implementation only
  when `FeatureBYOK` is licensed.
- `ee/kmip`: raw KMIP mTLS runtime and bounded parser. Core keeps only the KMIP
  listener lifecycle interface; the tagged attach seam supplies the runtime only
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
- `ee/pqc`: post-quantum and hybrid signatures plus ML-KEM key encapsulation
  behind the AN-3 crypto boundary — the only package that imports the CIRCL PQC
  library, so callers link it only when they use this package.
- `ee/pqcruntime`: the complete PQC issuance object graph attached by the one
  AN-9 seam — licensed leaf signer, hybrid CSR inspection/parsing, and
  multi-key SPIFFE SVID issuance.
- `ee/succession`: Proof-Carrying Algorithm Succession (PCAS), a patented
  feature set — the append-only, per-identity cryptographic-succession
  lifecycle and posture projection.
- `ee/translog`: the PCAS transparency log — signed tree heads and Merkle
  inclusion/consistency proofs.
- `ee/rpverify`: the offline relying-party verifier for PCAS succession
  chains; kept proprietary so no MPL patent grant attaches to it.
- `ee/reconcile`: the proprietary drift-reconciliation runtime (internal
  codename XREC) assembled behind the tagged attach seam — whole-estate
  canonicalization, quarantine, and witness countersignatures.
- `ee/decommission`: the proprietary attested-destroy control-plane runtime
  (internal codename VDEC) — quorum destroy ceremonies, key re-protection, and
  dependency-state tracking.
- `ee/agentid`: agent (AGID) delegation-chain identity — authority-scoped
  delegation records, task-envelope binding, reachability verification, and
  cascade revocation.

`ee/docs/` holds the PCAS security docs (key custody, threat model, and HSM
ceremony/break-glass runbooks) behind the same AN-9 fence — reference material,
not Go code.

The served trstctl remediation surface (`ee/incident`, `ee/fleet`,
`ee/pqcmigration`) is not probectl-style advisory remediation: it executes
replacement issue/deploy/revoke work on a human trigger. The tagged attach seam
mounts it only when `FeatureRemediation` is licensed, and the API still
requires RBAC (`incidents:*` plus `certs:issue` for replacement issuance).
