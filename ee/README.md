# trstctl EE Fence

Commercial trstctl code lives under `ee/`.

Boundary rules:

- Core must not import `trstctl.com/trstctl/ee`, except from `cmd/trstctl/ee_attach.go`.
- `cmd/trstctl/ee_attach.go` must carry `//go:build !trstctl_core`.
- The `trstctl_core` build uses `cmd/trstctl/ee_attach_core.go` and links zero `ee/` packages.

Multi-tenancy, the event spine, the crypto boundary, audit/export rights, and the license verifier stay in core.

Enterprise remediation lives here:

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

The served trstctl remediation surface is not probectl-style advisory remediation:
it executes replacement issue/deploy/revoke work on a human trigger. The tagged
attach seam mounts it only when `FeatureRemediation` is licensed, and the API
still requires RBAC (`incidents:*` plus `certs:issue` for replacement issuance).
