# Category leadership ledger

This page is the REPORT-004 control. It explains how trstctl treats the
Category-Leadership score after the COMPETE remediation work. The score is a
served-proof ledger, not marketing copy: a capability earns credit only when the
running product, docs, tests, and operator surfaces prove it. A roadmap item, a
library-only path, or a human product decision stays outside the served
Category-Leadership numerator.

## Current source gaps

| Source | Category capability | Status | Served proof |
|--------|---------------------|--------|--------------|
| COMPETE-001 | CAP-K8S-03 Ingress + Gateway API auto-issuance | Served proof recorded | `docs/features/discovery-and-inventory.md` describes the Kubernetes Ingress and Gateway API TLS auto-issuance source, metadata-only guard, findings, minted public certificate inventory rows, and UI readback. |
| COMPETE-021 | CAP-ISS-04 ACME External Account Binding | Served proof recorded | `docs/features/acme-and-dns.md` documents ACME External Account Binding, and `docs/configuration.md` documents the `TRSTCTL_PROTOCOLS_ACME_EAB_*` runtime controls that make the server require and verify EAB. |
| COMPETE-012 | CAP-SCALE-01 High-volume orchestration | Served proof recorded | `docs/performance.md` documents the served `GET /api/v1/scale/orchestration` and `trstctl-cli scale orchestration` posture for 100k, 250k, and 1M credential bands. |
| COMPETE-013 | CAP-SCALE-02 Multi-region HA issuance | Served proof recorded | `docs/performance.md` and `docs/features/platform-and-api.md` document the served regional issuance posture, tenant write fences, failover gates, RPO/RTO, and the constraint that HA does not mean unsafe split-brain writers. |
| COMPETE-034 | CAP-MODEL-02 SaaS / managed offering | Served proof recorded | `docs/features/platform-and-api.md` documents the Provider-tier managed-offering path, `GET /api/v1/managed-offering/status`, `trstctl-cli managed-offering status`, hosted-tenant provisioning, and the event-sourced `tenant.registered` projection. `internal/server/managed_offering_served_test.go` proves the Provider license gate, tenant projection, event metadata, and idempotent replay end to end. |
| COMPETE-036 | CAP-API-07 Idempotent automation + webhooks/eventing | Served proof recorded | `docs/features/platform-and-api.md` documents the REST, CLI, and Terraform `Idempotency-Key` contract, the served `POST /api/v1/identities/{id}/transitions` replay path, the event append plus `ca.issue` outbox binding, and the webhook test route `POST /api/v1/notification-channels/{id}/test`. `internal/server/idempotency_served_test.go` proves the served handler returns the original mutation response without appending a second tenant event or second `ca.issue` outbox row. `internal/server/notifications_served_test.go` proves tenant-authored webhook channel tests and expiry notifications dispatch through the served outbox. |
| COMPETE-039 | CAP-IAM-02 Multi-team / business-unit segmentation / multi-tenancy | Served proof recorded | `docs/features/platform-and-api.md` documents the multi-tenant topology: every tenant table carries `tenant_id`, PostgreSQL row-level security fails closed without tenant context, and `WithTenant` scopes transactions under the non-superuser app role. `internal/server/auth_served_test.go` `TestServedOIDCLoginEndToEnd` proves the served OIDC browser path maps two users into different tenants and each session can read only its own tenant's owners. |
| COMPETE-040 | CAP-KEY-05 Multiple algorithms (RSA / ECDSA / Ed25519) + PQC | Served proof recorded | `docs/features/issuance-and-cas.md` and `docs/features/lifecycle-and-pqc.md` document the buyer-visible profile path for classical RSA, ECDSA, Ed25519, hybrid transition, ML-DSA, and SLH-DSA signing choices. `internal/server/crypto_agility_served_test.go` `TestServedCryptoAgilityProfilesValidateBoundaryAlgorithms` proves `POST /api/v1/profiles` rejects unsupported labels and round-trips RSA, ECDSA, Ed25519, `Hybrid-ML-DSA-44-ECDSA-P256`, `ML-DSA-65`, and `SLH-DSA-SHA2-128s`. `internal/server/protocols_pqc_served_test.go` `TestServedProtocolsIssueHybridPQCLeaves` proves served ACME and CMP issuance can mint the hybrid transition leaf through the same profile-gated issuer. |
| COMPETE-041 | CAP-MODEL-01 Self-hostable, run-anywhere | Served proof recorded | `docs/features/platform-and-api.md` documents the buyer receipt for `GET /api/v1/platform/distribution` and `trstctl-cli platform distribution`: host-archive eval, Docker Compose eval, Kubernetes/Helm, and external-datastore production modes; supported pinned host archives; embedded-Postgres scan receipts; OpenAPI/CLI route parity; the architecture linter; and the open-core boundary that keeps offline license verification plus audit/export in core. `internal/api/platform_distribution_test.go` `TestServedPlatformDistributionCAPMODEL01` proves the served route returns CAP-MODEL-01, the run modes, host archive pins, release gates, and evidence refs. |
| COMPETE-042 | CAP-MODEL-03 Air-gapped / on-prem + data residency | Served proof recorded | `docs/features/platform-and-api.md` documents the buyer receipt for `GET /api/v1/platform/distribution` and `trstctl-cli platform distribution`: the `air_gap` receipt returns `TRSTCTL_AIRGAP_ENABLED`, private/address allowlist controls, `values-airgap.yaml`, operator-owned PostgreSQL/NATS endpoint posture, offline bundle checksum evidence, and the data-residency boundary for disconnected installs. `docs/airgap.md` is the operator runbook. `internal/server/airgap_served_test.go` `TestServedAirGapIssuesCertificateAndManagesSecretWithZeroOutboundEgress` proves the served API can issue a certificate and create/rotate a native secret with zero public egress after the guard blocks a synthetic public endpoint. |

These ten rows close the automatically fixable REPORT-004 source gaps. They are
allowed to lift the Category-Leadership score because the repo now points a
reader to a served product surface and an acceptance-test-backed doc surface for
each row.

## RED-006 Implemented packaging proof

| Source | Implemented decision | Served proof |
|--------|----------------------|--------------|
| NARRATIVE-001 | trstctl's front-door category label is "self-hosted non-human identity management / Machine IAM control plane". | README first viewport, docs index first viewport, `docs/editions.md`, and the web Platform first viewport use the label. |
| NARRATIVE-002 | trstctl has no per-certificate and no ephemeral-identity billing. Certificate and identity counts are operational telemetry or capacity signals. | `GET /api/v1/editions` returns `packaging.no_per_certificate_billing`, `packaging.no_ephemeral_identity_billing`, and meter classifications from `internal/usage`. |
| NARRATIVE-003 | The public proof rail is evidence-bound: live eval receipts, served NHI route coverage, OWASP NHI mapping, and current limitations. | README, docs index, and editions/pricing docs point to served proof and limitation pages instead of analyst-placement claims. |
| NARRATIVE-004 | Unified scope is split into served-now, conditional, partial, and roadmap evidence instead of broad category copy. | Feature pages and limitations continue to carry served-state evidence; this ledger only counts rows with served proof. |
| PACKAGING-001 | Public pricing posture names the billable unit and never-billed counters. | `docs/pricing.md`, `docs/editions.md`, and `GET /api/v1/editions` publish `control_plane_deployment`, `managed_tenant_band`, and the never-billed certificate posture. |
| PACKAGING-002 | The buyer matrix has Community, Enterprise, Provider, and Managed columns. | `docs/editions.md` and the web Platform packaging matrix render all four columns from the served editions payload. |
| PACKAGING-003 | Provider billing uses the managed tenant band. Certificate counters are operational telemetry. | `internal/usage.MeterDefinitions` classifies `certificates_issued` and `certificates_stored` as telemetry and marks `managed_tenant_band` as the primary Provider/Managed unit. |
| PACKAGING-004 | Managed is first-party operated. Provider is MSP or self-hosted provider-plane operation. | `docs/features/platform-and-api.md`, `docs/editions.md`, `docs/pricing.md`, and the managed-offering API/UI document the split. |

## Operator read

The practical interpretation is simple. trstctl now presents itself as a
self-hosted NHI / Machine IAM control plane before the architecture discussion
starts. A buyer can inspect the served capability rows, pricing posture,
edition matrix, and managed boundary without relying on sales language.
