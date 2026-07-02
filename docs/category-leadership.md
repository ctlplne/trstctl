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

These five rows close the automatically fixable REPORT-004 source gaps. They are
allowed to lift the Category-Leadership score because the repo now points a
reader to a served product surface and an acceptance-test-backed doc surface for
each row.

## Decision-track residuals

| Source | Residual | Why it is not counted as served leadership |
|--------|----------|--------------------------------------------|
| NARRATIVE-001 | Primary NHI category label | This is a decision-track residual. The recommended wording is "self-hosted non-human identity management / Machine IAM control plane", but the exact front-door category label needs human product approval before it can become public positioning. |
| PACKAGING-001 | Public pricing and plan terms | This is a decision-track residual. The recommended posture is transparent pricing with an explicit billable unit and an explicit never-billed list, but the actual plan terms need human approval before they can become product truth. |
| PACKAGING-004 | Public managed-offering boundary | The CAP-MODEL-02 provider-plane capability is served, but the public packaging choice still needs human approval: first-party SaaS, MSP/Provider operation, or self-hosted Provider licensing, including support, data-residency, and operating-responsibility terms. |

These residuals stay outside the served Category-Leadership numerator until the
human decisions are made and then wired into README, docs index, editions/pricing,
managed-offering packaging, and the web console. That keeps trstctl honest: the
score may improve from served Kubernetes, EAB, DNS, scale, HA, and provider-plane
managed-offering proof, but it cannot pretend that pricing, positioning, or
public managed-service packaging has been decided.

## Operator read

The practical interpretation is simple. trstctl has moved from "competitive but
not proved enough" to "served table-stakes proof is present for the REPORT-004
automation gaps, with two explicit human decisions still open." A buyer can
inspect the served capability rows without trusting sales language, and a product
owner can see exactly which decisions still block a stronger public category
claim.
