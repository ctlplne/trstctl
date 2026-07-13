# Product decision register

This page is the REPORT-007 control for product decisions that affect public
positioning, packaging, and buyer-facing proof. RED-006 moved the NHI category and
packaging rows from recommendations into implemented product truth on 2026-07-03.
The implementation owner for this record is the RED-006 remediation owner.

Status vocabulary:

- **Needs human decision** means a recommendation has no product effect yet.
- **Approved** means a human owner has accepted the decision and assigned the
  implementation work.
- **Implemented** means the accepted decision is wired into docs, UI, license
  surfaces, and tests.
- A row can move from **Needs human decision** to **Approved** or **Implemented**
  only when the same change updates `## Promotion records` with the human owner,
  decision date, and test evidence.

## Narrative decisions

| ID | Status | Implemented decision | Served surfaces |
|----|--------|----------------------|-------------------------------------|
| NARRATIVE-001 | Implemented | Adopt "Machine Identity Security Control Plane" as the front-door category label. | README first viewport, docs index, editions page, category leadership ledger, and Platform first viewport. |
| NARRATIVE-002 | Implemented | Use no per-certificate and no ephemeral-identity billing is product policy; keep certificate and identity counts as operational telemetry or capacity signals. | Pricing page, editions page, Provider billing docs, and challenger-cost narrative. |
| NARRATIVE-003 | Implemented | Publish an evidence-bound proof rail that uses live eval receipts, served NHI route coverage, OWASP NHI mapping, and current limitations. Do not imply analyst placement without a dated external citation. | README proof block, docs index proof rail, security/compliance overview, and release notes. |
| NARRATIVE-004 | Implemented | Split the unified-scope story into served-now, conditional, partial, and roadmap rows tied to served_state evidence. | Feature catalog, category leadership ledger, docs index summary, and web console overview. |

## Packaging decisions

| ID | Status | Implemented decision | Served surfaces |
|----|--------|----------------------|-------------------------------------|
| PACKAGING-001 | Implemented | Publish three tiers: Free for the self-hosted MPL core, Enterprise per control-plane deployment, and Provider / MSP by negotiated managed-customer band. Certificates, SVIDs, secrets, API keys, tokens, rotations, nodes, and deployments are not Provider wholesale billing counters. | Pricing page, editions page, Provider docs, and served editions API. |
| PACKAGING-002 | Implemented | The buyer-facing matrix has exactly Free, Enterprise, and Provider / MSP. A Provider license inherits every Enterprise feature and adds provider-plane capabilities. | `docs/editions.md`, web Platform packaging panel, license inheritance tests, and the license feature table. |
| PACKAGING-003 | Implemented | The managed-customer band is the Provider wholesale anchor, but the final price is negotiable for support, hosting posture, residency, contract term, and deployment isolation. The MSP sets its own downstream prices; certificate counters are operational telemetry. | Pricing page, served editions API, license CLI, and usage-meter contract. |
| PACKAGING-004 | Implemented | Provider / MSP includes managed-service and resale rights. One shared multi-tenant control plane is normal, while dedicated customer deployments remain supported. | Offline signed license status, managed-offering API, Provider docs, and Platform UI. |
| PACKAGING-007 | Implemented | Finalize the project license as MPL-2.0 open core with proprietary/commercial `ee/`; all PQC, license-gated, and future patented features land under `ee/` from day one. This supersedes DOCS-006, DOCS-007, and PACKAGING-002 where they encoded the old non-MPL posture. | Root `LICENSE`, `ee/LICENSE`, README badge, docs license pages, `GET /api/v1/editions`, license feature table, and architecture-linter boundary checks. |

## Promotion records

| ID | Status | Owner | Decision date | Test evidence |
|----|--------|-------|---------------|---------------|
| NARRATIVE-001 | Implemented | RED-006 remediation owner | 2026-07-03 | TestProductDecisionRegisterCapturesReport007Recommendations; TestCategoryLeadershipLedgerClosesReport004WithoutDecisionOverclaim |
| NARRATIVE-002 | Implemented | RED-006 remediation owner | 2026-07-03 | TestProductDecisionRegisterCapturesReport007Recommendations; TestCategoryLeadershipLedgerClosesReport004WithoutDecisionOverclaim |
| NARRATIVE-003 | Implemented | RED-006 remediation owner | 2026-07-03 | TestProductDecisionRegisterCapturesReport007Recommendations; TestCategoryLeadershipLedgerClosesReport004WithoutDecisionOverclaim |
| NARRATIVE-004 | Implemented | RED-006 remediation owner | 2026-07-03 | TestProductDecisionRegisterCapturesReport007Recommendations; TestCategoryLeadershipLedgerClosesReport004WithoutDecisionOverclaim |
| PACKAGING-001 | Implemented | RED-006 remediation owner | 2026-07-03 | TestProductDecisionRegisterCapturesReport007Recommendations; TestCategoryLeadershipLedgerClosesReport004WithoutDecisionOverclaim |
| PACKAGING-002 | Implemented | Product owner | 2026-07-13 | TestTierRightsAndProviderInheritance; TestEditionsEndpointServesRED006PackagingDecisions |
| PACKAGING-003 | Implemented | Product owner | 2026-07-13 | TestManagedCustomerBandValidation; TestLicenseHelperBandFlagsAndTierValidation |
| PACKAGING-004 | Implemented | Product owner | 2026-07-13 | TestTierRightsAndProviderInheritance; TestEditionsEndpointServesRED006PackagingDecisions |
| PACKAGING-007 | Implemented | PACKAGING-007 decision owner | 2026-07-04 | TestLicenseStatusIsConsistent; TestEditionsMatrixMatchesLicenseFeatureTable; trstctllint license boundary checks |

## Superseded audit cards

| ID | Superseded by | Reason |
|----|---------------|--------|
| DOCS-006 | PACKAGING-007 | The old positive evidence described the pre-MPL posture; the product posture is now MPL-2.0 open core plus proprietary `ee/`. Telemetry and AI egress controls remain valid. |
| DOCS-007 | PACKAGING-007 | The old README badge/card fixed the pre-MPL badge wording; PACKAGING-007 replaces that entire posture with MPL-2.0 open core. |

## Guardrail

These rows are now product truth because RED-006 wired them into public docs,
`GET /api/v1/editions`, the web Platform first viewport, and regression tests.
Future changes to the category label, billable unit, Provider rights, or
certificate-counter classification must update those same surfaces together.
