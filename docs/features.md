# Feature index

trstctl tracks **79 capabilities**. This page is the traceability matrix: every
feature, its ID, and the page that explains it the trstctl way — *what* it is, *why*
it exists, and *how* it works, for a reader who starts with [zero
knowledge](glossary.md). The index is not a blanket GA-served claim for all 79
rows: served-state metadata is enforced in `internal/featureparity/feature-map-backlog.json`
as `served_state`, using the vocabulary `served`, `conditional`, `partial`,
`library`, and `roadmap`. Current GA-facing catalog rows may not use `library` as a
landing zone for built-but-unserved behavior. If a capability is not wired to a served
runtime surface, it must either be `roadmap` with explicit disclosure or be promoted to
`served`, `conditional`, or `partial` with concrete evidence. It also records
`ga_served_scope` and `ga_scope_reason` for residual conditional/partial rows:
`in_ga` rows must be fully `served`, while `out_of_ga` rows remain visible in the
catalog with a row-specific residual reason and do not inflate the GA served
denominator. The same JSON records
`api_surface`, `api_na`, `cli_surface`, and `cli_na`; `internal/api` and `internal/cli` FeatureParity tests
verify that every named OpenAPI operation/CLI command exists, or that the row has
an explicit N/A reason. It also records `facet_evidence` for the served, UI, CLI,
API, test, docs, RBAC, audit, telemetry, a11y, and i18n facets. The
`FeatureFacetCoverage` test fails if any row is missing evidence or an explicit
N/A, and GA-ish rows (`served`, `conditional`, `partial`) must carry concrete
evidence for the facets that always apply to the shipped operator surface.
`FeatureServedGACoverageCOVER001` recomputes the GA served denominator and fails
unless it is 100% served after explicit residual exclusions. RBAC is
tracked through feature-authz manifests: `/api/v1` rows bind each OpenAPI operation
to a route permission or public credential-exchange rationale, while protocol rows
bind ACME/EST/SCEP/CMP/SSH/SPIFFE/TSA mounts to either `certs:request` or an
explicit protocol-public rationale plus tenant/principal mapping.

This page is the answer to "where is feature X documented?" Each capability has a
**primary page** that teaches it; some are also referenced from related pages and
from the honest [Current limitations](limitations.md) account of what the running
binary serves today versus what is built as library code.

## Discovery & inventory

See **[Discovery & inventory](features/discovery-and-inventory.md)**.

| ID | Feature |
|----|---------|
| F1 | Certificate inventory |
| F2 | Network discovery |
| F3 | Agent-based discovery |
| F42 | SSH credential discovery & inventory |
| F49 | Agentless cloud certificate discovery |
| F35 | Secret store discovery |
| F36 | API key / token inventory |

## Observability & risk

See **[Observability & risk](features/observability-and-risk.md)**.

| ID | Feature |
|----|---------|
| F17 | Certificate Transparency monitoring |
| F18 | Drift detection |
| F19 | Credential risk scoring |
| F52 | Cryptographic discovery & observability (CBOM) |

## Issuance & certificate authorities

See **[Issuance & certificate authorities](features/issuance-and-cas.md)**.

| ID | Feature |
|----|---------|
| F4 | CA-agnostic outbound issuance |
| F48 | Private/enterprise CA hierarchy management |
| F53 | Certificate profiles & registration-authority model |
| F46 | ACME Renewal Information (ARI) |
| F47 | X.509 revocation infrastructure |
| F26 | HSM integration |

## ACME & DNS validation

See **[ACME & DNS validation](features/acme-and-dns.md)**.

| ID | Feature |
|----|---------|
| F5 | Built-in ACME server |
| F69 | DNS-01 challenge automation |
| F70 | DNS-provider plugin framework |
| F71 | CNAME delegation for validation isolation |
| F72 | CAA policy enforcement & management |
| F73 | Multi-method domain-validation policy |
| F74 | Automated wildcard issuance & renewal |

## Enrollment protocols

See **[Enrollment protocols](features/enrollment-protocols.md)**.

| ID | Feature |
|----|---------|
| F22 | EST server (RFC 7030) |
| F23 | SCEP server (RFC 8894) |
| F55 | CMP server (RFC 4210 / CMPv3) |
| F54 | Embedded / IoT enrollment agent |
| F56 | Intune / MDM enrollment integration |

## Workload identity

See **[Workload identity](features/workload-identity.md)**.

| ID | Feature |
|----|---------|
| F24 | SPIFFE Workload API |
| F25 | Ephemeral credential issuance |
| F30 | Workload attestation chain |
| F59 | Non-human identity lifecycle management |
| F61 | AI-agent / NHI identity broker |

## SSH

See **[SSH](features/ssh.md)**.

| ID | Feature |
|----|---------|
| F43 | SSH certificate authority |
| F44 | SSH deployment & trust configuration (agent) |
| F45 | Attestation-gated short-lived SSH user certs |

## Lifecycle & PQC

See **[Lifecycle & PQC](features/lifecycle-and-pqc.md)**.

| ID | Feature |
|----|---------|
| F6 | Lifecycle automation |
| F16 | Crypto-agility and PQC readiness |
| F57 | PQC migration orchestration |

## Deployment connectors

See **[Deployment connectors](features/deployment-connectors.md)**.

| ID | Feature |
|----|---------|
| F7 | Deployment connectors (initial set) |
| F27 | Additional connectors |

## Code signing & timestamping

See **[Code signing & timestamping](features/code-signing-and-timestamping.md)**.

| ID | Feature |
|----|---------|
| F50 | Code-signing service |
| F51 | Timestamping authority (RFC 3161) |

## Incident response & just-in-time access

See **[Incident response & just-in-time access](features/incident-and-jit.md)**.

| ID | Feature |
|----|---------|
| F31 | Credential compromise workflow |
| F32 | Fleet re-issuance for CA compromise |
| F33 | Just-in-time issuance with approval flows |
| F34 | Break-glass procedures |

## Secrets

See **[Secrets](features/secrets.md)**.

| ID | Feature |
|----|---------|
| F37 | Secret rotation engine |
| F38 | Ephemeral API key issuance |
| F39 | Code/CI secret scanning bridge |
| F63 | Native secret store |
| F64 | Developer secrets experience (CLI, portal, SDKs) |
| F65 | Dynamic secrets |
| F66 | Encryption-as-a-service (transit) & KMIP |
| F67 | PKI as a secrets engine |
| F68 | Secret sync / platform integrations |
| F58 | Platform auth-method framework |
| F60 | Secret sharing & secret-change approvals |

## Policy & governance

See **[Policy & governance](features/policy-and-governance.md)**.

| ID | Feature |
|----|---------|
| F28 | Policy engine |
| F29 | Notification integrations |
| F62 | Cryptographic compliance reporting & posture dashboards, plus NHI access certification campaigns |
| F79 | Privacy and data-subject controls |
| F8 | RBAC |
| F9 | Audit log surfaces |

## Platform & API

See **[Platform & API](features/platform-and-api.md)**.

| ID | Feature |
|----|---------|
| F10 | REST API |
| F11 | CLI |
| F12 | Web UI |
| F13 | SSO/OIDC |
| F14 | Single-binary distribution |
| F15 | Encrypted control-plane transport |
| F40 | Multi-tenant deployment topology |
| F41 | Cross-cluster / multi-region federation |

## Extensibility & plugins

See **[Extensibility & plugins](features/extensibility-plugins.md)**.

| ID | Feature |
|----|---------|
| F20 | Plugin SDK with capability sandboxing |

## Graph, query & AI

See **[Graph, query & AI](features/graph-query-ai.md)**.

| ID | Feature |
|----|---------|
| F21 | Credential graph |
| F75 | Unified semantic query layer |
| F76 | Pluggable AI model adapter |
| F77 | Grounded RCA & natural-language query |
| F78 | trstctl MCP server |
