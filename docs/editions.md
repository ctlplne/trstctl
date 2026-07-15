# Editions

trstctl is an MPL-2.0 open-core Machine Identity Security Control Plane. The
product line keeps core credential issuance, enrollment,
rotation primitives, protocol interoperability, audit/export, PostgreSQL RLS
tenant isolation, and the offline license verifier in Free. Enterprise adds the
commercial `ee/` feature set. Provider / MSP includes every Enterprise feature and
adds provider-plane operations plus managed-service and resale rights.

## Pricing Posture

The canonical billing reference is [Pricing](pricing.md); the posture in brief:
Free has no license bill. Enterprise uses `control_plane_deployment`. Provider /
MSP uses a negotiated `managed_customer_band` as its wholesale anchor. The MSP
controls its downstream hosting and support prices. Certificates, SVIDs, secrets,
API keys, tokens, rotations, nodes, and deployment count are not automatic
Provider wholesale billing units.

## Buyer Matrix

| Packaging line | Free | Enterprise | Provider / MSP |
|---|---|---|---|
| Buyer | Organization operating trstctl for itself | Organization needing the commercial feature set | MSP operating or reselling trstctl-backed services to customers |
| Primary billing unit | None | Per control-plane deployment | Negotiated managed-customer band |
| Core protocols | ACME, EST, SCEP, CMP, SPIFFE, SSH CA, TSA | Included | Included |
| Tenant isolation | PostgreSQL RLS and event spine | Included | Included; shared multi-tenant control plane is the normal shape |
| Enterprise features | Not included | FIPS artifact posture, remediation, PQC, HA support, BYOK, governance, PCAS, agent delegation, reconciliation, and VDEC | All Enterprise features |
| Provider operations | Not included | Not included | Provider plane, metering, white label, and siloed isolation |
| Product motion and commercial `ee/` rights | Self-hosted core under MPL-2.0 | Self-hosted commercial feature set | Self-host, managed service, and resale of the commercial feature set |
| Deployment flexibility | Customer operated | Customer operated | Shared control plane or dedicated customer deployments |
| Pricing discretion | No license fee | Deployment contract | Wholesale band and terms are negotiable; MSP sets downstream pricing |

The same binary lineage serves all three tiers. The offline signed tier drives
both feature inheritance and use rights. Core multi-tenancy, audit/export, crypto,
and the license verifier remain in core.

## Core Protocols

These protocol surfaces are Free/Community capabilities. They are not Enterprise-only
features in `internal/license`.

| Capability | Edition | Notes |
|---|---|---|
| ACME | Community | ACME server, account/order flow, ARI, and DNS-validation framework. |
| EST | Community | RFC 7030 enrollment endpoint. |
| SCEP | Community | RFC 8894 enrollment endpoint. |
| CMP | Community | RFC 4210 / CMPv3 enrollment endpoint. |
| SPIFFE Workload API | Community | X.509 and JWT SVID workload identity surface. |
| SSH CA | Community | SSH certificate authority endpoints and KRL publication. |
| TSA | Community | Timestamping authority surface. |

## License-Gated Features

This table mirrors `internal/license` exactly. A feature absent from this table is
Free/Community by default unless a signed license explicitly grants it as an extra.
Provider inherits every Enterprise row below, then adds the Provider rows.

| Feature ID | Edition | Product line |
|---|---|---|
| `fips` | Enterprise | Assurance: FIPS-capable distribution posture and evidence. |
| `remediation` | Enterprise | Governance: guided remediation workflows and controls. |
| `pqc` | Enterprise | Proprietary post-quantum algorithms, key/certificate types, issuance/signing paths, migration APIs/UI, and tests. |
| `ha_support` | Enterprise | Scale: served enterprise support posture, SLA target catalog, 24x7 production tier, and professional-services packages. |
| `byok` | Enterprise | Assurance: bring-your-own-key / external custody operations. |
| `governance` | Enterprise | Governance: advanced approvals, policy, and audit controls. |
| `pcas` | Enterprise | Proof-carrying algorithm succession. |
| `agent-delegation` | Enterprise | Chain-bound AI agent identity lifecycle enforcement. |
| `reconcile` | Enterprise | Cross-plane trust reconciliation rounds and evidence machinery. |
| `vdec` | Enterprise | Verifiable decommissioning dependency-state re-protection and destruction proof machinery. |
| `provider_plane` | Provider | Managed-provider control plane features. |
| `metering` | Provider | Provider usage metering. |
| `white_label` | Provider | Provider branding controls. |
| `siloed_isolation` | Provider | Provider tenant-silo operating mode. |
