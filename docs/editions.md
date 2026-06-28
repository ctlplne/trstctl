# Editions

trstctl is source-available software with a production-usable Community tier and
commercial Enterprise and Provider tiers. The product line keeps core credential
issuance, enrollment, rotation primitives, and protocol interoperability in
Community; paid tiers add scale, assurance, governance, and provider-operating
controls.

## Core Protocols

These protocol surfaces are Community capabilities. They are not Enterprise-only
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
Community by default unless a signed license explicitly grants it as an extra.

| Feature ID | Edition | Product line |
|---|---|---|
| `fips` | Enterprise | Assurance: FIPS-capable distribution posture and evidence. |
| `remediation` | Enterprise | Governance: guided remediation workflows and controls. |
| `ha_support` | Enterprise | Scale: served enterprise support posture, SLA target catalog, 24x7 production tier, and professional-services packages. |
| `byok` | Enterprise | Assurance: bring-your-own-key / external custody operations. |
| `governance` | Enterprise | Governance: advanced approvals, policy, and audit controls. |
| `provider_plane` | Provider | Managed-provider control plane features. |
| `metering` | Provider | Provider usage metering. |
| `white_label` | Provider | Provider branding controls. |
| `siloed_isolation` | Provider | Provider tenant-silo operating mode. |
