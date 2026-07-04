# Editions

trstctl is MPL-2.0 open-core, self-hosted non-human identity management /
Machine IAM software. The product line keeps core credential issuance, enrollment,
rotation primitives, protocol interoperability, audit/export, PostgreSQL RLS
tenant isolation, and the offline license verifier in Community. Enterprise,
Provider, PQC, and Managed add scale, assurance, governance, support, proprietary
post-quantum migration features, and operating responsibility.

## Pricing Posture

The public billable unit is the control-plane deployment for self-hosted
Community and Enterprise. Provider and Managed packaging use the
`managed_tenant_band` because those offerings operate isolated tenant groups for
customers or business units. Issued certificates, stored certificates, and
ephemeral identities are never the primary billable unit; their counters remain
operational telemetry for capacity planning, abuse detection, and renewal
posture.

## Buyer Matrix

| Packaging line | Community | Enterprise | Provider | Managed |
|---|---|---|---|---|
| P-01 Category entry | Self-hosted NHI / Machine IAM control plane | Self-hosted NHI / Machine IAM with assurance and support | MSP or platform provider NHI / Machine IAM plane | First-party operated NHI / Machine IAM service |
| P-02 Deployment owner | Customer operated | Customer operated | Provider operated for hosted tenants | trstctl operated |
| P-03 Core protocols | ACME, EST, SCEP, CMP, SPIFFE, SSH CA, TSA | Same core protocols | Same core protocols across provider tenants | Same core protocols through the managed control plane |
| P-04 Tenant isolation | PostgreSQL RLS and event spine in core | Same core isolation | Provider tenant isolation plus silo controls | First-party operation with tenant isolation and residency terms |
| P-05 Audit/export | Included | Included plus governance workflows | Included for provider and hosted tenants | Included, with operating handoff terms |
| P-06 Governance | Core policy and audit surfaces | Advanced approvals, remediation, BYOK, governance | Provider governance delegation | Managed operations plus agreed governance handoff |
| P-07 Scale and support | Self-support | HA support and commercial support packages | Provider support terms for hosted tenants | Managed support terms |
| P-08 Assurance | Core crypto boundary and signer isolation | FIPS-capable artifact posture and external-custody options | Provider assurance posture for tenant operation | Managed assurance evidence and residual ownership |
| P-08a PQC and future patented features | Not included in MPL core | Proprietary `ee/` capability when licensed | Proprietary `ee/` capability when licensed | Proprietary operated capability when contracted |
| P-09 Provider operations | Not included | Not included unless explicitly licensed as an extra | Provider plane, metering, white label, siloed isolation | Operated through the Provider control-plane path |
| P-15 Managed offering | Not included | Not included | MSP or self-hosted provider-plane operation | First-party operated packaging column |

The same binary lineage serves all four columns. Community, Enterprise, and
Provider are edition/license boundaries. Managed is an operating model backed by
the Provider control-plane path; it does not move core multi-tenancy, audit,
crypto, or licensing code out of core.

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
| `pqc` | Enterprise | Proprietary post-quantum algorithms, key/certificate types, issuance/signing paths, migration APIs/UI, and tests. |
| `ha_support` | Enterprise | Scale: served enterprise support posture, SLA target catalog, 24x7 production tier, and professional-services packages. |
| `byok` | Enterprise | Assurance: bring-your-own-key / external custody operations. |
| `governance` | Enterprise | Governance: advanced approvals, policy, and audit controls. |
| `provider_plane` | Provider | Managed-provider control plane features. |
| `metering` | Provider | Provider usage metering. |
| `white_label` | Provider | Provider branding controls. |
| `siloed_isolation` | Provider | Provider tenant-silo operating mode. |
