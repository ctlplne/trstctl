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
| `provider_plane` | Provider | Managed-provider control plane features, gated by per-customer delegation (see below). |
| `metering` | Provider | Provider usage metering, durable per-customer, pullable as invoice evidence (see below). |
| `white_label` | Provider | Provider branding controls. |
| `siloed_isolation` | Provider | Provider tenant-silo operating mode. |

### Provider operator delegation

The provider plane has two independent gates, and both fail closed.

**Authentication** answers who an operator is. With no `Authenticator`
configured, `/provider/` refuses every request; there is deliberately no
placeholder verifier.

**Delegation** answers which customers that operator may touch, and through
which operations. Grants live in `provider_operator_delegations` and are read on
every customer-scoped action:

- An operator acts only on customers explicitly granted to them. Naming any
  other customer is refused, and the refusal happens before the store is
  written — a suspended customer and an audited refusal must never disagree.
- Operations are granted separately (`read`, `provision`, `suspend`, `resume`,
  `offboard`, `break-glass`) because they carry different blast radii.
  Suspending interrupts a live service and is reversible; offboarding destroys.
  Being trusted with one is not being trusted with the other.
- There is no wildcard customer. A wildcard grant is indistinguishable from the
  unscoped access this replaces.
- The tenant list returns only delegated customers. The full roster is the
  provider's commercial information, and it is the map an operator would need to
  attempt a cross-customer action.
- Break-glass is re-checked when the grant is USED, not only when it was
  requested, so revoking a delegation stops access an operator already holds.
- No delegation source, or a delegation source that cannot be read, refuses
  everything. Failing open on a read error would make the plane widest exactly
  when it is least healthy.

Grants are minted with a local subcommand against the database:

```
trstctl provider-grant -operator op-1 -customer tenant-acme -operations read,suspend
trstctl provider-grant -operator op-1 -customer tenant-acme -operations offboard -revoke
```

Offboarding a customer clears every grant over it. Tenant ids are derived from
the customer slug, so a grant that outlived the tenancy would hand a reused slug
to whoever held access on the old customer. This applies to database-backed
grants; a deployment still keeping grants in a static configuration file must
remove those lines itself, since rewriting an operator's config file from the
running process would put the file out of step with the system it describes.

This is a local command rather than a served route because of the bootstrap
problem: a route that hands out provider authority must itself be authorised by
somebody holding provider authority, and at install time no such operator
exists. Requiring direct database access states the real trust level.

Not yet built: IdP federation for provider operators (OIDC/SAML with SCIM
provisioning), and a provider access console for reviewing grants.

### Usage metering and invoice evidence

Metering is durable: usage is recorded in PostgreSQL under the same row-level
security fence as every other tenant table, so it survives a restart and cannot
be read across tenancies.

`GET /api/v1/provider/usage-evidence` (CLI: `trstctl usage evidence`, console:
Platform → Usage & invoice evidence) returns the evidence document for a period.
Two properties of that document matter more than the totals:

- **It is scoped to the caller's own tenancy.** A `customer_id` naming any other
  tenant is refused with 403 before the store is touched. A provider pulls a
  customer's evidence from inside that customer's tenancy.
- **It says whether it may be billed.** `signable` is false, with a `reason`, for
  any period the metering store cannot vouch for end to end — an open period,
  metering that was not durable for the whole window, or coverage that starts
  after the period does. The totals are still returned, because "your usage is
  incomplete and here is how" is actionable and an error is not, but they are a
  partial view rather than an invoice. There is deliberately no way to get the
  numbers without the verdict attached.

An absent metering store returns 503 rather than a zero-usage document: no
metering and no usage are different facts.
