# Editions

trstctl is an MPL-2.0 open-core Machine Identity Security Control Plane. The
product line keeps core credential issuance, enrollment,
rotation primitives, protocol interoperability, audit/export, PostgreSQL RLS
tenant isolation, and the offline license verifier in Free. Enterprise adds the
commercial `ee/` feature set. Provider / MSP includes every Enterprise feature and
adds provider-plane operations plus managed-service and resale rights.

## Pricing Posture

The canonical billing reference is [Pricing](pricing.md); the posture in brief:
Free has no license bill. Enterprise publishes annual USD reference list prices
of $15,000 Standard and $30,000 Plus per production
`control_plane_deployment`. Provider / MSP publishes wholesale bands of $12,000
for 1–10 managed customers, $30,000 for 11–50, and $72,000 for 51–250; 250+
is negotiated. The MSP controls its downstream hosting and support prices.
Certificates, SVIDs, secrets, API keys, tokens, rotations, and nodes are never
automatic billing units. See [Pricing](pricing.md) for support and renewal terms.

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
| Pricing | No license fee | $15,000 Standard or $30,000 Plus annual reference list | $12,000 / $30,000 / $72,000 annual wholesale reference bands; 250+ negotiated |
| Environment entitlement | Community deployments are unmetered | 1 production + 3 signed non-production deployment slots | Same bundle per licensed Provider control plane |

The same binary lineage serves all three tiers. The offline signed tier drives
both feature inheritance and use rights. Core multi-tenancy, audit/export, crypto,
and the license verifier remain in core.

## Signed deployment environment entitlement

New licenses use claim version 2. Their signed `environment_entitlement` object
contains `production_deployment_id`, up to three
`non_production_deployment_ids`, and `non_production_allowance: 3`. The vendor
helper refuses duplicate IDs, a production ID repeated as non-production, an
unsafe ID, or more registered non-production IDs than the allowance.

The offline vendor helper creates that bundle explicitly:

```bash
trstctl-license sign \
  --private-key vendor-ed25519.key \
  --out acme-license.json \
  --id lic-acme-2027 --customer "Acme Corp" --tier enterprise \
  --production-deployment-id acme-prod \
  --non-production-deployment-ids acme-stage,acme-dev,acme-test \
  --expires-at 2027-08-13T00:00:00Z
```

The running binary binds those claims to operator-owned configuration:

```bash
TRSTCTL_LICENSE_FILE=/etc/trstctl/license.json \
TRSTCTL_LICENSE_DEPLOYMENT_ID=acme-stage \
TRSTCTL_LICENSE_ENVIRONMENT=non_production \
trstctl
```

Both runtime values are required together for v2. `production` must match the
one signed production ID; `non_production` must match one signed non-production
ID. A copied file with a changed or misclassified ID fails startup. The Editions
API exposes `deployment_entitlement.environment`, `deployment_id`,
`production_units_consumed`, registered and remaining non-production slots, and
the legacy marker. A non-production deployment therefore provides a
machine-readable zero production-unit result rather than relying on sales prose.

Version 1 files remain readable for upgrade continuity, but they are explicitly
production-only and `legacy_unbound: true`; a v1 file cannot activate the
bundled non-production right. This compatibility rule avoids inventing an
entitlement that was never signed.

The supervised signer child receives the same deployment ID and environment as
the control plane and independently applies the same bound loader. An operator
starting `trstctl-signer` as a separate process must pass
`--license-deployment-id` and `--license-environment` beside `--license`; a v2
file without that pair fails closed before the signing service listens.

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

Grants are minted with a local subcommand against PostgreSQL **and the event
log**. Every invocation needs a stable idempotency key; an identical retry
returns the canonical authority event, while reusing the key for a changed
grant is refused:

```
trstctl provider-grant -operator op-1 -customer tenant-acme \
  -operations read,suspend -granted-by platform-admin \
  -idempotency-key tenant-acme-op-1-read-suspend-v1
trstctl provider-grant -operator op-1 -customer tenant-acme \
  -operations offboard -revoke -granted-by platform-admin \
  -idempotency-key tenant-acme-op-1-offboard-revoke-v1
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
exists. The command opens the configured PostgreSQL and JetStream stores,
bootstraps any pre-event delegation rows exactly once, appends one immutable
`provider.delegation.granted` or `provider.delegation.revoked` event, and lets
the provider authority projection update the delegation view. It never writes
the table directly. When embedded NATS is configured, run the command while the
control plane is offline so two processes do not open the same file-backed
store.

Provider OIDC bearer verification uses pinned JWKS, issuer, audience, expiry,
not-before, role, and MFA claims. Provider SAML is a separate SP at
`/provider/v1/auth/saml/{login,acs,metadata}`: the crypto boundary validates the
signed assertion, issuer, audience/recipient, time window, request correlation,
role, and MFA attributes before minting a Provider-only HttpOnly session. That
cookie never becomes a customer-tenant session; state-changing requests also
need its double-submit `X-Provider-CSRF-Token` value.

Provider SCIM is served at `/provider/scim/v2`. Token bytes are read from
custody-checked files, hashed, wiped, and never retained as strings. User
join/update/`active:false`/delete emits immutable operator lifecycle events.
When SCIM is enabled, OIDC and SAML re-read that projected operator row on
**every request**. A still-valid token or browser session therefore stops at the
first request after a leaver event; the leaver projection also revokes every
standing customer grant for that operator.

Provider administrators with current MFA use `GET /provider/v1/operators`,
`GET /provider/v1/access/customers`, and the per-operator `/delegations`,
`/revocations`, and `/role` mutation routes.
The console shows the operator, SCIM source, role, exact customer/operation,
grant source, expiry, last use, and retained revocation evidence. These routes
are not the install-time bootstrap: the local `provider-grant` command remains
available for creating the first authority before an administrator exists.
`POST /provider/v1/auth/logout` revokes the Provider session, clears its cookie,
and is protected by the same CSRF and idempotency contract as other mutations.

### Provider authority event source and retries

Customer lifecycle, delegation, quota, white-label branding, and break-glass
grant/use state share one tenant-scoped immutable authority history. The
`provider_tenants`, `provider_operators`, `provider_operator_delegations`,
`provider_tenant_quotas`, `tenant_branding`, and
`provider_breakglass_grants` tables are read models owned only by that
projection; their PostgreSQL stores expose no direct mutators. An upgraded
installation captures each uncovered pre-event row once before its first
rebuild, including brand token overrides and both break-glass consents.

Every state-changing `/provider/v1` request requires `Idempotency-Key`. The key
is immutably bound to the authenticated operator, method, path, and body; exact
retries return the original status, headers, and bytes, including concurrent
retries, while a changed command returns `409`. Break-glass result access
increments use count and is therefore `POST
/provider/v1/breakglass/{grant}/results`, not a read-looking GET. The provider
console generates a distinct key for every mutation it submits.

`GET /provider/v1/activity?limit=100` derives a newest-first authority evidence
view directly from that same immutable history. It returns event identity,
sequence, type, time, customer, actor, grant, subject, and reason only: request
bindings, authority state payloads, and break-glass tenant snapshots are never
exposed through the history route. Current delegation is applied before any
customer event is returned, so an operator cannot discover another customer's
authority history; deployment-wide isolation-drill evidence is Provider-admin
only. The Provider console renders this view beside the controls, making the
evidence for a completed mutation visible without trusting a second audit store.

### Usage metering and invoice evidence

Metering is durable: usage is recorded in PostgreSQL under the same row-level
security fence as every other tenant table, so it survives a restart and cannot
be read across tenancies.

`GET /api/v1/provider/usage-evidence` (CLI: `trstctl usage evidence`, console:
Platform → Usage & invoice evidence) returns the evidence document for a period.
Two properties of that document matter more than the totals:

- **The tenant route is scoped to the caller's own tenancy.** A `customer_id`
  naming any other tenant is refused with 403 before the store is touched.
  Provider billing staff do not impersonate that tenant: their separate
  workforce credential calls `GET
  /provider/v1/tenants/{id}/usage-evidence` with an exact customer read delegation
  (the `read` operation). An undelegated customer or a grant for another operation is
  refused before the customer's forced-RLS metering transaction opens.
- **It says whether it may be billed.** `signable` is false, with a `reason`, for
  any period the metering store cannot vouch for end to end — an open period,
  metering that was not durable for the whole window, or coverage that starts
  after the period does. The totals are still returned, because "your usage is
  incomplete and here is how" is actionable and an error is not, but they are a
  partial view rather than an invoice. There is deliberately no way to get the
  numbers without the verdict attached.

An absent metering store returns 503 rather than a zero-usage document: no
metering and no usage are different facts.

The Provider route returns the same canonical signed JSON/JWS document as the
tenant route, or `?format=csv` for a strict finance CSV whose rows retain the
customer, period, signable verdict, reconciliation result, and document digest.
The `/provider` console selects customer and period, downloads signed JSON or
finance CSV, and fetches public trust separately from `GET
/provider/v1/evidence/verification-keys`. It reconstructs the displayed
document's canonical bytes and shows **Signature verified** only when RS256,
the protected billing-invoice artifact domain, key id, digest, and signature
all match. A green label therefore does not trust the evidence response's own
`signable` boolean.
