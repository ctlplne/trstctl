# Plan and license

trstctl is a source-available Machine Identity Security Control Plane: the core is
BUSL-1.1, converting to MPL-2.0 four years after each release, and the commercial
editions are proprietary. The
product line keeps core credential issuance, enrollment,
rotation primitives, protocol interoperability, audit/export, PostgreSQL RLS
tenant isolation, and the offline license verifier in Free. Enterprise adds the
commercial `ee/` feature set. Provider / MSP includes every Enterprise feature and
adds provider-plane operations plus managed-service and resale rights.

## Commercial posture

Free has no license bill: the BUSL-1.1 core runs in production without a signed
license. Enterprise and Provider / MSP are commercial editions activated by an
offline Ed25519-signed license; their commercial terms are not published yet and
are agreed per customer. A Provider license is scoped by a managed-customer
band, and the MSP controls its own downstream hosting, support, and terms.
Certificates, SVIDs, secrets, API keys, tokens, rotations, nodes, discovery
findings, and audit events are never automatic billing units: there is no
per-connector, no per-protocol, and no per-certificate or per-ephemeral-identity
meter. Every Enterprise or Provider license names 1 production deployment and
bundles 3 non-production deployments with the full licensed feature set and no
production SLA; see
[Signed deployment environment entitlement](#signed-deployment-environment-entitlement).

### Grace and expiry

At expiry, the offline verifier provides a 30-day grace period. During grace,
licensed modes remain enabled. After grace, the license state and commercial
feature modes become `read_only`; core issuance, renewal, revocation, protocol,
audit/export, tenancy, and license-verification capabilities remain Community
software. The core keeps running: a lapsed commercial order never bricks a
customer's PKI. Commercial mutation surfaces honor the served `read_only` mode,
and the editions page makes that state visible before an operator acts.
`GET /api/v1/editions` and Platform → Editions expose the effective tier, the
expiry/read-only horizon, the signed deployment environment, production-unit
consumption, remaining non-production slots, and packaging rules;
`internal/license` owns the one feature-to-tier table and the one bundled
allowance constant, and the API and docs are guarded against drift from them.

## Console journey

Open **Plan and license** at `/admin/editions` to answer two questions first:
which signed features this deployment may use, and when that permission ends.
The opening card shows the current plan, enabled-feature count, expiry, and a
plain-language state such as Community, Active, Grace, or Read-only. The page
makes only the Editions API read needed for that answer.

The deeper proof remains available without putting it in the operator's way:

1. **Signature verification** explains whether the offline Ed25519 signature
   verified and when the deployment becomes read-only.
2. **Feature table** maps each exact feature ID to its required plan and current
   mode.
3. **Entitlement evidence** shows the customer, deployment binding, environment,
   use rights, FIPS posture, and optional packaging evidence. Deployment
   distribution and active-active issuance evidence are fetched only after the
   nested architecture disclosure is opened.

**Add license** is an operator guide, not a browser upload. A private license is
installed as an operator-controlled `0600` file, bound to the signed deployment
ID and environment, then supplied to both the control plane and isolated signer
at startup. Restart those two processes together. This avoids browser custody of
the license and prevents the control plane and signer from temporarily applying
different rights. Read or verification failures are shown with sanitized,
fail-closed language and a safe retry; raw server errors are not displayed.

### Where the trusted vendor key comes from

A license verifies only against the vendor's license signing public keys baked
into the binaries at build time. Native builds bake them with
`make LICENSE_KEYS_B64=$(base64 -w0 license-signing.pub)`; container images bake
them with the `LICENSE_KEYS_B64` build argument of `deploy/docker/Dockerfile`
(the release pipeline passes the repository variable
`TRSTCTL_LICENSE_KEYS_B64`). Only public keys are ever baked. A build without
a baked key bakes no trust: no license file can verify and the deployment stays
Community, which is the fail-closed default for local builds. The local
click-through demo is the one exception: its image target mints a throw-away
key and license inside the build and deletes the signing material, so a demo
license never verifies on any other build.

### Containers and the partner lab

In containers the license is a read-only mounted file owned by the operator,
never an image layer. The partner lab ships this path as an opt-in profile:

```bash
TRSTCTL_LAB_LICENSE_FILE=/secure/acme-license.json \
TRSTCTL_LAB_LICENSE_KEYS_B64="$(base64 -w0 vendor-ed25519.pub)" \
TRSTCTL_LAB_LICENSE_DEPLOYMENT_ID=acme-lab \
TRSTCTL_LAB_LICENSE_ENVIRONMENT=non_production \
deploy/demo/lab/run.sh
```

`run.sh` refuses a license file that is group- or world-readable, builds the
clean `release` image target with the vendor key baked in, copies the file once
into the run-owned runtime volume for the service user, and starts the control
plane and the isolated signer with the same bound deployment ID and
environment. The deployment ID must be one the license signed for that
environment; a copied file with another binding fails startup. The same profile
pins the lab's local identity provider for provider-operator sign-in (see
[Provider operator delegation](#provider-operator-delegation) and the
[provider journey](journeys/operate-as-a-provider.md)).

## Buyer Matrix

| Packaging line | Free | Enterprise | Provider / MSP |
|---|---|---|---|
| Buyer | Organization operating trstctl for itself | Organization needing the commercial feature set | MSP operating or reselling trstctl-backed services to customers |
| Primary billing unit | None | Per control-plane deployment | Negotiated managed-customer band |
| Core protocols | ACME, EST, SCEP, CMP, SPIFFE, SSH CA, TSA | Included | Included |
| Tenant isolation | PostgreSQL RLS and event spine | Included | Included; shared multi-tenant control plane is the normal shape |
| Patent-pending families and PQC | Included: PCAS, agent delegation, reconciliation, VDEC, and post-quantum cryptography attach in every build | Included | Included |
| Remediation | Incident response and guided remediation, subject to authorization and configured targets | Included | Included |
| Enterprise features | Not included | FIPS artifact posture, HA support, BYOK, governance, tenant SAML/LDAP/SCIM (Enterprise SSO), and audit anchoring/retention/compliance packaging | All Enterprise features |
| Provider operations | Not included | Not included | Provider plane, metering, white label, and siloed isolation |
| Product motion and commercial `ee/` rights | Self-hosted core under BUSL-1.1 | Self-hosted commercial feature set | Self-host, managed service, and resale of the commercial feature set |
| Deployment flexibility | Customer operated | Customer operated | Shared control plane or dedicated customer deployments |
| Commercial terms | No license fee | Not yet published | Not yet published |
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
PCAS, agent delegation, reconciliation, verifiable decommissioning, PQC and
remediation are core capabilities and require no commercial feature grant.

| Feature ID | Edition | Product line |
|---|---|---|
| `fips` | Enterprise | Assurance: FIPS-capable distribution posture and evidence. |
| `ha_support` | Enterprise | Scale: served enterprise support posture, SLA target catalog, 24x7 production tier, and professional-services packages. |
| `byok` | Enterprise | Assurance: bring-your-own-key / external custody operations. |
| `governance` | Enterprise | Governance: advanced approvals, policy, and audit controls. |
| `enterprise_sso` | Enterprise | Tenant SAML and LDAP sign-in, plus tenant SCIM provisioning. OIDC remains core. |
| `audit_compliance` | Enterprise | Audit timestamp anchoring, retention, and compliance packaging. Plain signed history export stays core. |
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
log**. Name the customer by the slug you will provision (its tenant id is
derived from the slug, so a customer can be delegated before it exists; the
command prints the derived id) or by an existing tenant id. Every invocation
needs a stable idempotency key; an identical retry returns the canonical
authority event, while reusing the key for a changed grant is refused. The same
rule holds for every provider mutation over the API: a key binds its first
answer, a refusal included, and a replayed answer carries the
`Idempotent-Replayed: true` header. After you fix the cause of a refusal, retry
with a new key:

```
trstctl provider-grant -operator op-1 -customer acme \
  -operations read,provision,suspend -granted-by platform-admin \
  -idempotency-key acme-op-1-read-provision-suspend-v1
# time-boxed: the grant stops authorizing after -expires-at (RFC3339)
trstctl provider-grant -operator op-1 -customer acme \
  -operations read -granted-by platform-admin \
  -expires-at 2027-01-01T00:00:00Z \
  -idempotency-key acme-op-1-read-until-2027-v1
trstctl provider-grant -operator op-1 -customer acme \
  -operations offboard -revoke -granted-by platform-admin \
  -idempotency-key acme-op-1-offboard-revoke-v1
```

Offboarding a customer clears every grant over it. Tenant ids are derived from
the customer slug, so a grant that outlived the tenancy would hand a reused slug
to whoever held access on the old customer. This applies to database-backed
grants; a deployment still keeping grants in a static configuration file must
remove those lines itself, since rewriting an operator's config file from the
running process would put the file out of step with the system it describes.

This is a local command rather than a served route because of the bootstrap
problem: a route that hands out provider authority must itself be authorized by
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

The same customer selection also reads `GET
/provider/v1/tenants/{id}/health`. This is a small operational view, not
break-glass access: after the exact `read` delegation succeeds,
`DirectTenantSnapshot` enters that customer's PostgreSQL RLS identity and
counts only active certificate rows for that tenant. The response distinguishes
healthy, suspended, offboarded, and no-active-certificate states. A customer
that does not exist returns 404; a storage failure returns 503; and the console
renders both as unknown/unavailable rather than showing zero as if it were a
measured fact. **Customer health** and **Invoice evidence** therefore name the
same selected customer while keeping lifecycle/count truth separate from the
signed billing period.
