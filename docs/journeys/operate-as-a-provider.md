# Operate as a managed-service provider

<!-- trstctl:journey-census:start -->
!!! success "Served path — wiring census 81/81"

    The Definition-of-Done census reports **81/81 required capabilities served**: **12 of 81 census rows launch the shipped binary** and **69 of 81 are proved through the production-assembled handler**.
    Production-assembled means production `buildRunDeps` output driving the assembled `Server.Handler` in-process, with a hand-built `Deps` rejected; only the process launch differs.
    This journey uses no separately proof-gated capability row; it stays on core served surfaces.
    Core surfaces guarded by route and journey tests: `provider_plane`, `license_verification`, `tenant_rls`, `audit_export`.
    This badge is generated from `wiring-census.json`; `make journey-census-check` fails closed if the census or this page drifts.
<!-- trstctl:journey-census:end -->

## Goal

You run trstctl for several customers and want to manage them from one provider
plane without ever letting one customer's operator, data, or issuer reach another
customer. At the end of this journey you hold a licensed deployment, a provider
operator who signed in through your identity provider, two customer tenants that
only delegated operators can touch, one customer-scoped certificate lifecycle with
its metering evidence, and proof that the plane refuses what it must refuse. This
is for the operations lead of an MSP, an internal platform team selling a hosted
service to business units, or an evaluator checking those claims.

## Before you start

- An Enterprise Provider license from the vendor, installed the way
  [Plan and license](../editions.md) describes: a `0600` file supplied to both
  the control plane and the isolated signer with its bound deployment ID and
  environment. The provider plane is absent from an unlicensed build and stays
  read-only under a grace or expired posture.
- A provider-operator identity source pinned offline
  ([configuration](../configuration.md), `TRSTCTL_PROVIDER_OIDC_*` or the SAML
  service provider). Operators are identified by your identity provider; the
  plane maps a signed role claim to *provider admin* or *provider operator* and
  requires a signed MFA proof for every mutation.
- The partner lab ships both in its licensed profile
  (`deploy/demo/lab/README.md`), with a local identity provider whose operator
  sign-in page is `http://127.0.0.1:19081/provider/sign-in`.

## Steps

### 1. Confirm the entitlement

Open **Plan and license** (`/admin/editions`). The opening card must read
*Provider* with an *Active* state, and **Signature verification** must show the
offline signature verified against the vendor key and the deployment binding your
operator configured. If it reads Community, the binaries do not trust the key that
signed your license; if it reads Grace or Read-only, the plane refuses mutations.

### 2. Sign in as a provider operator

Open the console's **Provider** page (`/provider`). It offers the sign-in methods
your deployment pinned: SAML redirects to your identity provider; OIDC accepts the
bearer your identity provider issued to the operator (the lab's local provider shows
it once on its sign-in page). The token is held in memory only. `GET
/provider/v1/auth/session` answers who you are and which role and MFA state the
plane derived from the signed claims.

### 3. Bootstrap delegation once

Authority over customers is never granted through the API by someone who does not
already hold it. On the control-plane host, mint the first grants with the local
command and a stable idempotency key, naming each customer by the slug you will
provision in the next step (the command prints the tenant id it derived; a grant
over an existing tenant id also works):

```bash
trstctl provider-grant -operator op-1 -customer acme-robotics \
  -operations read,provision,suspend,resume -granted-by platform-admin \
  -idempotency-key acme-robotics-op-1-v1
```

An identical retry returns the same authority event; reusing the key with a
different grant is refused. Every grant names one customer and the operations it
covers; there is no wildcard customer. The operator id is the subject your
identity provider signs (`sub`).

### 4. Provision two customers

From the Provider page (or `POST /provider/v1/tenants` with an `Idempotency-Key`),
provision two customers with distinct slugs. Each becomes an isolated tenant with
its own row-level-security boundary, quota, health view, ownership, delegation
list, issuer selection, and alert routing. `GET /provider/v1/tenants` returns
only the customers delegated to the signed-in operator; the full roster is the
provider's commercial information and is never listed to an operator who is not
delegated to all of it.

### 5. Run one customer-scoped lifecycle

Acting for one customer, issue a certificate for a real endpoint, deploy it
through that customer's connector, verify it on the wire, and renew it: the same
journey as [Keep your existing CA](preserve-existing-ca.md), inside the customer's
boundary. The customer's endpoint is served by the customer's own agent, enrolled
with a token minted in the customer tenant, never by the provider's agent; in the
partner lab that is the customer listener on port 10449
(`deploy/demo/lab/README.md`). Then pull the customer's metering (`/provider/v1/tenants/{id}/quota` and
the provider evidence endpoints) as invoice evidence; the verification keys for
that evidence are published at `/provider/v1/evidence/verification-keys`.

### 6. Prove the refusals

- Revoke or let a delegation expire, then repeat a read or mutation for that
  customer: the plane answers *forbidden* and the audit trail records the refusal
  before any store write.
- Name the other customer's tenant from an operator not delegated to it: the
  answer is the same refusal with no hint that the tenant exists.
- An operator whose grant lacks `offboard` cannot offboard; offboarding is
  preview-only until a break-glass grant is used, and that grant is re-checked at
  use, not only at request time.
- A license bound to a different deployment ID, or an expired license, fails
  startup or drops the plane to read-only with sanitized language; it never widens
  access.

## What you have now

A licensed provider deployment with identity-provider-backed operators, customers
that only delegated operators can touch, one proven customer lifecycle with
metering evidence, and audited refusals at every boundary. Suspending, resuming,
and offboarding follow the same delegation rules; SCIM provisioning of your
workforce is available at `/provider/scim/v2` when enabled.

## See also

- [Plan and license](../editions.md) — entitlement, the vendor key, delegation rules
- [Configuration](../configuration.md) — `TRSTCTL_PROVIDER_*` settings
- [Onboard a team as a tenant](onboard-a-team.md) — what each customer tenant gets
- [Current limitations](../limitations.md)
