# Platform & API — how you drive trstctl, and how it runs

## What it is

This page covers the "platform plumbing" — the surfaces you use to operate trstctl and
the properties of how it runs: the **REST API**, the **CLI**, the **web UI**, **OIDC,
SAML, and LDAP / Active Directory sign-on**, **SCIM 2.0 provisioning**,
**RBAC plus ABAC authorization controls**,
**single-binary distribution**, **encrypted transport**,
**multi-tenant topology**, and **federation**. These aren't glamorous features, but they're what make
trstctl usable, secure, and operable in a real organization.

The mental model: if the [feature pages](../features.md) are the appliances, this is the
wiring, the breaker box, the front door lock, and the meter — the infrastructure that lets
everything else run safely on shared premises.

## Why it exists

A control plane is only as good as how you interact with it and how safely it runs. You
need a programmable API for automation, a CLI for scripts and CI, a UI for humans, SSO so
people log in with existing accounts, encrypted channels so nothing is sniffable, hard
tenant isolation so customers can't see each other, and a distribution simple enough to
actually deploy. These are the table-stakes properties an enterprise checks before it
trusts a platform with its credentials.

## How it works

### The REST API (F10)

The API is **data-driven**: every route is declared once in a single registry that
simultaneously generates the served `http.ServeMux`, the **OpenAPI 3.1** document (served
at `/api/v1/openapi.json`), the CLI command table, and the Terraform provider route
constants for its managed resources — so the spec, the server, the CLI, and the
infrastructure-as-code surface can't drift apart. Errors are RFC 7807
`application/problem+json`. Every mutation
requires an [`Idempotency-Key`](../glossary.md), recorded in PostgreSQL so a retry returns
the original result instead of applying the change twice. Tenant comes from the
authenticated principal (so one tenant can never act on another's data), pagination uses
opaque cursors, and over-budget callers get `429` with `Retry-After`. Every guarded
route checks RBAC first; when `auth.abac.enabled` is configured, a deny-only ABAC
overlay can then block the request using route, actor, environment, and time attributes.
**Served.**

### The CLI (F11)

`trstctl-cli` is the API's twin: every command is a row in a table that maps
`trstctl-cli <group> <verb>` straight to an API route, so the CLI is provably at parity
with the API and carries no bespoke logic. It auto-supplies idempotency keys on mutations.
Command groups: `owners`, `issuers`, `identities`, `certificates`, `workloads`,
`broker`, `ephemeral`, `profiles`, `audit`, `privacy`, `graph`, `risk`, `cbom`,
`pqc`, `agents`, `secrets`, `managed-keys`, `transit`, `ai`, and `mcp`. **Served
(binary).**

### Terraform provider

`terraform-provider-trstctl` is built with the standard HashiCorp Terraform plugin
framework and ships as a normal trstctl binary. It manages certificate profiles through
`POST /api/v1/profiles`, issues short-lived certificates through
`POST /api/v1/secrets/pki`, and manages application secrets through
`/api/v1/secrets/store`. Each mutation sends an `Idempotency-Key`, uses the same bearer
token and tenant headers as the CLI, and is backed by provider tests plus a real
Terraform apply acceptance test. See [Terraform provider](../terraform-provider.md).
**Served (binary).**

### The web UI (F12)

The UI is a React 18 + Vite + shadcn/ui single-page app **served by the binary** from
an embedded filesystem on the same port and TLS certificate as the API. Real hashed
asset files are served directly, deep links fall back to the SPA, and `/api/*` stays
owned by the API handler. No separate static server is required. **Served.** The embedded
`index.html` references the real Vite bundle, and tests fail if a clean build regresses to
the placeholder.

### OIDC, SAML, and LDAP / Active Directory sign-on (F13)

People log in through **OIDC** (OpenID Connect), **SAML 2.0**, or **LDAP / Active
Directory** against a standards-compliant provider. OIDC uses the authorization-code flow with random `state`
(CSRF protection) and a mandatory `nonce` (replay protection); the returned id_token is
verified — signature (via JWKS through the single isolated cryptography path), issuer,
audience, expiry, nonce — before session issue. SAML serves a Service Provider at
`/auth/saml/metadata`, starts SP-initiated login at `/auth/saml/login`, and accepts
signed POST-binding assertions at `/auth/saml/acs`; IdP metadata and XML signature
verification stay behind the same isolated cryptography boundary. LDAP / Active
Directory mounts `POST /auth/ldap/login`, binds the user to the directory, searches
directory groups, and maps those groups to tenant roles. All three paths mint the same
short-lived, HMAC-signed, `HttpOnly`+`Secure` session cookie and resolve the verified
subject, tenant claim, or groups through the same per-user tenant-mapping table. CI/CD
instead uses API tokens (`trst_`-prefixed, only the SHA-256 hash stored). **Served when
`auth.oidc.enabled`, `auth.saml.enabled`, or `auth.ldap.enabled` is configured.** API
tokens remain the zero-dependency auth path when SSO is disabled; an
enabled-but-incomplete OIDC, SAML, or LDAP block fails closed at startup.

### SCIM 2.0 provisioning

Directory provisioning is served under `/scim/v2` when `auth.scim.enabled` is on.
An IdP such as Okta or Microsoft Entra sends a tenant-bound bearer token to
`/scim/v2/Users` and `/scim/v2/Groups`; trstctl hashes the configured token file at
startup and keeps only the hash in memory. The token chooses the tenant before any
payload is read, so a SCIM request cannot smuggle a tenant id in its JSON body.

SCIM users project into the same tenant-member read model used by RBAC. Creating or
updating a user appends a tenant-member upsert event; `active:false` or DELETE appends
an offboarding event. SCIM groups map to existing RBAC role names: a group named
`viewer` gives its members the `viewer` role, and removing a member removes that role.
Browser sessions consult the current tenant-member roles on each API request, so
SCIM provisioning and deprovisioning change real authorization, not just an admin list.
Supported IdP operations are SCIM Users create/get/list/put/patch/delete and Groups
create/get/list/patch/delete. **Served when `auth.scim.enabled` is configured.**

### Single-binary distribution (F14)

For evaluation, the one `trstctl` binary **can supervise its own datastores**: bundled
PostgreSQL (downloaded once, checksum-pinned, run on loopback) and embedded,
file-backed NATS JetStream. Bundled PostgreSQL is allowed only for host archives with
committed runtime pins in `deploy/supply-chain/embedded-postgres.json` (summarized in
[Supply chain](../supply-chain.md)) (`linux-amd64`, `linux-arm64v8`, `darwin-arm64v8`
today), and startup fails closed if
the archive is unsupported, unpinned, or hash-mismatched. Even bundled, Postgres runs
under the non-superuser `trstctl_app` role so row-level security still applies — per-tenant
isolation is enforced at the database layer even for eval, not relaxed. The
[signing service](../design/signing-service.md) is *always* a separate supervised child
process, never in-process — private-key operations stay in their own isolated service. For
production, flip Postgres/NATS to external. **Served (binary).**

### Encrypted control-plane transport (F15)

Every channel is encrypted. By default the signing service is reached over a **Unix
domain socket with `SO_PEERCRED`** peer-uid authentication (a 0600 socket; a different
uid is rejected); across nodes it is reached over **mTLS** (TLS 1.3, AEAD-only, the
control plane and signer each pinning the other's certificate). Either way the signing
service has no HTTP server and no SQL driver — it stays a separate, isolated process — and
at startup it disables core dumps and ptrace so secret material can't be read out of its
memory. The REST API/UI is served over **TLS** (self-signed by default for instant start,
operator cert in production, TLS 1.3, AEAD-only). Agents connect over
**[mTLS](../glossary.md)** with short-lived, auto-rotated client certificates. The
KMIP listener, when enabled, is also TLS 1.3 mutual TLS and verifies client
certificates against `TRSTCTL_PROTOCOLS_KMIP_CLIENT_CA_FILE`. All TLS/x509 code lives
behind the single isolated cryptography path. **Served.**

> Note: the default signer channel is a peer-authenticated UDS (co-located/sidecar);
> the cross-node channel is mutually-authenticated, mutually-pinned mTLS.

### Multi-tenant topology (F40)

Isolation between tenants is enforced **by PostgreSQL itself**, not by application code —
one tenant can never read another's data, and that guarantee lives at the database layer.
Every table carries a `tenant_id` and has [row-level security](../glossary.md) that denies
all rows when the tenant context is unset (fail-closed). `WithTenant` drops to the
non-superuser role and sets the tenant for the transaction, so every query is confined
automatically — and a custom build check *fails the build* if any repository query omits
the tenant filter. A single-company deployment simply runs one tenant.

### Federation (F41)

Cross-cluster / multi-region **federation** imports peer event logs into the local event
log, then projects those imported events through the same read-model projector as local
writes. That gives a passive region the same tenant registry, trust issuers, certificate
inventory, audit facts, and other replayable read state without adding another datastore
or copying PostgreSQL tables directly. Imported events keep their original event id,
timestamp, tenant id, payload, actor, and schema version, so retries are duplicate-safe
and the target region can rebuild from its own local log after failover.

The worker is off until an operator enables it. It runs under the existing leader
election, so one control-plane replica imports a peer while every replica can serve the
replicated read state. The peer cursor is durable per source cluster; a restart resumes
from the last imported source sequence. A typical passive region points at the primary
region's external NATS URL:

```sh
export TRSTCTL_FEDERATION_ENABLED=true
export TRSTCTL_FEDERATION_CLUSTER_ID=us-west-passive
export TRSTCTL_FEDERATION_REGION=us-west-2
export TRSTCTL_FEDERATION_PEER_ID=us-east-primary
export TRSTCTL_FEDERATION_PEER_REGION=us-east-1
export TRSTCTL_FEDERATION_PEER_NATS_URL=nats://nats.us-east.example:4222
export TRSTCTL_FEDERATION_INTERVAL=1s
export TRSTCTL_FEDERATION_RPO=5s
export TRSTCTL_FEDERATION_RTO=30s
```

The RPO target is the maximum import polling gap plus the health of the peer's
replicated JetStream stream. The RTO target is the time for the passive region to finish
local projection and accept traffic after you move clients or ingress. See
[Configuration](../configuration.md) and
[Run in production](../journeys/run-in-production.md).

## Use it

```sh
# the API spec (no auth needed) — point your tooling at it
curl -s https://trstctl.example.com/api/v1/openapi.json

# drive it from the CLI
trstctl-cli certificates list --limit 50
trstctl-cli audit events --type cert.issued --since 2026-01-01T00:00:00Z

# one-binary evaluation: bundled datastores, supervised signer
TRSTCTL_POSTGRES_MODE=bundled TRSTCTL_NATS_MODE=embedded ./trstctl
```

The web console, browser `/auth/login` flow, SCIM `/scim/v2` provisioning surface,
REST API, and CLI all drive the same served control plane. API tokens are still the
zero-dependency bootstrap path; OIDC, SCIM, and the ABAC deny overlay turn on only when
configured. See
[Current limitations](../limitations.md),
[Install](../install.md), and [Configuration](../configuration.md) for production setup.

## Pitfalls & limits

- **Federation is passive-read-state replication** — run one writable region for a
  tenant at a time, then promote a passive region during failover after its peer cursor
  and projection lag are inside your RPO/RTO target.
- **TLS defaults to self-signed** for instant start; set an operator cert
  (`TRSTCTL_SERVER_TLS_MODE=file`) for production. Plaintext mode requires
  `TRSTCTL_DEV_ALLOW_PLAINTEXT=true` and a loopback bind, so it is mechanically
  local-dev bounded.
- **Bundled datastores are for evaluation**; run external PostgreSQL and NATS in
  production.
- **The signer is a separate process by design** — don't try to collapse it in; keeping
  private-key operations in their own isolated process is a security boundary.

## Reference

- **API:** OpenAPI 3.1 at `GET /api/v1/openapi.json`; RFC 7807 errors; `Idempotency-Key`
  on mutations; cursor pagination; `429` + `Retry-After`; authenticated REST JSON
  request bodies are capped at 1 MiB and reject trailing JSON tokens.
- **CLI groups:** `owners`, `issuers`, `identities`, `certificates`, `workloads`,
  `broker`, `ephemeral`, `profiles`, `audit`, `privacy`, `graph`, `risk`, `cbom`,
  `pqc`, `agents`, `secrets`, `managed-keys`, `transit`, `ai`, and `mcp`.
- **Auth:** `/auth/login`, `/auth/callback`, `/auth/me`, `/auth/logout` (OIDC when
  `auth.oidc.enabled` is on); `/auth/saml/login`, `/auth/saml/acs`, and
  `/auth/saml/metadata` (SAML when `auth.saml.enabled` is on); `POST
  /auth/ldap/login` (LDAP / Active Directory when `auth.ldap.enabled` is on); API
  tokens prefixed `trst_`. Config:
  `TRSTCTL_AUTH_OIDC_ISSUER`, `TRSTCTL_AUTH_OIDC_CLIENT_ID`,
  `TRSTCTL_AUTH_OIDC_REDIRECT_URI`, `TRSTCTL_AUTH_SAML_ENTITY_ID`,
  `TRSTCTL_AUTH_SAML_ACS_URL`, `TRSTCTL_AUTH_SAML_IDP_METADATA_FILE`,
  `TRSTCTL_AUTH_LDAP_URL`, `TRSTCTL_AUTH_LDAP_GROUP_FILTER`.
- **SCIM provisioning:** `GET /scim/v2/ServiceProviderConfig`, `/scim/v2/Users`,
  and `/scim/v2/Groups` when `auth.scim.enabled` is on. Config:
  `TRSTCTL_AUTH_SCIM_ENABLED`, `TRSTCTL_AUTH_SCIM_TOKEN_TENANT_ID`,
  `TRSTCTL_AUTH_SCIM_TOKEN_FILE`.
- **Authorization overlays:** RBAC on every guarded route; ABAC deny overlay when
  `auth.abac.enabled` is on. Config: `TRSTCTL_AUTH_ABAC_ENABLED`,
  `TRSTCTL_AUTH_ABAC_MODULE`, `TRSTCTL_AUTH_ABAC_ENVIRONMENT`.
- **Run modes:** `TRSTCTL_POSTGRES_MODE` (`bundled`/`external`), `TRSTCTL_NATS_MODE`
  (`embedded`/`external`), `TRSTCTL_SERVER_TLS_MODE` (`internal`/`file`/`disabled`).
- **Federation (F41):** event-log import with durable peer checkpoints,
  duplicate-safe event identity, and local read-model projection.

## See also

[Policy & governance](policy-and-governance.md) (RBAC + audit) ·
[Install](../install.md) · [Configuration](../configuration.md) ·
[Signing-service design](../design/signing-service.md) ·
[Current limitations](../limitations.md) ·
glossary: [idempotency](../glossary.md), [mTLS](../glossary.md),
[RLS](../glossary.md), [multi-tenancy](../glossary.md)

**Covers:** F10, F11, F12, F13, F14, F15, F40, F41
