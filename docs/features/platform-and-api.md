# Platform & API — how you drive trstctl, and how it runs

## What it is

This page covers the "platform plumbing" — the surfaces you use to operate trstctl and
the properties of how it runs: the **REST API**, the **CLI**, the **web UI**, **OIDC
single sign-on**, **single-binary distribution**, **encrypted transport**, **multi-tenant
topology**, and **federation**. These aren't glamorous features, but they're what make
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
at `/api/v1/openapi.json`), and the CLI command table — so the spec, the server, and the
CLI can't drift apart. Errors are RFC 7807 `application/problem+json`. Every mutation
requires an [`Idempotency-Key`](../glossary.md), recorded in PostgreSQL so a retry returns
the original result instead of applying the change twice. Tenant comes from the
authenticated principal (so one tenant can never act on another's data), pagination uses
opaque cursors, and over-budget callers get `429` with `Retry-After`. **Served.**

### The CLI (F11)

`trstctl-cli` is the API's twin: every command is a row in a table that maps
`trstctl-cli <group> <verb>` straight to an API route, so the CLI is provably at parity
with the API and carries no bespoke logic. It auto-supplies idempotency keys on mutations.
Command groups: `owners`, `issuers`, `identities`, `certificates`, `profiles`, `audit`,
`graph`, `risk`, `agents`. **Served (binary).**

### The web UI (F12)

The UI is a React 18 + Vite + shadcn/ui single-page app **served by the binary** from
an embedded filesystem on the same port and TLS certificate as the API. Real hashed
asset files are served directly, deep links fall back to the SPA, and `/api/*` stays
owned by the API handler. No separate static server is required. **Served.** The embedded
`index.html` references the real Vite bundle, and tests fail if a clean build regresses to
the placeholder.

### OIDC single sign-on (F13)

People log in through **OIDC** (OpenID Connect) against any standards-compliant provider.
The authorization-code flow uses random `state` (CSRF protection) and a mandatory `nonce`
(replay protection); the returned id_token is verified — signature (via JWKS through the
single isolated cryptography path), issuer, audience, expiry, nonce — and on success
trstctl mints a short-lived, HMAC-signed, `HttpOnly`+`Secure` session cookie. That
session resolves to an [RBAC](policy-and-governance.md) principal, so a browser login
authorizes API calls. CI/CD instead uses API tokens (`trst_`-prefixed, only the SHA-256 hash
stored). **Served when `auth.oidc.enabled` is configured.** API tokens remain the default
auth path when OIDC is disabled; an enabled-but-incomplete OIDC block fails closed at
startup.

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
**[mTLS](../glossary.md)** with short-lived, auto-rotated client certificates. All
TLS/x509 code lives behind the single isolated cryptography path. **Served.**

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

Cross-cluster / multi-region **federation** — replicating the event log across regions,
placing credentials by residency, and replicating audit across regions — is **planned, not
yet built**. There is no federation code in the platform today; the design is scoped for a
future release, and when built it will rest on the same `tenant_id` per-tenant isolation
and event-log-replication foundations. We document it here, honestly, as roadmap rather
than a shipped capability. See [Current limitations](../limitations.md).

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

The web console, browser `/auth/login` flow, REST API, and CLI all drive the same
served control plane. API tokens are still the zero-dependency bootstrap path; OIDC
turns on only when configured. See [Current limitations](../limitations.md),
[Install](../install.md), and [Configuration](../configuration.md) for production setup.

## Pitfalls & limits

- **Federation (F41) is roadmap, not shipped** — don't design a multi-region topology
  around it yet.
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
- **CLI groups:** `owners`, `issuers`, `identities`, `certificates`, `profiles`, `audit`,
  `graph`, `risk`, `agents`.
- **Auth:** `/auth/login`, `/auth/callback`, `/auth/me`, `/auth/logout` (OIDC when
  `auth.oidc.enabled` is on); API tokens prefixed `trst_`. Config:
  `TRSTCTL_AUTH_OIDC_ISSUER`, `TRSTCTL_AUTH_OIDC_CLIENT_ID`,
  `TRSTCTL_AUTH_OIDC_REDIRECT_URI`.
- **Run modes:** `TRSTCTL_POSTGRES_MODE` (`bundled`/`external`), `TRSTCTL_NATS_MODE`
  (`embedded`/`external`), `TRSTCTL_SERVER_TLS_MODE` (`internal`/`file`/`disabled`).
- **Federation (F41):** planned, not implemented.

## See also

[Policy & governance](policy-and-governance.md) (RBAC + audit) ·
[Install](../install.md) · [Configuration](../configuration.md) ·
[Signing-service design](../design/signing-service.md) ·
[Current limitations](../limitations.md) ·
glossary: [idempotency](../glossary.md), [mTLS](../glossary.md),
[RLS](../glossary.md), [multi-tenancy](../glossary.md)

**Covers:** F10, F11, F12, F13, F14, F15, F40, F41
