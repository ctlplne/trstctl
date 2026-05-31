# Current limitations & what's not yet served

certctl is pre-1.0 and under active hardening. This page is the honest companion
to the capability list: it states plainly **what the running binary serves today**
versus **what is built and tested as library code but not yet wired into the
served product**, and which surfaces are explicitly Phase 2. Nothing here is
feature-gated — "open edition" and "commercial" run the same code; these are
maturity boundaries, not paywalls.

If a capability matters to your evaluation, check this page before relying on it.

## Served by the running binary today

`cmd/certctl` assembles and serves a control plane: the event log, projections,
orchestrator, and REST API, with the signing service supervised as a separate
out-of-process child (AN-4). What you can do end to end against the running binary:

- **Inventory and lifecycle** for owners, issuers, identities, and certificates —
  create, read, list (keyset-paginated), and drive the lifecycle state machine.
- **Real X.509 issuance**: transitioning an identity to *issued* mints a leaf
  certificate from the assembled CA (its key held in the out-of-process signer) and
  records it in inventory. This is exercised end to end in CI.
- **Authentication and RBAC** (API tokens and OIDC SSO sessions), **multi-tenancy**
  with PostgreSQL row-level security, and a **tamper-evident audit chain**.
- **Transport security** (TLS, internal or file-based), **idempotency** and the
  **outbox**, **observability** (`/metrics`, `/readyz`, W3C trace headers),
  **bulkheads + per-tenant rate limiting**, **backup/restore + disaster recovery**,
  and **safe schema migrations**.

The web UI and the `certctl-cli` drive this same served surface.

## Built and tested, but not yet served by the binary

These subsystems exist as **library code with real unit/integration/conformance
tests**, but are **not yet wired into the served API of the running binary**. They
are usable from Go today; "served, authenticated, end-to-end in the binary" is the
remaining integration work.

- **CA integrations** (9 under `internal/ca/`) and the **private CA hierarchy**
  (root/intermediate, cross-sign, rotation, and the m-of-n key ceremony — see the
  [key-ceremony runbook](runbooks/key-ceremony.md)).
- **Deployment connectors** (~10–11 under `internal/connector/`: nginx, Apache,
  IIS, HAProxy, F5, AWS ACM, Azure Key Vault, GCP Certificate Manager, NetScaler,
  Java keystore, plus Kubernetes). The lifecycle's `connector.deploy` step is
  acknowledged by the outbox but not yet routed to these in the served path.
- **Discovery**: network/filesystem scans, SSH key & trust inventory, agentless
  cloud-certificate enumeration, the **CBOM** with post-quantum posture, and
  **Certificate Transparency** monitoring.
- **Posture**: the **credential graph** (reachability, blast radius), **composite
  risk scoring**, and **drift detection**.

## Plugin isolation: first-party in-process, third-party sandboxed

This is a deliberate, documented trust boundary (not an accident):

- **Shipped first-party CA and connector integrations run as trusted in-process
  Go code** — they are *not* sandboxed through the WASM host. Their **blast radius**
  if one is defective is the control plane's address space: the DB connection pool
  (RLS-scoped) and the signer *client* handle (it can request signatures), but
  **not** the CA private key, which stays in the separate signer process (AN-4).
  They are mitigated by code review, the conformance suite, the connector SDK's
  capability-scoped `Sandbox` facade, and AN-7 bulkheads.
- **The WASM plugin host (`internal/pluginhost`, wazero) is real and is the
  isolation boundary for third-party plugins.** A loaded plugin has no ambient
  capabilities and only the host functions its grant permits; the host holds no DB
  pool or signer handle; and a deliberately misbehaving plugin is **proven
  contained** by test. Migrating the first-party integrations onto it is future
  work. See the [plugin trust model](security/threat-model.md).

## Protocols

- **ACME** server with **ARI**: all three domain-validation challenges are now
  validated **for real**, each failing closed — **HTTP-01** (RFC 8555 §8.3),
  **DNS-01** (§8.4, the `_acme-challenge` TXT digest), and **TLS-ALPN-01**
  (RFC 8737, the `acme-tls/1` `id-pe-acmeIdentifier` handshake) — behind a
  multiplexer with an automatic method selector (wildcards → DNS-01, no inbound
  `:80` → TLS-ALPN-01, else HTTP-01). The prior accept-everything validator has
  been **removed from the production build** (it survives only in the test
  binary). A DNS-01 solver with a reference provider and conformance harness ships
  for the publish side. Still outstanding: real hosted DNS providers
  (Route53/Cloudflare) and a **live Boulder/Pebble differential + cert-manager
  interop** run in CI; and the ACME server is **library code, not yet mounted in
  the served binary**.
- **EST**, **SCEP**, **SPIFFE** (Workload API), and the **SSH CA** issuance servers
  are Phase 2 — placeholders in `internal/protocols/`, correctly not served.

## Single sign-on (OIDC only)

certctl's interactive SSO is **OIDC only**: the UI and CLI authenticate against any
OpenID Connect provider (Microsoft Entra ID / Azure AD, Okta, Ping, Google, Auth0,
Keycloak, and the like), and API/CI access uses scoped API tokens. **SAML 2.0 is
not supported.** PRD F13 originally named SAML as a Phase-1 SSO method, but certctl
is **OIDC-only by decision** (R4.1): OIDC covers the modern identity-provider
landscape, and SAML's XML-signature handling is a security-sensitive surface we
chose not to carry. A SAML 2.0 Service Provider is a candidate for a future epoch —
it would route through the existing `internal/crypto` boundary (AN-3) — but it is
**not present today**, and no part of the product claims it is.

## CA key custody

The assembled issuing CA's key is now **persisted, sealed at rest** in the
signer's key store (R3.2): a signer restart **preserves** the CA instead of
silently rotating it, and the key survives across restarts. **HSM/KMS-backed
custody** (rather than a local sealed key file) and a served, m-of-n break-glass
flow are still future work — the key-encryption key is a local file by default.
See the [key-ceremony runbook](runbooks/key-ceremony.md),
[incident response](runbooks/incident-response.md), and
[disaster recovery](disaster-recovery.md).

## Kubernetes deployment

The control plane ships a production-shaped **Helm chart** (`deploy/helm/certctl`):
the API/UI with the **signing service isolated** (its own locked-down, network-
unreachable sidecar), external PostgreSQL and NATS as the default, a default-deny
`NetworkPolicy`, and TLS. Two things are **deliberately deferred to S15.1**:

- **A Kubernetes Operator.** A CRD-driven operator is planned (S15.1); today the
  Helm chart is the supported control-plane install.
- **Multi-replica HA.** The signer holds the CA key with a per-pod sealed key
  store and a UDS-only transport, so horizontal scaling needs a separate signer
  pod reached over **mTLS** — that network transport is not yet implemented, so the
  chart runs **one** control-plane replica. (The agent, separately, runs as a
  DaemonSet across all nodes.)

## How to read the roadmap against this

The [README capability table](https://github.com/imfeelingtheagi/certctl#capabilities)
describes what is **built and tested**; this page tells you what is **served by the
binary today**. When the two differ, this page is the authority for what you can
rely on at runtime.
