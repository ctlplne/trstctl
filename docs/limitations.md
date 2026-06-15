# Current limitations & what's not yet served

trustctl is pre-1.0 and under active hardening. This page is the honest companion
to the capability list: it states plainly **what the running binary serves today**
versus **what is built and tested as library code but not yet wired into the
served product**, and which surfaces are explicitly Phase 2. Nothing here is
feature-gated — "open edition" and "commercial" run the same code; these are
maturity boundaries, not paywalls.

If a capability matters to your evaluation, check this page before relying on it.

## Served by the running binary today

`cmd/trustctl` assembles and serves a control plane: the event log, projections,
orchestrator, and REST API, with the signing service supervised as a separate
out-of-process child (AN-4). What you can do end to end against the running binary:

- **Inventory and lifecycle** for owners, issuers, identities, and certificates —
  create, read, list (keyset-paginated), and drive the lifecycle state machine.
- **Real X.509 issuance**: transitioning an identity to *issued* mints a leaf
  certificate from the assembled CA (its key held in the out-of-process signer) and
  records it in inventory. This is exercised end to end in CI.
- **Authentication and RBAC** via **scoped API tokens** (sent as
  `Authorization: Bearer`), **multi-tenancy** with PostgreSQL row-level security,
  and a **tamper-evident audit chain**. A fresh boot fails closed (every route
  `401`s until a credential exists); mint the first tenant-scoped token on the host
  with `trustctl token create --tenant <uuid>` (it writes through the store and
  prints the token once). Interactive **OIDC SSO login is not yet wired into the
  served binary** (see "Single sign-on" below); API-token auth is the served path
  today.
- **Transport security** (TLS, internal or file-based), **idempotency** and the
  **outbox**, **observability** (`/metrics`, `/readyz`, W3C trace headers),
  **bulkheads + per-tenant rate limiting**, **backup/restore + disaster recovery**,
  and **safe schema migrations**.

The `trustctl-cli` drives this same served surface. The **React web console is not
yet shipped in the binary** (the embedded build is a placeholder) and **interactive
OIDC browser login is not yet wired** — both are covered under "Built and tested,
but not yet served" below; the served console+login wiring is tracked as
**`EXC-WIRE-01`** (auth/session) and **`EXC-WIRE-04`** (console + AI surface).

## Built and tested, but not yet served by the binary

These subsystems exist as **library code with real unit/integration/conformance
tests**, but are **not yet wired into the served API of the running binary**. They
are usable from Go today; "served, authenticated, end-to-end in the binary" is the
remaining integration work.

- **CA integrations** (9 under `internal/ca/`) and the **private CA hierarchy**
  (root/intermediate, cross-sign, rotation, and the m-of-n key ceremony — see the
  [key-ceremony runbook](runbooks/key-ceremony.md)).
- **Deployment connectors** (**13** under `internal/connector/`: nginx, Apache,
  IIS, HAProxy, F5, NetScaler, plus the network-appliance set Cisco, FortiGate, and
  Palo Alto, plus AWS ACM, Azure Key Vault, GCP Certificate Manager, and Java
  keystore — plus the Kubernetes destination). The lifecycle's `connector.deploy`
  step is acknowledged by the outbox but not yet routed to these in the served path.
- **Discovery**: network/filesystem scans, SSH key & trust inventory, agentless
  cloud-certificate enumeration, the **CBOM** with post-quantum posture, and
  **Certificate Transparency** monitoring.
- **SSH trust *rewrite* (the privileged `authorized_keys`/CA-trust mutator,
  `internal/agent/sshtrust`)**: the applier that installs a trusted SSH CA and
  rolls it back on failure is **fully built and well tested, but not linked into
  any binary** (SIGNER-004) — `cmd/trustctl-agent` does not import it, so the agent
  reads SSH trust (inventory, above) but does **not** rewrite a host's trust today.
  This is deliberately gated: weakening `sshd`/`authorized_keys` trust is a
  high-blast-radius mutation, so wiring it behind a default-off operator opt-in
  (with the signer-issued host/user certs and rollback) is tracked as
  **`EXC-WIRE-05`**. Until then the served/library split is: SSH trust is
  *discovered*, not *mutated*.
- **Posture**: the **credential graph** (reachability, blast radius), **composite
  risk scoring**, and **drift detection**.
- **The React web console (F12)**: the React 18 + Vite + shadcn/ui single-page app
  exists and is tested (Vitest/axe), but the `go:embed` bundle in a clean build is a
  hand-written placeholder, so a release artifact serves a "not built" page at `/`.
  The console — and the first-run wizard — are **built and tested, not yet served by
  the binary**. Wiring a real Vite bundle into the served binary is tracked as
  **`EXC-WIRE-04`**.
  - **No generated FE↔BE contract yet (SURFACE-005).** The frontend currently
    hand-duplicates the API types (`web/src/lib/api.ts`) rather than generating a
    client from `/api/v1/openapi.json`, so a server field change can silently
    desync the SPA — the audit caught one such drift (`certificate.status`), now
    aligned on both sides. As an interim guard, a **contract-drift test**
    (`internal/api` `TestCertificateContractFEMatchesBE`) fails CI if the FE
    `Certificate` type references a field the served OpenAPI `Certificate` schema
    does not define. Adopting a **generated** OpenAPI client (openapi-typescript /
    orval) with a CI regenerate-and-diff gate — the structural fix — is tracked as
    **`EXC-WIRE-04`**.
  - **Console UX hardening (SURFACE-007).** A **destructive-transition confirmation**
    (revoke/retire now require an explicit, credential-named confirm dialog) and
    **429/`Retry-After` handling** (the API client surfaces a concrete "retry in Ns"
    hint) have landed and are tested (`web/src/lib/api.test.ts`,
    `web/src/__tests__/lifecycle.test.tsx`). Still outstanding in the SPA:
    **cursor-based pagination** (the client reads only `.items` and ignores
    `next_cursor`) and **list virtualization** for large tables; both are tracked
    with the console wiring under **`EXC-WIRE-04`**.
- **Interactive OIDC browser login & sessions (F13)**: the authorization-code flow,
  id_token verification (signature/issuer/audience/nonce via the AN-3 JOSE
  boundary), and the HMAC-signed `HttpOnly`+`Secure` session cookie are implemented
  and tested as library code, but `api.WithAuth` is **not wired into the served
  composition**, so `/auth/login`, `/auth/callback`, `/auth/me`, and `/auth/logout`
  are **not served today** (only scoped API tokens authenticate the running binary).
  This is **built and tested, not yet served by the binary**; serving it is tracked
  as **`EXC-WIRE-01`**.
  - **Per-user tenant mapping is not yet wired (TENANT-004).** Even when the OIDC
    login flow is exercised, every browser user is currently mapped to a single
    configured `DefaultTenant` at session issue (`internal/api/auth.go`) — the code
    is honest that real per-user/per-claim tenant mapping is still to land. Storage
    multi-tenancy (PostgreSQL RLS) is real and confines each session to its assigned
    tenant, so this is **not a cross-tenant leak**; what is missing is the browser
    auth path distinguishing tenants, so **multi-tenant SaaS via the UI is not served
    end-to-end** yet. API tokens already carry a real per-token tenant. Mapping the
    OIDC subject/claims (an org/tenant claim or an IdP-group→tenant table) to the
    real tenant — and rejecting a no-tenant login — is tracked as **`EXC-WIRE-01`**.
- **The AI surface — model adapter (F76), grounded RCA / NL query (F77), and the
  MCP server (F78)**: these are real, tested **library** code (model-agnostic
  cloud/local adapter with a boundary redactor, grounded read-only RCA with
  citations, a read-only tenant-scoped MCP tool server). None is mounted in the
  served binary — there is **no served, authenticated AI/RCA/MCP endpoint today** —
  and the default is **no model** (AI is off unless one is configured). They are
  **built and tested, not yet served by the binary**; serving an authenticated,
  RBAC-guarded, tenant-scoped surface is tracked as **`EXC-WIRE-04`**. The boundary
  redactor strips key/secret material before any prompt reaches a model (AN-8), so
  even when wired, secret material does not egress.
- **The secrets/identity frameworks — the workload auth-method framework
  (`internal/authmethod`, F58), secret-sync to external stores
  (`internal/secretsync`, F60), the application secrets SDK (`internal/secretsdk`,
  F64), PKI-as-a-secret / dynamic certificate leasing (`internal/pkisecret`, F67),
  and secret sharing (`internal/secretshare`, F68)**: these are real, tested
  **library** code today. Each has **zero importers on the served path** — the
  running binary does not mount a secrets/identity API, so there is **no served,
  authenticated login/secrets endpoint for these five frameworks today**. They are
  **built and tested, not yet served by the binary**; wiring them into an
  authenticated, tenant-scoped served surface is tracked as **`EXC-WIRE-03`**.
  Library credentials are held as `[]byte` and never logged (AN-8); sessions and
  dynamic-secret revocations are event-sourced (AN-2); methods and providers are
  tenant-scoped (AN-1).

## Authorization policy gates: served on the issue/deploy/revoke path

As of **`EXC-WIRE-03`** the OPA/Rego default-deny policy gate, the RA scope split,
and dual-control approval are **enforced on the served mutating issuance path** of
the running binary — not just in library code. They gate the served lifecycle
transition (`POST /api/v1/identities/{id}/transitions`) for issue, deploy, and
revoke, fail-closed, before the orchestrator records the transition or enqueues the
mint/revoke effect. The gate is wired from `cmd/trustctl` → `internal/server`
(`server.Build` → `api.WithMutationGate`/`api.WithApprovals`), and is tenant-scoped
(AN-1), audited (AN-2), and runs the policy engine on its own bulkhead (AN-7).

- **Registration-authority (RA) separation & dual-control approval (SEC-002 — now
  served).** The served gate enforces the RA scope split: a privileged issue/revoke
  transition requires the `certs:issue` authority, so a `certs:request`-only
  requester (the `ra-officer`) **cannot self-issue** on the served path. When dual
  control is enabled (`ca.policy.require_approval`), a privileged action is denied
  until a **distinct** approver records an approval via
  `POST /api/v1/identities/{id}/approvals` (which itself requires `certs:issue`); a
  **self-approval is rejected** (the requester cannot approve their own request),
  backed by the RLS-isolated `issuance_approval_requests` / `issuance_approvals`
  tables. This is the served half of the RED-004 "loaded gun" defense (the bootstrap
  token already withholds `certs:issue`; the served mint now enforces the RA split +
  dual control too). The `internal/approval` package's full request→approve→issue
  state machine (notifications, time-bounded grants, JIT) remains the richer library
  model; the served gate enforces the core distinct-approver / no-self-issue invariant.
- **OPA/Rego policy gate — default-deny on issue/deploy/revoke (SEC-005 — now
  served).** With `ca.policy.enabled` set, the served binary invokes the policy
  engine (`internal/policy`) on every issue/deploy/revoke transition: the request is
  **denied unless the deployed Rego policy explicitly allows it** (default-deny,
  fail-closed). The policy input carries the action, `tenant_id`, the actor
  (authenticated principal), and the bound profile name, so an operator can enforce a
  real Rego document at runtime. A non-compiling policy module is a hard startup
  error, an evaluation error denies, and a saturated policy pool sheds with a 503
  (never an allow). The built-in base policy is default-deny, permits revocation, and
  requires a bound certificate profile to issue/deploy (composing with PKIGOV-002).
  Enforcement is **off by default** (`ca.policy.enabled=false`) so an in-place
  upgrade does not silently start denying; the RA scope split is enforced for
  privileged transitions regardless of this flag.

**Served-leaf profile enforcement (CORRECT-003 / PKIGOV-002).** Independently of the
policy flag, when a default certificate profile is bound (`ca.default_profile`) the
served mint validates the request against the active profile version and rejects an
out-of-profile request before signing (an `issuance.profile_evaluated` deny event) —
so the served mint is profile-gated, not ungated.

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
- **Plugin extensibility is library-only — not served by the binary yet
  (ARCH-007).** The WASM plugin host and the `plugins/ca` / `plugins/connectors`
  modules are **built and tested, not yet served by the binary**: nothing under
  `internal/server`, `internal/api`, or `cmd` imports `internal/pluginhost`, so the
  **running control plane cannot load a third-party plugin** — advertised
  **CA-via-plugin** and **connector-via-plugin** extensibility is not production
  capability today. The shipped first-party integrations run as trusted in-process
  Go (see above), not through the host. Wiring the plugin host into the served
  binary with enforced capability grants is tracked as **`EXC-WIRE-05`**.
- **No plugin signature/provenance verification yet (SUPPLY-004).** `Host.Load`
  instantiates the supplied `.wasm` bytes **without any signature, content-hash, or
  trusted-key check** — there is no cosign/Ed25519 verification step before a module
  runs. The exposure is **bounded today** because the load path is **library-only and
  unwired** (`Host.Load` has **zero non-test callers** in the served binary; the
  shipped first-party connectors run as trusted in-process Go via `NewGrant()`, not
  through the WASM host), and the wazero sandbox is real, tested defense-in-depth
  (the host holds no DB pool or signer handle). But the host's stated purpose is
  loading code the core team did not write, so before any **served** plugin surface
  is wired, `Load` must require a detached signature over the `.wasm` verified
  against an operator-configured trusted-key set and pin by content hash (keeping the
  sandbox as defense-in-depth). Adding that signature/provenance gate alongside
  wiring the served plugin surface is tracked as **`EXC-WIRE-05`**.

## Protocols

- **ACME** server with **ARI**: all three domain-validation challenges are now
  validated **for real**, each failing closed — **HTTP-01** (RFC 8555 §8.3),
  **DNS-01** (§8.4, the `_acme-challenge` TXT digest), and **TLS-ALPN-01**
  (RFC 8737, the `acme-tls/1` `id-pe-acmeIdentifier` handshake) — behind a
  multiplexer with an automatic method selector (wildcards → DNS-01, no inbound
  `:80` → TLS-ALPN-01, else HTTP-01). The prior accept-everything validator has
  been **removed from the production build** (it survives only in the test
  binary). A DNS-01 solver with a reference provider and conformance harness ships
  for the publish side. A **real RFC 8555 client conformance suite** now exercises
  HTTP-01 end to end (the production validator fetches the published key
  authorization; multi-SAN issuance; a wrong key authorization fails closed), and
  the same protocol-conformance routine runs as a **differential against Pebble**
  (the reference test ACME CA) in CI — so a divergence from the reference surfaces
  as a failure. Still outstanding: real hosted DNS providers (Route53/Cloudflare)
  and the **full cert-manager-in-kind enrollment** (a real in-cluster enrollment in
  CI), tracked for **Epoch 8b**. The ACME server is now **served by the running
  binary** (`EXC-WIRE-02`): it is mounted on the control-plane TLS listener at
  `/directory` + `/acme/...` and brokers issuance through the orchestrator-backed,
  signer-backed (AN-4), tenant-scoped (AN-1), event-sourced (AN-2), idempotent (AN-5),
  profile-gated path. A stock `golang.org/x/crypto/acme` client with an **ECDSA
  account key** drives the served handler end to end (new-account → new-order →
  http-01 → finalize) and downloads a real, signer-issued certificate; a served
  acceptance test asserts the cert verifies and a `certificate.recorded` event exists,
  then revokes via ACME `revokeCert` and asserts the served OCSP responder returns
  *revoked*. The directory advertises the mandatory `revokeCert` and `keyChange`
  resources, and the server accepts ECDSA and Ed25519 account keys (not only RSA).
  Enable/disable it with `protocols.acme.enabled` (default on); it activates only when
  an issuing CA is provisioned (a signer is configured) and fails closed otherwise.
- **EST** (RFC 7030), **SCEP** (RFC 8894), **CMP** (RFC 4210/6712), the **SPIFFE
  Workload API**, and the **SSH CA** issuance servers are **served end-to-end by the
  running binary** (`EXC-WIRE-02`), each behind the same signer-backed, tenant-scoped,
  event-sourced, idempotent, profile-gated issuance seam as the API mint:
  - **EST** at `/.well-known/est/...` (Bearer-API-token authenticated on top of TLS),
    **SCEP** at `/scep`, **CMP** at `/cmp` — mounted on the control-plane mux and
    exercised by served round-trip acceptance tests (a stock base64-PKCS#10 EST
    enroll, a CMS-enveloped SCEP `PKIOperation`, a CMP `p10cr`) that each download a
    real, signer-issued certificate verifying against the served CA and assert a
    `certificate.recorded` event (AN-2). SCEP/CMP use an in-process RSA *transport*
    key for CMS (deliberately **not** the CA key, which stays in the signer — AN-4).
  - the **SPIFFE Workload API** is served as a **gRPC service on a Unix domain
    socket** (`protocols.spiffe.enabled`), so a `spiffe-helper`/go-spiffe/Envoy-SDS
    client dials the socket and `FetchX509SVID` returns an SVID + trust bundle signed
    through the signer; a served acceptance test drives the SPIFFE Workload API wire
    protocol (with the mandatory `workload.spiffe.io` metadata) over the socket and
    validates the SVID. The Workload API protobuf/gRPC contract is vendored verbatim
    from go-spiffe so the wire format is byte-identical (no build-time go-spiffe
    dependency).
  - the **SSH CA** is served at `/ssh/...` (`protocols.ssh.enabled`): cert issuance
    plus the **OpenSSH binary KRL** at `/ssh/krl` (`sshd`'s `RevokedKeys` consumes it
    — INTEROP-009); a served acceptance test issues a user cert (verified with
    `ssh-keygen -L`), revokes it, and confirms the served KRL is the binary format.
    The SSH CA key lives in the signer under its own handle constrained to SSH-cert
    signing (AN-4).

  Each protocol is gated by `protocols.<name>.enabled` (ACME/EST/SCEP/CMP default on;
  SPIFFE and SSH default off — an operator opts those into a deployment) and binds a
  tenant via `protocols.<name>.tenant_id`; a protocol with no configured tenant fails
  closed at issuance (it must not mint into a blank tenant — AN-1). All protocols
  activate only when an issuing CA is provisioned.
  - **Reference-implementation differentials (TEST-002).** Two protocols are
    cross-checked against an *independent* implementation, not just our own parser:
    **ACME** runs a differential against **Pebble** (the reference test ACME CA) as a
    dedicated CI job, and **EST** runs a differential against the **OpenSSL** `pkcs7`
    parser/verifier on every `make test` (so `/cacerts` and `/simpleenroll` output is
    validated by code we did not write). The EST wire framing is *additionally*
    corroborated by an embedded C reference client that enrolls end to end. The
    **SPIFFE Workload API** has a **served round-trip differential**: a real
    Workload-API gRPC client (the go-spiffe-vendored protobuf contract, with the
    mandatory `workload.spiffe.io` metadata) fetches and validates an SVID over the
    served UDS. What is **not yet wired** as a *dedicated CI job*: the **libest**
    `estclient` differential is opt-in/local only (it runs when an operator sets
    `EST_LIBEST`; no workflow ships the binary), and SCEP/CMP have served round-trip
    acceptance tests but no external-reference (sscep / OpenSSL-cmp) differential CI
    job yet — those reference cross-checks are tracked under **`EXC-GATE-01`**.
  - **SSH KRL distribution format (INTEROP-009).** The SSH CA's key-revocation list is
    now emitted in the **OpenSSH binary KRL format** (`KRL.DistributeKRL`), the artifact
    `sshd`'s `RevokedKeys` and `ssh-keygen -Q -f` consume — verified end-to-end by a test
    that has stock `ssh-keygen` report a revoked certificate as revoked using trustctl's
    KRL (and a non-revoked one as valid). The legacy JSON `Snapshot` (`Distribute`) is
    retained for programmatic callers. The SSH CA is now **served** (`EXC-WIRE-02`,
    `protocols.ssh.enabled`): cert issuance at `/ssh/...` and the binary KRL at
    `/ssh/krl`, the artifact a host's `RevokedKeys` consumes.
  - **Public-CA profile linter (PKIGOV-009).** Issued certificates are checked by an
    in-tree **structural RFC 5280 / CA-Browser-Forum profile linter**
    (`internal/ca/profilelint`) in the issuance test suite — version, serial bounds,
    validity ordering/length, basicConstraints, key usage, SAN presence, SKI/AKI
    presence, weak-signature and minimum-key-strength checks — and the suite is **red on
    a deliberately-broken profile**. What is **not yet wired** is an *external* public-CA
    linter (**zlint**/**certlint**) as a dedicated CI gate over a sample of every emitted
    profile; standing that up (vendoring/pinning the tool and running it on issued
    fixtures) is tracked as **`EXC-GATE-01`**.
- **SPIFFE transport (Workload API):** the SVID *document* is spec-shaped (a single
  `spiffe://` URI SAN, correct key usage), and the Workload API is now **served as a
  gRPC service on a Unix domain socket** (`EXC-WIRE-02`, `protocols.spiffe.enabled`),
  so a `spiffe-helper`/go-spiffe/Envoy-SDS workload dials the socket and
  `FetchX509SVID` returns an SVID + trust bundle signed through the signer (AN-4). The
  SVID's workload key is minted server-side and returned in the response (per the
  spec); the X.509-SVID CA is the served issuing CA in the signer and the JWT-SVID
  signing key has its own signer handle. The Workload-API gRPC/protobuf contract is
  vendored verbatim from go-spiffe so the wire format is byte-identical without a
  build-time go-spiffe dependency.
- **Agent ↔ control-plane mTLS gRPC channel (WIRE-004 / OPS-005):** the in-network
  agent's mutual-TLS gRPC transport (`internal/agent/transport`,
  `internal/crypto/mtls`) is built and tested, but it is **library-only and not yet
  served by the binary**: the transport registers **only the standard health
  service** — there are no agent RPCs yet — and **no agent gRPC listener is mounted**
  in `internal/server` (the only served `grpc.Server` is the signer's UDS). So
  although the served `POST /enroll/bootstrap` route mints an **agent mTLS** client
  certificate, there is **no served channel for that agent to connect to** in a real
  deployment. The shipped fleet manifests reflect this gap, not a served port:
  `deploy/kubernetes/daemonset.yaml` points agents at `trustctl.trustctl.svc:9443`
  and the Windows MSI uses `--server …:9443`, but the **control-plane Service exposes
  only the API port `8443`** — there is **no control-plane Service/NetworkPolicy on
  `9443`** (the only `:9443` in the chart belongs to the *isolated signer* topology,
  which is itself not-yet-implemented — see "Multi-replica HA"). So the advertised
  steady-state agent channel (fleet rotation push, drift reporting) is **not
  exposed by the shipped artifacts** (OPS-005). Additionally, the agent CA is
  **in-process and regenerated per boot** today (a deliberate, self-disclosed
  stand-in at `internal/crypto/mtls` — see AN-4): until its key is custodied by the
  signer, an agent's **pinned CA would change on every control-plane restart**.
  Storage multi-tenancy still confines everything (AN-1), so this is a
  **served-vs-library / availability gap, not a tenant leak**. Mounting the agent
  gRPC listener (with the agent RPCs, a control-plane Service + NetworkPolicy on the
  agent port, signer-custodied CA, and cert-derived tenant) is tracked as
  **`EXC-WIRE-02`**.

## Revocation

Revoking a credential through the running binary is **real and recorded**, not a
no-op. Transitioning an identity to *revoked* drives the served outbox handler to:

- mark the issued certificate **revoked in the inventory** — via a projected
  `certificate.revoked` event (AN-2), so the status is reconstructable from the
  log on a `Rebuild()`, and the certificate API now returns `status` /
  `revoked_at` / `revocation_reason` so the revocation is **visible** on the
  served surface (a revoked cert reads `"revoked"`, not silently `"active"`); and
- record the certificate's serial in the **revocation store** (`ca_issued_certs`)
  that backs OCSP/CRL.

The **online revocation-distribution surface is now served** (`EXC-REVOKE-01`):
the running binary mounts an RFC 6960 **OCSP responder** at `/ocsp/{tenant}` (GET
base64-in-path and POST `application/ocsp-request`) and an RFC 5280 **CRL
endpoint** at `/crl/{tenant}`, and runs a background **freshness scheduler** that
regenerates each tenant's CRL ahead of its `nextUpdate`. A query for a revoked
serial returns `revoked` over OCSP and the serial appears on the CRL within the
freshness window; a query for an issued-but-not-revoked serial returns `good`; an
unknown serial returns a signed `unknown`. These endpoints are **public by RFC
design** (relying parties check status without credentials) but run on the API
bulkhead pool, so an OCSP/CRL flood sheds rather than starving the rest of the
control plane (AN-7).

OCSP responses and CRLs are **signed through the out-of-process signer** (AN-4):
the signing op crosses the `internal/crypto` boundary (`SignOCSPResponse` /
`CreateCRL`) using the same signer-held CA key (a purpose-bound `RemoteSigner`)
the leaf path uses, so the CA private key **never materializes in the control
plane** — only the digest crosses. Every query is tenant-scoped under RLS (AN-1),
and each published CRL emits a `ca.crl.published` event (AN-2).

This is exercised end to end in CI (issue → revoke → assert OCSP returns
`revoked` (and `good` before revocation) and the CRL lists the serial within the
freshness window, with both signatures verifying against the issuing CA, driven
over real HTTP against the assembled binary and the real out-of-process signer).

The **CDP/AIA pointers** stamped on issued leaves are operator-configured
(`TRUSTCTL_CA_CRL_DISTRIBUTION_POINTS` / `_OCSP_SERVERS`, PKIGOV-001) because the
externally reachable URL is deployment-specific; point them at the binary's
`/ocsp/{tenant}` and `/crl/{tenant}` (behind your ingress) so relying parties
discover and fetch revocation status automatically. trustctl revocation is now
both authoritative in the product's own inventory/records **and** publishable to
external relying parties over served OCSP/CRL.

## Single sign-on (OIDC only)

trustctl's interactive SSO is **OIDC only**: the UI and CLI authenticate against any
OpenID Connect provider (Microsoft Entra ID / Azure AD, Okta, Ping, Google, Auth0,
Keycloak, and the like), and API/CI access uses scoped API tokens. **SAML 2.0 is
not supported.** PRD F13 originally named SAML as a Phase-1 SSO method, but trustctl
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

**In-memory custody of the reference-path CA keys (CRYPTO-005 / SIGNER-008).** The
library-tier private-CA hierarchy (`internal/crypto/ca`) now holds its live ECDSA
signing keys in **locked secret buffers** (mlock + `MADV_DONTDUMP`, AN-8) rather than
as a bare `*ecdsa.PrivateKey` on the Go heap for the lifetime of the in-process CA;
the key is reconstructed only for the instant of each signature and the transiently
parsed copy is best-effort zeroized afterward (the same hardening applied to the
signer's `LockedSigner`, SIGNER-008). This narrows — but, given Go's runtime, does
not eliminate — the window in which an unprotected key sits in dumpable heap; it is
complemented process-wide by `RLIMIT_CORE=0` / `PR_SET_DUMPABLE=0`. The durable fix,
**HSM/signer custody so the CA key never materializes in the control-plane address
space at all**, is tracked as **`EXC-CRYPTO-01`**.

**Signer UDS peer-uid is Linux-only (WIRE-009 / SIGNER-006).** The signing service's
Unix-domain-socket listener authenticates the connecting process's uid via
`SO_PEERCRED`, which exists only on **Linux** — the supported production target
(Docker/Helm). On non-Linux hosts the peer-uid layer is unavailable and the access
control is the `0700` socket directory + `0600` socket alone; the listener accepts a
connection whose uid it cannot determine. This is defense-in-depth, not the primary
control, and the rejection path is now covered by tests so a regression that breaks
the uid comparison is caught in CI.

## Post-quantum cryptography (issuance algorithms)

trustctl's cryptography sits behind one boundary (AN-3, `internal/crypto`), and the
post-quantum support lives there — ML-DSA, ML-KEM, and the hybrid scheme in
`internal/crypto/pqc`, and SLH-DSA in `internal/crypto/slhdsa.go` — all built on
Cloudflare's CIRCL. What is available today:

- **ML-DSA** (FIPS 204; `mldsa44` / `mldsa65` / `mldsa87`) — the NIST-standard
  lattice signature.
- **ML-KEM** (FIPS 203; `mlkem512` / `768` / `1024`) — the NIST-standard key
  encapsulation.
- **SLH-DSA / SPHINCS+** (FIPS 205; `SLH-DSA-SHA2-128s` / `128f` / `192s` / `256s`) —
  the NIST-standard stateless **hash-based** signature, delivered in the Epoch 14
  post-quantum-migration work. Its security rests only on the hash function, so it is
  the conservative choice for long-lived roots where you want assumptions independent
  of the lattice schemes; the trade-off is much larger signatures.
- **A hybrid signature** (`HybridEd25519Dilithium3`) — classical Ed25519 paired with
  ML-DSA, so breaking either component alone does not forge a signature.

Private key material is held in locked, zeroized buffers (AN-8) and parsed only for
the moment of each operation, exactly like classical keys. The discovery side knows
these algorithms too — the **CBOM** scanner recognizes ML-DSA, ML-KEM, and
SLH-DSA / SPHINCS+ as quantum-safe when it finds them in your estate. Because all
cryptography enters through the single AN-3 boundary, each scheme is a contained,
one-package registration (a CIRCL scheme plus known-answer tests), with no ripple
into the rest of the system.

What is **not yet** end-to-end is PQC *issuance through every enrollment protocol* and
the fully automated, fleet-wide **migration orchestration** — the crypto primitives
are in place and the migration tooling is being built out. See
[Lifecycle & PQC](features/lifecycle-and-pqc.md) for the current state of that
tooling (F57).

## Kubernetes deployment

The control plane ships a production-shaped **Helm chart** (`deploy/helm/trustctl`):
the API/UI with the **signing service isolated** (its own locked-down, network-
unreachable sidecar), external PostgreSQL and NATS as the default, a default-deny
`NetworkPolicy`, and TLS. Two things are **deliberately deferred to S15.1**:

- **A Kubernetes Operator.** A CRD-driven operator is planned (S15.1); today the
  Helm chart is the supported control-plane install.
- **Multi-replica HA.** The signer holds the CA key with a per-pod sealed key
  store and a UDS-only transport, so horizontal scaling needs a separate signer
  pod reached over **mTLS** — that network transport is not yet implemented, so the
  chart runs **one** control-plane replica with a `Recreate` rollout (RESIL-002). A
  node failure or a config rollout takes issuance/validation offline until the pod
  reschedules; the datastores (external Postgres + replicated NATS) hold durability,
  so this is an availability gap, not data loss. The supported HA posture today is
  **fast failover of a single active replica** (run it under a Deployment, keep the
  datastores replicated). When the isolated-signer transport lands, active/active
  needs `replicaCount >= 2` behind a shared isolated signer **plus leader election**
  gating the background workers (outbox dispatcher, audit retention,
  idempotency/outbox GC, projection tailer) so only one replica runs them — tracked
  under RESIL-004 / EXC-RESIL-01. See
  [disaster recovery → High availability](disaster-recovery.md). (The agent,
  separately, runs as a DaemonSet across all nodes.)

## How to read the roadmap against this

The [README capability table](https://github.com/imfeelingtheagi/trustctl#capabilities)
describes what is **built and tested**; this page tells you what is **served by the
binary today**. When the two differ, this page is the authority for what you can
rely on at runtime.
