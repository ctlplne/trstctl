# Current limitations & what's not yet served

trstctl is pre-1.0 and under active hardening. This page is the honest companion
to the capability list: it states plainly **what the running binary serves today**
versus **what is built and tested as library code but not yet wired into the
served product**, and which surfaces are explicitly Phase 2. Nothing here is
feature-gated — "open edition" and "commercial" run the same code; these are
maturity boundaries, not paywalls.

If a capability matters to your evaluation, check this page before relying on it.

## Served by the running binary today

`cmd/trstctl` assembles and serves a control plane: the event log, projections,
orchestrator, and REST API, with the signing service supervised as a separate
out-of-process child (AN-4). What you can do end to end against the running binary:

- **Inventory and lifecycle** for owners, issuers, identities, and certificates —
  create, read, list (keyset-paginated), and drive the lifecycle state machine.
- **Connector delivery and lifecycle rotation evidence**: deployment attempts emit
  `connector.delivery.recorded` receipts, scheduled renewals emit
  `lifecycle.rotation.recorded` runs, and both are readable through the API, CLI,
  and console. The receipt is routing/status metadata only: no private key or secret
  bytes are returned.
- **Discovery control plane + network scan execution**: the running binary serves
  discovery sources, schedules, and runs under `/api/v1/discovery/*` — create/list a
  source, create/list a schedule, queue a run (idempotent, AN-5), and read runs and
  findings (keyset-paginated). Queuing a run is **event-sourced**
  (`discovery.run.queued`, AN-2) and records its scan **intent** in the outbox
  (AN-6); an outbox worker then **executes** the run. For a **network** source the
  served worker runs a real `netscan` certificate sweep over the configured
  targets/CIDRs (bounded workers/queue, AN-7), records discovered certificates into
  inventory and findings, and completes the run; a **manual** source records its
  supplied findings. The **other collectors** — SSH key/trust scan, agentless
  cloud-certificate enumeration, Certificate Transparency monitoring, and CBOM — are
  **not** wired into the served worker; see the Discovery bullet under "Built and
  tested, but not yet served" below.
- **Credential-compromise incident execution**: `POST /api/v1/incidents/executions`
  drives a served, idempotent (AN-5), event-sourced (AN-2) single-identity
  remediation — replacement issue/deploy, revocation, blast-radius capture, and a
  sealed evidence pack readable via `GET /api/v1/incidents/executions{,/{id}}`.
  *Fleet-wide* re-issuance and m-of-n break-glass are not this surface; they remain
  library/API-only (see "Incident response" notes below).
- **Real X.509 issuance**: transitioning an identity to *issued* mints a leaf
  certificate from the assembled CA (its key held in the out-of-process signer) and
  records it in inventory. This is exercised end to end in CI.
- **Authentication and RBAC** via **scoped API tokens** (sent as
  `Authorization: Bearer`), **multi-tenancy** with PostgreSQL row-level security,
  and a **tamper-evident audit chain**. A fresh boot fails closed (every route
  `401`s until a credential exists); mint the first tenant-scoped token on the host
  with `trstctl token create --tenant <uuid>` (it writes through the store and
  prints the token once). Interactive **OIDC SSO login is served by the binary**
  when `auth.oidc.enabled` is set (see "Single sign-on" below): the browser
  authorization-code flow mints an `HttpOnly` session cookie that authorizes API
  calls under the **same RBAC + per-tenant RLS scoping** as an API token, and each
  user is mapped to its real tenant (`EXC-WIRE-01`). API-token auth remains the
  default when OIDC is disabled.
- **Transport security** (TLS, internal or file-based), **idempotency** and the
  **outbox**, **observability** (`/metrics`, `/readyz`, W3C trace headers),
  **bulkheads + per-tenant rate limiting**, **backup/restore + disaster recovery**,
  and **safe schema migrations**.

The `trstctl-cli` drives this same served surface. **Interactive OIDC browser
login + sessions are served by the binary** (`EXC-WIRE-01`, behind
`auth.oidc.enabled`) — see "Single sign-on" below. The **React web console is now
shipped in the binary** (`EXC-WIRE-04`): a clean `go build ./cmd/trstctl` embeds the
real built Vite bundle and serves it at `/`, and the frontend's API types are
**generated from the served OpenAPI contract** so they cannot silently drift
(SURFACE-001/005). The **AI/RCA/MCP** surface — once the remaining tail of
`EXC-WIRE-04` — is **now served too** (`SURFACE-003`, behind `ai.enable_api`); see its
section below.

### Tenant offboarding boundary

Tenant offboarding erases **PostgreSQL read state** for the target tenant:
`OffboardTenant` deletes every tenant-scoped table under that tenant's RLS context,
verifies zero residue, and returns a deletion attestation. The
`tenant.offboarded` event is replayed by projections, so a read-model rebuild does
not resurrect the tenant's PostgreSQL rows.

That is the TENANT-owned boundary. It is not a promise that the append-only event log
or a signed **audit archive** disappears when a tenant is offboarded. Those records
are governed by audit/privacy retention policy: configure
`TRSTCTL_AUDIT_RETENTION` plus `TRSTCTL_AUDIT_ARCHIVE_DIR` for archive-then-prune
of audit records, and use **Privacy Retention** for non-audit personal data
pseudonymization. WORM/object-store archive cleanup and legal hold decisions remain
operator privacy/compliance work, described in [compliance](compliance.md) and
[configuration](configuration.md).

## Built and tested, but not yet served by the binary

These subsystems exist as **library code with real unit/integration/conformance
tests**, but are **not yet wired into the served API of the running binary**. They
are usable from Go today; "served, authenticated, end-to-end in the binary" is the
remaining integration work.

- **CA integrations** (9 under `internal/ca/`) and the **private CA hierarchy**
  (root/intermediate, cross-sign, rotation, and the m-of-n key ceremony — see the
  [key-ceremony runbook](runbooks/key-ceremony.md)).
- **Deployment connector implementation bodies** (**13** under `internal/connector/`:
  nginx, Apache, IIS, HAProxy, F5, NetScaler, Cisco, FortiGate, Palo Alto, AWS ACM,
  Azure Key Vault, GCP Certificate Manager, and Java keystore). The running binary
  serves the connector catalog and delivery receipts. Actual target mutation is
  routed only when a provenance-verified signed connector plugin is loaded; otherwise
  `connector.deploy` is acknowledged as an `unrouted` receipt with the reason.
- **Discovery scanners/collectors other than network scan**
  (`internal/discovery/{sshscan,cloudcert,ctmonitor}`): SSH key & trust inventory,
  agentless cloud-certificate enumeration, the **CBOM** with post-quantum posture, and
  **Certificate Transparency** monitoring. These collector packages have **no
  importer on the served path** and are library-only. (The **network** collector,
  `internal/discovery/netscan`, *is* wired into the served discovery worker — see
  "Discovery control plane + network scan execution" above — so a queued *network*
  run is executed end-to-end by the binary; the collectors named here are not.)
- **SSH trust *rewrite* (the privileged `authorized_keys`/CA-trust mutator,
  `internal/agent/sshtrust`)**: the applier that installs a trusted SSH CA and
  rolls it back on failure is now **wired into `cmd/trstctl-agent`** behind a
  **default-off operator opt-in** (`--ssh-trust-add-ca`) that additionally requires
  **explicit confirmation** (`--ssh-trust-confirm`) before it will rewrite trust
  (SIGNER-004, EXC-WIRE-05). The op is **additive** (it never removes existing
  trust), validates the new config with `sshd -t`, reloads, runs a separate
  operator-supplied post-reload health command (`--ssh-trust-health-cmd`), and
  **auto-rolls-back** to the last-known-good on any failure — so a bad rewrite
  cannot lock operators out. Reload success alone is not treated as health. Because
  weakening `sshd`/`authorized_keys` trust is a high-blast-radius
  mutation, the feature stays off unless the operator turns it on and confirms;
  with the flag off the agent only *discovers* SSH trust (inventory, above), it
  does not *mutate* it. Trust *removal* still requires its own explicit confirmation
  (the safe default, SIGNER-007).
- **Posture collectors and agents:** CT monitoring, CBOM scanning triggers, drift
  detection loops, and the **non-network discovery collectors** (SSH/cloud-cert/CT)
  remain library/agent work — the discovery *control surface* and the **network**
  scan executor are served (above), but the other collector kinds are not yet driven
  by the served worker. The **credential
  graph** and **risk scoring** read APIs are already served (`/api/v1/graph*`,
  `/api/v1/risk/credentials`), and the **AI/RCA/MCP** surface is served behind
  `ai.enable_api`; they are not part of this not-yet-served bucket.
- **React console scale work:** the console itself is served (see "The React web
  console" below). What remains not yet served of the original F12 epic is cursor
  pagination and list virtualization for very large tables (SURFACE-007).

## The React web console: served by the binary

As of **`EXC-WIRE-04`** the React 18 + Vite + shadcn/ui single-page app (F12) is the
**real embedded artifact the running binary serves**, closing SURFACE-001/005/006:

- **The shipped binary serves the real console.** `make web` (run in CI and the
  release pipeline) builds the SPA into `internal/webui/dist`, which the binary embeds
  via `//go:embed`; the built bundle is committed, so even a plain
  `go build ./cmd/trstctl` (no `make web` step) serves the real console at `/` —
  hashed `/assets/index-*.{js,css}` and an `index.html` that references them — not the
  old "not built" placeholder. A Go test boots the served handler over the real embed
  and fails if it ever regresses to the placeholder
  (`internal/webui` `TestServedRootIsTheRealConsoleNotThePlaceholder`,
  `TestServedHashedAssetsResolve`); the release gate `TestEmbeddedUIIsARealBuild`
  (set `TRSTCTL_REQUIRE_BUILT_UI=1`, run by `make web` and the release job) blocks a
  release that would embed the placeholder.
- **Generated FE↔BE contract (SURFACE-005).** The frontend's API types are **generated
  from the served OpenAPI contract**, not hand-duplicated: `web/scripts/gen-api-types.mjs`
  emits `web/src/lib/api-types.gen.ts` from the spec golden
  (`internal/api/testdata/openapi.golden.json`, pinned == the live served spec by
  `TestOpenAPIGolden`), and `web/src/lib/api.ts` re-exports those types so a backend
  field add/rename/remove that is not regenerated fails `tsc`. A CI regenerate-and-diff
  gate (`npm run gen:api -- --check`, plus the Go `TestGeneratedFETypesMatchServedContract`
  and the Vitest `contract.test.ts`) fails the build on drift — the `certificate.status`
  drift the audit caught can no longer recur silently.
- **Operational console routes (SURFACE-004).** The console has first-class routes,
  nav entries, typed API wrappers, and Vitest route coverage for the GA operator slice:
  **Profiles** (`/profiles`, profile list + create), **Graph** (`/graph`, graph inventory
  + blast-radius query), **Audit** (`/audit`, audit-event list + evidence export),
  **dual-control approvals** from the identity table, **incident execution** (`/incidents`,
  replacement issue/deploy, revocation queue, connector receipt, rollback evidence, and
  sealed audit bundle), and the existing
  **Assistant/RCA/MCP** console (`/assistant`). Deliberately **API-only / library-only**
  surfaces remain labeled here until they receive their own served UI: fleet
  reissuance/break-glass workflows, secret-sync dispatch, connector-driven deploy
  actions, discovery scan scheduling, and very-large-list cursor/virtualized browsing.
- **Console UX hardening (SURFACE-007).** A **destructive-transition confirmation**
  (revoke/retire require an explicit, credential-named confirm dialog) and
  **429/`Retry-After` handling** (the API client surfaces a concrete "retry in Ns"
  hint) are served and tested (`web/src/lib/api.test.ts`,
  `web/src/__tests__/lifecycle.test.tsx`). Still outstanding in the SPA:
  **cursor-based pagination** (the client reads only `.items` and ignores
  `next_cursor`) and **list virtualization** for large tables; both remain tracked
  under **`EXC-WIRE-04`**.

## Interactive OIDC browser login & sessions: served by the binary

As of **`EXC-WIRE-01`** the OIDC authorization-code login + sessions are **served by
the running binary** (behind `auth.oidc.enabled`), closing SEC-001/WIRE-001/
SURFACE-002. The composition wires `api.WithAuth` from `cmd/trstctl` →
`internal/server` (`server.Build`), so the served control plane mounts the `/auth/*`
routes (the IdP redirect, the callback, the current-principal endpoint, and logout).
The callback verifies the id_token's **signature, issuer, audience, nonce, and
temporal claims (exp/nbf/iat)** through the AN-3 JOSE boundary (`internal/auth`),
then sets an **`HttpOnly` + `SameSite=Strict` session cookie** (marked `Secure`
whenever the control plane serves TLS) plus a **double-submit CSRF token** (SEC-007).
A session cookie authorizes API calls under the **same RBAC + per-tenant RLS
scoping** as an API token; mutations on the cookie path require the CSRF header. When
`auth.oidc.enabled` is false the binary authenticates with scoped API tokens only,
exactly as before; an enabled-but-misconfigured block **fails closed at startup**.

- **Per-user → tenant mapping is served (TENANT-004 — now served).** Each
  authenticated user is mapped to its **real tenant** at session issue — by a
  configurable id_token claim (`auth.oidc.tenant_claim`, optionally used directly as
  the tenant id), by an IdP-group → tenant table, or by an explicit
  subject/claim/group → tenant mapping (`auth.oidc.tenant_mappings`) — instead of
  collapsing every browser user to one tenant. A user that maps to **no tenant is
  rejected** (the login fails closed, never minting a session in a fallback tenant
  unless an operator explicitly opts into `allow_default_tenant`). PostgreSQL RLS
  then confines each session to its mapped tenant (AN-1), so two OIDC users in
  different tenants see only their own data via the served API. The legacy single
  `DefaultTenant` is retained only as that opt-in fallback. This is the served half
  of the RED-004 defense for tenant isolation; a freshly logged-in user still cannot
  self-issue (issuance stays behind the `EXC-WIRE-03` RA/policy gate and the
  requester scope excludes `certs:issue`).
- **The AI surface — model adapter (F76), grounded RCA / NL query (F75/F77), and the
  read-only MCP tool server (F78) — now SERVED (`SURFACE-003`).** As of `SURFACE-003`
  the AI surface is **mounted on the running binary** under `/api/v1/ai/*` and
  `/api/v1/mcp/*` (off by default — `ai.enable_api` — and **fail-closed** when off, so
  an upgrade does not silently expose it):
  - `POST /api/v1/ai/query` answers a **typed semantic / natural-language query** over
    the tenant's own data surfaces (owners, certificates, the credential graph, the
    CBOM, the event log), grounded and **citing real records** (F75);
  - `POST /api/v1/ai/rca` answers a **grounded root-cause / NL question** from cited
    real records gathered through the tenant-then-RBAC scoping seam (`internal/query`,
    SF.7), preferring "insufficient evidence" to a guess (F77);
  - `GET /api/v1/mcp/tools` + `POST /api/v1/mcp/tools/{tool}` expose the **read-only,
    tenant-scoped MCP tools** an external AI agent can list and invoke (F78); there are
    **no write/remediation tools** (`HasWriteTool()` is false).

  Every route is **auth-gated** (API token or session, `graph:read`), **tenant-scoped
  under RLS** (the tenant is the authenticated principal's, **never** a request field —
  AN-1), **read-only**, **rate-limited**, and **injection-inert** (a hostile string in a
  record is inert, cited data — there is no action path). The **AI model is air-gapped /
  opt-in** by default (`ai.enable_api` mounts the surface; no model is configured, so
  grounding + citations work and **nothing phones home**); when an operator opts into a
  cloud/local model, **every prompt crosses `aimodel.DefaultRedactor` + the
  residual-entropy refuse-gate** before any egress, so **no key/secret material leaves to
  a model** (AN-8 / `SURFACE-004`). The wire-in lives in `cmd/trstctl` →
  `internal/server` (`server.Build` → `api.WithAISurface`, adapting the real
  `query.Engine` to `rca.Query`) and is proven end-to-end by the acceptance tests in
  `internal/server/aisurface_served_test.go` (served grounded NL-query/RCA citing real
  records, cross-tenant denial, injection-inert + secret-redacted, and an MCP
  list+invoke). **SURFACE-003 status: served.**
- **The secrets/identity frameworks — now SERVED (`GAP-006`, four of five).** Four of
  the secrets/identity frameworks are **mounted on the running binary** under
  `/api/v1/secrets/*` (off by default — `secrets.enable_api` — and fail-closed when
  off, requiring a KEK when on):
  - the workload **auth-method framework** (`internal/authmethod`, F58) backs
    `POST /api/v1/secrets/login` — a machine presents a token credential and receives
    a scoped, tenant-scoped session (distinct from the human OIDC SSO bridge). Token
    credentials MAC-bind tenant, audience, principal, and expiry; `X-Tenant-ID` is only
    the lookup hint and mismatched tenant headers are rejected;
  - the **application secrets SDK** (`internal/secretsdk`, F64) backs the secret store
    `POST/GET/PUT/DELETE /api/v1/secrets/store/...` (create, read, **rotate**, delete);
    values are sealed at rest under the KEK (`internal/crypto/seal`) and the read path
    fetches through a `secretsdk.Client`;
  - **PKI-as-a-secret / dynamic certificate leasing** (`internal/pkisecret`, F67) backs
    `POST /api/v1/secrets/pki` — it issues a short-lived certificate **and its private
    key** (a usable TLS identity, `tls.X509KeyPair`-loadable) through the issuing CA in
    the out-of-process signer (AN-4), recorded on the served revocation pipeline so a
    revoked dynamic-secret cert stops validating;
  - **secret sharing** (`internal/secretshare`, F68) backs
    `POST /api/v1/secrets/shares` + `.../redeem` — a one-time self-destructing share
    that redeems exactly once (a second redeem fails); the bearer token is never
    written to the audit/event log.

  Every served route is **auth-gated** (API token or session, `secrets:read` /
  `secrets:write`), **tenant-scoped under RLS** (AN-1), **idempotent** (AN-5), and
  **event-sourced** (AN-2); secret values are held as `[]byte`, never logged, and never
  returned beyond their design (AN-8). The wire-in lives in `cmd/trstctl` →
  `internal/server` (`server.Build` → `api.WithSecrets`) and is proven end-to-end by
  the acceptance tests in `internal/server/secrets_served_test.go`.
- **Secret-sync to external stores (`internal/secretsync`, F60) — still library-only.**
  The outbound secret-sync engine (push + drift detection to Kubernetes, GitHub
  Actions, GitLab CI, Terraform, Vercel/Netlify, AWS Parameter Store, and a generic
  webhook) is real, tested **library** code with **no importer on the served path** —
  the running binary does not yet mount a secret-sync surface. It is **built and tested
  but not yet mounted on the served binary**; serving it (it needs the
  connector-target surface) is tracked as the remaining tail of **`EXC-WIRE-03`**. Its
  deliveries go through the outbox (AN-6) and are tenant-scoped (AN-1) and audited
  (AN-2) in library code today.
- **Transit/KMIP (`internal/transit`, `internal/kmip`, F66) — still library-only.**
  The KMIP package now has a bounded TTLV RequestMessage parser with frame-size,
  field-count, and nesting-depth caps plus `FuzzParseTTLV`, and its library operation
  model still requires TLS client-certificate authentication before decode. The
  running binary does **not** import a KMIP listener or transit API/CLI surface yet,
  so the console and feature docs must keep disclosing it as library-only until a
  served endpoint is mounted and reference-client appliance profiles are exercised.

## Authorization policy gates: served on the issue/deploy/revoke path

As of **`EXC-WIRE-03`** the OPA/Rego default-deny policy gate, the RA scope split,
and dual-control approval are **enforced on the served mutating issuance path** of
the running binary — not just in library code. They gate the served lifecycle
transition (`POST /api/v1/identities/{id}/transitions`) for issue, deploy, and
revoke, fail-closed, before the orchestrator records the transition or enqueues the
mint/revoke effect. The gate is wired from `cmd/trstctl` → `internal/server`
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

**Regulated CA governance mode — one coherent posture switch (PKIGOV-003 — now
served).** Previously the policy gate, four-eyes dual control, the bound default
profile, revocation publication, and FIPS were each enabled independently, with no
single mode that refused to start unless they were all coherently present — a
compliance deployment could half-enable the posture and silently drop a control.
That gap is closed: with `ca.governance_mode=regulated` the running binary **fails
startup** unless **all** of the OPA policy gate (`ca.policy.enabled`), distinct-
approver four-eyes dual control (`ca.policy.require_approval` with a `>= 2`
threshold), a bound default certificate profile (`ca.default_profile`), revocation
publication (`ca.crl_distribution_points` and/or `ca.ocsp_servers`), and — when
`ca.require_fips` is declared — an active FIPS 140-3 module are present together,
each with an actionable error. A complete regulated config boots; the default
(`standard`) posture imposes no coupling. The switch is enforced in the served
startup/config validation path (`internal/config` `Validate` → the same boot path
`cmd/trstctl` runs before `server.Run`, where the FIPS power-on self-test already
asserts the module when required). See
[configuration → regulated CA governance mode](configuration.md#regulated-ca-governance-mode).

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
- **Plugin extensibility is now served by the binary (ARCH-007, EXC-WIRE-05).**
  The WASM plugin host is **wired into the served control plane**: `internal/server`
  imports `internal/pluginhost`, and when `plugins.enabled` the running binary loads
  operator-supplied **connector plugins** from `plugins.dir` and routes a served
  `connector.deploy` through the plugin's **capability sandbox** (the same
  `pluginhost.Grant` model the connector SDK uses) — tenant-scoped (AN-1),
  event-sourced (AN-2), on the plugin bulkhead (AN-7). The plugin runs in its own
  wazero runtime with **no DB pool or signer handle**, an operation outside its
  grant is denied at runtime (and fails the deploy), and the surface is **off by
  default** (a `connector.deploy` is acknowledged unrouted unless plugins are
  enabled). The shipped first-party CA/connector integrations still run as trusted
  in-process Go (see above); migrating them onto the host, and serving a **CA-via-
  plugin** issuance path, remain follow-ups.
- **Served plugins are signature/provenance-verified (SUPPLY-004, EXC-WIRE-05).**
  The served loader admits a `.wasm` module **only after** its detached **Ed25519
  signature** verifies (through the `internal/crypto` boundary, AN-3) against the
  operator-configured **trusted-key set** (`plugins.trusted_key_files`), with an
  optional **content-digest pin** (`plugins.pinned_digests`). An **unsigned**,
  **wrong-key**, **byte-tampered**, or **unpinned** module is **refused** and the
  binary **fails closed at startup** — it never instantiates an unverified plugin.
  The raw `Host.Load` (which `InstantiateWithConfig(ctx, wasm, …)` calls) remains
  for the in-process/conformance path; the served surface uses `LoadVerified`, which
  runs the provenance gate first and keeps the wazero sandbox as defense-in-depth.

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
  Enable it with `protocols.acme.enabled` plus `protocols.acme.tenant_id`; it activates
  only when an issuing CA is provisioned (a signer is configured) and fails closed
  otherwise.
- **EST** (RFC 7030), **SCEP** (RFC 8894), **CMP** (RFC 4210/6712), the **SPIFFE
  Workload API**, and the **SSH CA** issuance servers are **served end-to-end by the
  running binary** (`EXC-WIRE-02`), each behind the same signer-backed, tenant-scoped,
  event-sourced, idempotent, profile-gated issuance seam as the API mint:
  - **EST** at `/.well-known/est/...` (Bearer-API-token authenticated on top of TLS),
    **SCEP** at `/scep`, **CMP** at `/cmp` — mounted on the control-plane mux and
    exercised by served round-trip acceptance tests (a stock base64-PKCS#10 EST
    enroll, a CMS-enveloped SCEP `PKIOperation`, a CMP `p10cr`) that each download a
    real, signer-issued certificate verifying against the served CA and assert a
    `certificate.recorded` event (AN-2). SCEP/CMP use a sealed RSA *transport*
    identity at `protocols.ra_key_file` for CMS (deliberately **not** the CA key,
    which stays in the signer — AN-4); keep that file on shared persistent storage
    in HA so cached clients survive restarts and rolling deploys.
  - the **SPIFFE Workload API** is served as a **gRPC service on a Unix domain
    socket** (`protocols.spiffe.enabled`), so a `spiffe-helper`/go-spiffe/Envoy-SDS
    client dials the socket and `FetchX509SVID` returns an SVID + trust bundle signed
    through the signer; a served acceptance test drives the SPIFFE Workload API wire
    protocol (with the mandatory `workload.spiffe.io` metadata) over the socket and
    validates the SVID. A required CI job also runs stock go-spiffe and stock
    `spiffe-helper` against that served UDS; go-spiffe is a test-only dependency so
    the served binary does not take a new runtime dependency for the proof.
  - the **SSH CA** is served at `/ssh/...` (`protocols.ssh.enabled`): cert issuance
    plus the **OpenSSH binary KRL** at `/ssh/krl` (`sshd`'s `RevokedKeys` consumes it
    — INTEROP-009); a served acceptance test issues a user cert (verified with
    `ssh-keygen -L`), revokes it, and confirms the served KRL is the binary format.
    The SSH CA key lives in the signer under its own handle constrained to SSH-cert
    signing (AN-4).
  - the **RFC 3161 TSA** is served at `/tsa` (`protocols.tsa.enabled`): clients POST
    `application/timestamp-query` `TimeStampReq` bodies and receive
    `application/timestamp-reply` `TimeStampResp` bodies. The timestamping key lives
    in the signer under its own stable handle, the TSA certificate is persisted at
    `protocols.tsa_cert_file`, and the certificate carries the critical
    `timeStamping` EKU that stock OpenSSL enforces.

  Each protocol surface is gated by `protocols.<name>.enabled` and binds a tenant via
  `protocols.<name>.tenant_id`. All protocol toggles default off until an operator
  explicitly binds the served endpoint to a tenant; if a protocol is enabled without a
  tenant, startup validation fails before the route is exposed (it must not mint or
  issue tenant-scoped evidence into a blank tenant — AN-1). All protocols activate only
  when an issuing CA is provisioned.
  - **Reference-implementation differentials (TEST-002).** Two protocols are
    cross-checked against an *independent* implementation, not just our own parser:
    **ACME** runs a differential against **Pebble** (the reference test ACME CA) as a
    dedicated CI job, and now also has a **stock certbot CI transcript**: certbot
    manual DNS-01 issues, renews, and revokes through the served `/directory` endpoint
    while CI archives public challenge records, client logs, and issued certificates.
    **EST** runs a differential against the **OpenSSL** `pkcs7` parser/verifier on
    every `make test` (so `/cacerts` and `/simpleenroll` output is validated by code
    we did not write). A dedicated CI job also builds a checksum-pinned
    **libest** `estclient` from source and requires it to perform simpleenroll
    against the served EST endpoint. The
    **SPIFFE Workload API** has a **served stock-client differential**: the real
    go-spiffe `workloadapi` client fetches and validates an SVID over the served UDS,
    and stock `spiffe-helper` writes the served SVID, key, and trust bundle to disk.
    **CMP** has a dedicated stock-client CI transcript: OpenSSL
    `cmp -cmd p10cr` creates the request, enrolls through the served `/cmp` endpoint,
    accepts the protected response, and uploads the request/response/cert/log
    artifacts. **SCEP** now has a dedicated stock-client CI transcript as well:
    a SHA-256-pinned `sscep` v0.10.0 build fetches the served CA, enrolls through
    `/scep/pkiclient.exe`, and uploads the captured PKIOperation request/response
    plus client logs. **TSA** has a dedicated stock-client CI transcript: OpenSSL
    `ts -query` creates a DER `TimeStampReq`, CI POSTs it to the served `/tsa`
    endpoint, OpenSSL `ts -verify` validates the returned `TimeStampResp`, and public
    request/response/log artifacts are uploaded.
  - **SSH KRL distribution format (INTEROP-009).** The SSH CA's key-revocation list is
    now emitted in the **OpenSSH binary KRL format** (`KRL.DistributeKRL`), the artifact
    `sshd`'s `RevokedKeys` and `ssh-keygen -Q -f` consume — verified end-to-end by a test
    that has stock `ssh-keygen` report a revoked certificate as revoked using trstctl's
    KRL (and a non-revoked one as valid). The legacy JSON `Snapshot` (`Distribute`) is
    retained for programmatic callers. The SSH CA is now **served** (`EXC-WIRE-02`,
    `protocols.ssh.enabled`): cert issuance at `/ssh/...` and the binary KRL at
    `/ssh/krl`, the artifact a host's `RevokedKeys` consumes.
  - **Public-CA profile linter (PKIGOV-009 / PKIGOV-004).** Issued certificates are
    checked by an in-tree **structural RFC 5280 / CA-Browser-Forum profile linter**
    (`internal/ca/profilelint`) in the issuance test suite — version, serial bounds,
    validity ordering/length, basicConstraints, key usage, SAN presence, SKI/AKI
    presence, weak-signature and minimum-key-strength checks — and the suite is **red
    on a deliberately-broken profile**. The compose CI gate now also generates a PEM
    corpus for every emitted X.509 profile shape (served leaves, mTLS agent
    certificates, SPIFFE X.509-SVID, TSA, and the issuing CA), runs pinned **zlint**
    over the served CA plus that corpus, and uploads the generated fixtures and JSON
    lint transcripts as artifacts. This is an internal/private-CA assurance gate, not a
    claim that trstctl operates as a WebPKI public CA.
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
- **Agent ↔ control-plane mTLS gRPC channel (WIRE-004 / OPS-005):** the agent
  steady-state channel is now **served by the running binary** when
  `agent_channel.enabled` (off by default — an upgrade does not silently open an agent
  port). The control plane mounts an **agent-facing gRPC listener** (default `:9443`)
  over **mutual TLS** (`internal/server` `RunAgentChannel`; the agent service is
  `internal/agent/transport`), and an enrolled agent connects to it to (a) **heartbeat**
  its inventory/status — the server records the agent **tenant-scoped under RLS** (AN-1)
  and emits an `agent.heartbeat` event (AN-2) — and (b) **renew its own certificate**
  before expiry — a fresh cert is minted through the **signer-custodied agent CA**
  (AN-3/AN-4), **idempotently** on the presented serial (AN-5), recorded as an
  `agent.cert.renewed` event (AN-2). The tenant is derived from the agent's **verified
  client-certificate SPIFFE SAN** (WIRE-003/AN-1), never a request field. The channel
  is behind its own bounded **agent bulkhead** and per-connection gRPC stream cap, so a
  heartbeat or renewal storm sheds with `ResourceExhausted` rather than starving API,
  protocol, outbox, or signer capacity (AN-7). Agents announce an explicit
  protocol/capability handshake and schedule heartbeats from the server hint with
  bounded jitter, so rolling upgrades and fleet restarts do not synchronize a thundering
  beat. The **agent
  CA key now lives in the isolated signer** under a stable handle, so it does **not**
  regenerate per boot — an agent's pinned CA **survives a control-plane restart** (the
  earlier in-process/per-boot stand-in is replaced when the channel is enabled, and the
  same signer-custodied agent CA also signs the bootstrap enrollment, so a
  bootstrap-enrolled agent is accepted on the steady-state channel). The shipped chart
  exposes the channel (**OPS-005**): when `agentChannel.enabled`, the control-plane
  **Service publishes the agent port `9443`** (`agent-grpc`), the container exposes it,
  and the **NetworkPolicy** admits it (from the configured `agentChannel.allowedCIDRs`
  plus the in-cluster peers the API admits) — so the fleet manifests
  (`deploy/kubernetes/daemonset.yaml`, the Windows MSI) that point agents at `:9443`
  reach a served port. This is distinct from the *isolated signer's* `:9443` (a
  signer-only Service under `signer.mode=isolated`, which admits only the control
  plane). An untrusted/unpinned agent client is rejected at the mutual-TLS handshake
  (fail-closed). Proven end-to-end by
  `internal/server/agentchannel_served_test.go` (real signer + embedded Postgres: enroll
  → heartbeat → renew → idempotent retry → reject untrusted) and the rendered-chart
  assertions in `deploy/helm/agentchannel_test.go`.

## Revocation

Revoking a credential through the running binary is **real and recorded**, not a
no-op. Transitioning an identity to *revoked* drives the served outbox handler to:

- mark the issued certificate **revoked in the inventory** — via a projected
  `certificate.revoked` event (AN-2), so the status is reconstructable from the
  log on a `Rebuild()`, and the certificate API now returns `status` /
  `revoked_at` / `revocation_reason` so the revocation is **visible** on the
  served surface (a revoked cert reads `"revoked"`, not silently `"active"`); and
- project the certificate's serial into the **revocation read model**
  (`ca_issued_certs`) from the same event, so OCSP/CRL state is rebuilt from the
  log instead of from a side write.

The **online revocation-distribution surface is now served** (`EXC-REVOKE-01`):
the running binary mounts an RFC 6960 **OCSP responder** at `/ocsp/{tenant}` (GET
base64-in-path and POST `application/ocsp-request`) and an RFC 5280 **CRL
endpoint** at `/crl/{tenant}`, and runs a background **freshness scheduler** that
regenerates each tenant's CRL ahead of its `nextUpdate`. Trusted issue, renewal,
revocation, protocol-enrollment, and scheduler paths publish CRLs; public
`GET /crl/{tenant}` is read-only and returns 404 until a CRL is already published
for a tenant that has issued certificates. A query for a revoked serial returns
`revoked` over OCSP and the serial appears on the CRL within the freshness window;
a query for an issued-but-not-revoked serial returns `good`; an unknown serial
returns a signed `unknown`. These endpoints are **public by RFC design** (relying
parties check status without credentials) but run on the API bulkhead pool, so an
OCSP/CRL flood sheds rather than starving the rest of the control plane (AN-7).

OCSP responses and CRLs are **signed through the out-of-process signer** (AN-4):
the signing op crosses the `internal/crypto` boundary (`SignOCSPResponse` /
`CreateCRL`) using the same signer-held CA key (a purpose-bound `RemoteSigner`)
the leaf path uses, so the CA private key **never materializes in the control
plane** — only the digest crosses. Every query is tenant-scoped under RLS (AN-1).
Each published CRL emits a v2 `ca.crl.published` event that carries the CRL DER
and validity window, so `ca_crls` is rebuilt from the event log (AN-2).

This is exercised end to end in CI (issue → revoke → assert OCSP returns
`revoked` (and `good` before revocation) and the CRL lists the serial within the
freshness window, with both signatures verifying against the issuing CA, driven
over real HTTP against the assembled binary and the real out-of-process signer).

The **CDP/AIA pointers** stamped on issued leaves are operator-configured
(`TRSTCTL_CA_CRL_DISTRIBUTION_POINTS` / `_OCSP_SERVERS`, PKIGOV-001) because the
externally reachable URL is deployment-specific; point them at the binary's
`/ocsp/{tenant}` and `/crl/{tenant}` (behind your ingress) so relying parties
discover and fetch revocation status automatically. trstctl revocation is now
both authoritative in the product's own inventory/records **and** publishable to
external relying parties over served OCSP/CRL.

## Single sign-on (OIDC only)

trstctl's interactive SSO is **OIDC only**: the UI and CLI authenticate against any
OpenID Connect provider (Microsoft Entra ID / Azure AD, Okta, Ping, Google, Auth0,
Keycloak, and the like), and API/CI access uses scoped API tokens. **SAML 2.0 is
not supported.** PRD F13 originally named SAML as a Phase-1 SSO method, but trstctl
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
private-CA hierarchy (`internal/crypto/ca`) holds its live ECDSA signing keys in
**locked secret buffers** (mlock + `MADV_DONTDUMP`, AN-8) rather than as a bare
`*ecdsa.PrivateKey` on the Go heap for the lifetime of the in-process CA; the key
is reconstructed only for the instant of each signature and the transiently parsed
copy is best-effort zeroized afterward (the same hardening as the signer's
`LockedSigner`, SIGNER-008). This narrows — but, given Go's runtime, does not
eliminate — the window in which an unprotected key sits in dumpable heap; it is
complemented process-wide by `RLIMIT_CORE=0` / `PR_SET_DUMPABLE=0`.

**BYOK / HSM key lifecycle (`EXC-CRYPTO-01`).** trstctl provides a full
bring-your-own-key / HSM key lifecycle behind the AN-3 boundary
(`internal/crypto/byok` for in-process keys, `crypto.RemoteKeyLifecycle` +
`internal/kms/*` for HSM/KMS-resident keys), covering **generate-or-import →
rotate → revoke → zeroize** for CA/issuing signing keys and the secrets
key-encryption key (KEK):

- every transition is **event-sourced** (AN-2) through an injected event sink and
  is recorded with the key's identity, version, and public key — never its private
  bytes;
- key material lives only in **locked, zeroizable memory** (a `secret.Buffer`-backed
  `LockedSigner` / `LocalKEK`, AN-8), never a `string`; on rotate the superseded
  material is destroyed and on zeroize the buffer is wiped, after which the key can
  no longer sign or wrap (fail-closed);
- for an **HSM/KMS-resident** key the private key never enters the control-plane
  address space at all: rotate mints a successor at the provider, revoke disables
  the key (the provider refuses further signatures), and zeroize schedules the
  provider's destruction of the material — the durable custody story.

The **HSM/KMS-resident lifecycle is now served end to end** (CRYPTO-005): the running
control plane exposes `POST /api/v1/managed-keys` (generate) and
`/api/v1/managed-keys/{rotate,revoke,zeroize}`, with a matching `trstctl managed-keys
{generate,rotate,revoke,zeroize}` CLI. Each verb is tenant-scoped (AN-1), idempotent
(AN-5), and event-sourced (AN-2); the three **destructive** transitions
(rotate/revoke/zeroize) require a **distinct-approver dual-control approval** — the same
four-eyes machinery the issuance gate uses — before the provider is ever called, so no
single operator can rotate, disable, or destroy a managed key. The surface is served
only when a KMS/HSM custody backend is configured (`Deps.ManagedKeyCustody`); otherwise
the routes fail closed. *Code:* `internal/managedkeys` (served service + fake-KMS E2E),
`internal/api` (routes + handlers), `internal/cli`, wired in `internal/server`.

Still **library-tier** (reachable from no served verb yet): the **in-process**
`internal/crypto/byok` lifecycle for the local CA/issuing signing key and the secrets
KEK (generate-or-import → rotate → revoke → zeroize is implemented and end-to-end
tested but not yet exposed as its own served route), and a served **m-of-n break-glass**
flow. The signer's at-rest CA key is still sealed under a local key-encryption file by
default. See the [key-ceremony runbook](runbooks/key-ceremony.md),
[incident response](runbooks/incident-response.md), and
[disaster recovery](disaster-recovery.md). The remaining external residual of
`EXC-CRYPTO-01` is the **product NIST CMVP certificate** (see
[compliance → FIPS](compliance.md#fips-cryptography--a-fips-capable-build-path-pkigov-007--exc-crypto-01)),
a lab process software cannot perform.

**Signer UDS peer-uid is Linux-only (WIRE-009 / SIGNER-006).** The signing service's
Unix-domain-socket listener authenticates the connecting process's uid via
`SO_PEERCRED`, which exists only on **Linux** -- the supported production target
(Docker/Helm). On non-Linux hosts, `trstctl-signer` now fails closed when process
hardening, locked memory, or UDS peer credentials are unavailable. Local developers
can opt into the filesystem-permissions-only fallback with the explicit
`--allow-insecure-dev-nonlinux` flag (or
`TRSTCTL_SIGNER_ALLOW_INSECURE_DEV_NONLINUX=true` for child signer mode), but this is
not a production control. Production deployments without reliable UDS peer
credentials should use the signer's fail-closed mTLS transport with pinned peer
certificates.

## Post-quantum cryptography (issuance algorithms)

trstctl's cryptography sits behind one boundary (AN-3, `internal/crypto`), and the
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

The control plane ships a production-shaped **Helm chart** (`deploy/helm/trstctl`):
the API/UI with the **signing service isolated** (its own locked-down, network-
unreachable sidecar), external PostgreSQL and NATS as the default, a default-deny
`NetworkPolicy`, and TLS.

- **Kubernetes Operator scope.** A **minimal** CRD-driven operator ships from S15.1:
  `cmd/trstctl-operator` (a binary that rides inside the same multi-binary
  control-plane image and is run by `deploy/operator/operator.yaml` via an
  entrypoint override) reconciles `TrstctlControlPlane` custom resources into a
  managed control-plane Deployment — keeping that Deployment's **replica count and
  image** matching each resource's `spec`, and writing the observed phase back to
  the resource status. It is a real, level-based reconcile loop (poll, diff,
  converge), not a stub; it speaks the Kubernetes API directly (no
  client-go/controller-runtime). It is **deliberately minimal**: it owns the
  Deployment's replicas+image only, and does **not** yet manage Services, secrets,
  `NetworkPolicy`, or the isolated-signer topology. For a complete,
  production-shaped control-plane install (isolated signer, external
  PostgreSQL/NATS, default-deny `NetworkPolicy`, multi-replica HA) the **Helm
  chart** (`deploy/helm/trstctl`) remains the richer, recommended path.
- **Multi-replica HA.** The Helm chart runs the control plane **multi-replica by
  default** (`replicaCount: 2`, `RollingUpdate maxUnavailable: 0`, PodDisruptionBudget,
  pod anti-affinity), and running >1 replica is **safe** (RESIL-002 / RESIL-004 /
  EXC-RESIL-01): **leader election** (a PostgreSQL session-scoped advisory lock) gates
  the continuous background workers — the outbox dispatcher, audit retention,
  idempotency/outbox GC, the projection tailer, the CRL scheduler, and the read-model
  snapshot worker — to exactly one replica so they never double-apply, with automatic
  failover to a follower on leader loss; all replicas serve reads. A **shared signer
  key store** (`persistence.signerKeysAccessMode: ReadWriteMany`) means every pod's
  locked-down sidecar signer (AN-4) loads the SAME sealed issuing-CA key, so all
  replicas are the same CA (first-boot provisioning is serialized by an advisory
  lock). For a single signer pod that serves all replicas **independently**, set
  `signer.mode: isolated`: the signer runs as its own pod reached over a **cross-node
  mTLS gRPC channel** — TLS 1.3, AEAD-only, with the control plane and the signer each
  **pinning** the other's certificate (an untrusted or merely CA-signed-but-unpinned
  peer is rejected). This is now **implemented** (SIGNER-005): the `trstctl-signer`
  binary serves `--mtls-listen` and the control plane dials it with
  `signer.mtls_address`; the chart renders the signer Deployment/Service/NetworkPolicy
  on `:9443` when you supply the `signer.mtls.*` certificate material. The default
  co-located sidecar (UDS) topology remains the simplest single-pod option and is not
  required to change for the HA above. See
  [disaster recovery → High availability](disaster-recovery.md). (The agent,
  separately, runs as a DaemonSet across all nodes.)

## Non-functional targets: what is measured vs. aspirational

We separate NFRs that have **executable evidence** from ones that are **aspirational
and not yet measured** in CI, so neither is silently over-claimed.

- **Performance & scale NFRs are measured.** The hot-path latency/throughput SLOs and
  the capacity model are pinned to a committed measurement receipt
  (`scripts/perf/artifacts/smoke-baseline.json`) by an executable smoke gate
  (`make perf-smoke` / `scripts/perf/run-local.sh`, denominator `internal/perf`,
  PERF-001/002/003), and sustained-load endurance is pinned by a **soak gate**
  (`make soak` / `scripts/perf/soak.sh`, analyzer `internal/perf` `AnalyzeSoak`,
  PERF-004) that fails on a leak slope or an SLO breach. These are smoke/self-test
  scale denominators, not a substitute for a customer-specific multi-hour load test
  at your own capacity tier.
- **Usability outcome NFRs are aspirational and unmeasured.** Targets such as a
  **timed first-run / time-to-first-certificate** wall-clock budget and any
  **operator-satisfaction / NPS** goal are **design aspirations**, not facts the
  product measures: there is **no automated CI measurement** of first-run wall-clock
  time or operator satisfaction, and no published timed-first-run or NPS receipt.
  The getting-started flow is exercised for *correctness* end-to-end (and issuance is
  *latency*-measured per the SLOs above), but the human *time-to-success* and
  *satisfaction* numbers are not benchmarked. Treat any such figure as a goal to
  validate with real operators, not a guarantee (TRACE-011).

## How to read the roadmap against this

The [README capability table](https://github.com/imfeelingtheagi/trstctl#capabilities)
describes what is **built and tested**; this page tells you what is **served by the
binary today**. When the two differ, this page is the authority for what you can
rely on at runtime.
