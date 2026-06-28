# Current limitations & what's not yet served

trstctl is pre-1.0 and under active hardening. This page is the honest companion
to the capability list: it states plainly **what the running binary serves today**
versus **what is built and tested as library code but not yet wired into the
served product**, and which surfaces are explicitly Phase 2. Maturity boundaries
are separate from edition gates: Community self-host includes the core control
plane, while Enterprise and Provider capabilities are activated by an offline
signed license and remain behind the `ee/` boundary. trstctl is source-available,
not open-source; the production self-host grant lives in `LICENSE`, with attribution
and contribution terms in `NOTICE`.

If a capability matters to your evaluation, check this page before relying on it.

## Served by the running binary today

The `trstctl` binary assembles and serves a control plane: the tamper-evident event
log, the read models it projects, the lifecycle orchestrator, and the REST API, with
the signing service supervised as a separate out-of-process child so private keys
never live in the API process. What you can do end to end against the running binary:

- **Inventory and lifecycle** for owners, issuers, identities, and certificates —
  create, read, list (keyset-paginated), and drive the lifecycle state machine.
- **Connector delivery and lifecycle rotation evidence**: deployment attempts emit
  `connector.delivery.recorded` receipts, scheduled renewals emit
  `lifecycle.rotation.recorded` runs, and both are readable through the API, CLI,
  and console. The receipt is routing/status metadata only: no private key or secret
  bytes are returned.
- **Expiry-alert notification delivery**: the leader lifecycle scheduler honors the
  configured alert window, writes `notification.expiry` outbox work, stamps
  `alerted_at` in the same transaction so one certificate does not spam, and the
  served outbox worker dispatches the alert through operator-wired Slack, Teams,
  email, PagerDuty, OpsGenie, or webhook channels. This is runtime delivery, not a
  tenant channel-management API.
- **Deployment connector target mutation** for the shipped connector set is served
  through the outbox when an operator wires a native `ConnectorRegistry` into the
  running binary, or when a provenance-verified signed WASM connector plugin owns
  the connector name. A direct `connector.deploy` payload that carries `cert_pem`
  and `key_pem` is delivered at-least-once to the registered connector and records
  a `delivered` or `failed` receipt. A lifecycle transition that contains only
  routing metadata still records an `unrouted` receipt instead of pretending it
  deployed bytes the control plane no longer has.
  The shipped connector set is 24 connectors: nginx, Apache, Caddy, Envoy, IIS,
  HAProxy, F5, NetScaler, A10, Kemp, Cisco, FortiGate, Palo Alto, Postfix,
  Traefik, AWS ACM, Azure Key Vault, GCP Certificate Manager, Java keystore,
  PostgreSQL, MySQL, RabbitMQ, Elasticsearch, and Tomcat.
- **Discovery control plane + continuous monitoring repository, network, cloud-certificate, CT-log, and drift execution**: the running binary serves
  discovery sources, schedules, and runs under `/api/v1/discovery/*` — create/list a
  source, create/list a schedule, queue a run (idempotent — deduplicated by
  `Idempotency-Key`), read runs and findings (keyset-paginated), and read
  `GET /api/v1/discovery/monitoring` for the centralized continuous-monitoring view
  across sources, enabled schedules, last runs, findings, and certificate inventory
  counts. `GET /api/v1/certificates/health` and `trstctl certificates health` serve
  the estate-wide certificate expiry/source dashboard over the same inventory
  projection, including certificates issued elsewhere and later imported or
  discovered. Queuing a run is recorded as an immutable event (`discovery.run.queued`) in the tamper-evident log,
  so run state is reconstructable from history, and the scan **intent** is journaled to
  the outbox; an outbox worker then **executes** the run with at-least-once delivery.
  For a **network** source the served worker runs a real certificate sweep over the
  configured targets/CIDRs on its own bounded worker lane (a flood fast-rejects rather
  than starving other subsystems), records discovered certificates into inventory and
  findings, and completes the run. This is the served **network scan execution** path.
  For a **cloud_certificate** source the served
  worker executes AWS ACM, Azure Key Vault, and GCP Certificate Manager enumeration
  through credential references, records discovered certificates into inventory and
  findings, and completes the run. For a **ct_log** source the worker polls configured
  RFC 6962 log fixtures or public logs, checkpoints each log, records unexpected
  issuance as `ct_unexpected_issuance` findings, and queues notification alerts through
  the same outbox discipline as expiry alerts. For a **drift** source the worker compares
  configured credential paths against expected fingerprints and permissions, records
  `credential_drift` findings, and queues drift alerts. A **manual** source records its
  supplied findings. The remaining **SSH key/trust scan** collector is not wired into the
  served worker; see the Discovery bullet under "Built and tested, but not yet served"
  below.
- **CBOM scan and migration inventory**: `POST /api/v1/cbom/scans` runs the
  cryptographic bill of materials scanner against TLS endpoints and host config
  files, records `cbom.asset.observed` events, and projects tenant-scoped
  `crypto_assets`. `GET /api/v1/cbom/assets` returns the stored inventory plus
  FIPS 203/204/205 migration targets and `migration_progress` so operators can see
  which assets are already post-quantum-ready and which are still
  quantum-vulnerable.
- **Credential-compromise incident execution**: when the Enterprise `remediation`
  feature is licensed, `POST /api/v1/incidents/executions` drives a served,
  idempotent (deduplicated by `Idempotency-Key`),
  history-reconstructable single-identity remediation — replacement issue/deploy,
  revocation, blast-radius capture, and a
  sealed evidence pack readable via `GET /api/v1/incidents/executions{,/{id}}`.
  *Fleet-wide* re-issuance is served separately at
  `POST /api/v1/incidents/fleet-reissuance-runs` with pause/resume/rollback and
  evidence export routes under `/api/v1/incidents/fleet-reissuance-runs/{id}`,
  matching `trstctl incidents fleet-reissuance *` CLI commands, and the `/incidents`
  console;
  online m-of-n break-glass issuance is not this surface. Break-glass recovery
  reconciliation is served separately at
  `POST /api/v1/breakglass/reconcile`, where signed offline bundles are verified and
  recorded as `breakglass.issued` audit events.
- **Real X.509 issuance**: transitioning an identity to *issued* mints a leaf
  certificate from the assembled CA (its key held in the out-of-process signer) and
  records it in inventory. This is exercised end to end in CI.
- **Attested X.509-SVID issuance**: when the operator wires the six attesters and
  their trust material into the served binary, `POST /api/v1/workloads/attested-issuance`
  verifies a workload proof (`aws_iid`, `azure_imds`, `gcp_iit`, `github_oidc`,
  `k8s_sat`, or `tpm`), signs a short-lived X.509-SVID for the presented public key in
  the isolated signer, records `certificate.recorded`, binds `attestation.bound`, and
  returns the certificate plus verified subject metadata. The route requires
  `certs:issue`, an `Idempotency-Key`, and the authenticated tenant; a forged proof
  fails closed and mints nothing. There is not yet a tenant self-service UI/API for
  managing attester roots/JWKS/nonce policy — operators configure those process inputs.
- **Authentication and RBAC** via **scoped API tokens** (sent as
  `Authorization: Bearer`), **multi-tenancy** with PostgreSQL row-level security,
  and a **tamper-evident audit chain**. A fresh boot fails closed (every route
  `401`s until a credential exists); mint the first tenant-scoped token on the host
  with `trstctl token create --tenant <uuid>` (it writes through the store and
  prints the token once). Interactive **OIDC, SAML, and LDAP / Active Directory login
  are served by the binary** when `auth.oidc.enabled`, `auth.saml.enabled`, or
  `auth.ldap.enabled` is set (see "Single sign-on" below): the browser flow mints an
  `HttpOnly` session cookie that
  authorizes API calls under the **same RBAC + per-tenant database-isolation
  scoping** as an API token, and each user is mapped to its real tenant. API-token
  auth remains the default when SSO is disabled.
- **SCIM 2.0 provisioning** is served when `auth.scim.enabled` is set. IdPs call
  `/scim/v2/Users` and `/scim/v2/Groups` with a tenant-bound bearer token; user
  create/update/deprovision writes the tenant-member event stream, and group
  membership maps to existing RBAC role names. A deprovisioned user loses session
  authorization because RBAC reads the current tenant-member state.
- **Transport security** (TLS, internal or file-based), **idempotency** and the
  **outbox**, **observability** (`/metrics`, `/readyz`, W3C trace headers),
  **bulkheads + per-tenant rate limiting**, **backup/restore + disaster recovery**,
  and **safe schema migrations**.
- **Protocol parity hardening:** served ACME supports the explicit
  **ACME trust_authenticated** profile mode for authenticated internal issuance, plus
  account-keyed order/hour and concurrent-order limits. Served EST includes
  `/serverkeygen`, RFC 9266 `tls-server-end-point` binding, profile PathID dispatch,
  and an mTLS sibling route when configured. Served SCEP includes the
  **SCEP Intune challenge** gate with tenant/CSR binding, single-use replay rejection,
  per-profile RA material, and per-device rate limiting.
- **Revocation hardening:** RFC 5280 named revocation reasons, bulk revoke routes,
  delegated OCSP responders, OCSP nonce echo, nonce-free OCSP response caching, and
  CRL ETag / `If-None-Match` caching are served on the revocation surface.
- **notification routing matrix and inbox:** expiry, CT, drift, and workflow alerts
  resolve through the configured severity-to-channel matrix, dedup by
  per-subject/threshold/channel, and are inspectable through the served notification
  inbox with dead-letter requeue.
- **MCP-vs-REST parity guard:** the served MCP automation surface includes broad
  route-backed REST tools in addition to the named investigation tools, and CI fails
  when a served REST route is missing both an MCP mapping and an explicit allowlist.
- **Cert-ops console parity:** issuer catalog and Test connection, operations queue,
  Notifications inbox, richer certificate filters, dashboard charts, CTA empty states,
  onboarding carousel, and server-side command-palette search are in the served console.

The `trstctl-cli` drives this same served surface. **Interactive OIDC, SAML, and
LDAP / Active Directory browser login + sessions are served by the binary** (behind
`auth.oidc.enabled`, `auth.saml.enabled`, or `auth.ldap.enabled`) — see
"Single sign-on" below. The **React web console is now shipped in the binary**: a
clean build of the control-plane binary embeds the real built Vite bundle and serves
it at `/`, and the frontend's API types are **generated from the served OpenAPI
contract** so they cannot silently drift. The **AI/RCA/MCP** surface is **now served
too** (behind `ai.enable_api`); see its section below.

### Tenant offboarding boundary

Tenant offboarding erases **PostgreSQL read state** for the target tenant: it deletes
every tenant-scoped table under that tenant's row-level-isolation context, verifies
zero residue, and returns a deletion attestation. The `tenant.offboarded` event is
replayed by projections, so a read-model rebuild does not resurrect the tenant's
PostgreSQL rows.

That is the limit of what tenant offboarding deletes. It is not a promise that the append-only event log
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

- Remaining **private CA hierarchy** operator flows beyond root/intermediate/leaf
  issuance. Root/intermediate CA creation, existing signer-backed CA chain import,
  offline-root import, offline-intermediate CSR generation/import, m-of-n approvals,
  signer-backed leaf issuance, and configured upstream CA issuance are now served at
  `/api/v1/ca/ceremonies`, `/api/v1/ca/authorities`,
  `/api/v1/ca/authorities/offline-roots`,
  `/api/v1/ca/authorities/imported`,
  `/api/v1/ca/authorities/{id}/offline-intermediates/csr`,
  `/api/v1/ca/authorities/{id}/offline-intermediates`, and
  `/api/v1/external-cas`. Public/private direct-CA discovery is now served at
  `/api/v1/ca/discovery`, which returns configured public upstream CAs, configured
  private upstream CAs, and imported CA hierarchy authorities without PEM or key
  material. Rotation and cross-signing remain library/operator workflows until
  their served routes ship (see the
  [key-ceremony runbook](runbooks/key-ceremony.md)).
- **14 CA integrations** are present under the served external-CA registry when the
  operator configures their credentials/backends: AD CS, AWS PCA, Azure Key Vault,
  DigiCert, EJBCA, Entrust, GlobalSign, Google CAS, Let's Encrypt/ACME, Sectigo,
  shell CA, Smallstep, Vault PKI, and Venafi TPP/TLS Protect.
- **Discovery scanners/collectors still outside served execution**: the **SSH key/trust
  scan** collector still has **no path into the served worker** and remains agent/library
  execution today. The **network**, **cloud_certificate**, **ct_log**, **drift**, and
  **manual** source kinds are wired through the served discovery worker — see "Discovery
  control plane + network, cloud-certificate, CT-log, and drift execution" above. The
  **CBOM** scanner is also served, but through its own `/api/v1/cbom/*` API rather than
  the discovery-run worker.
- **SSH trust *rewrite* (the privileged `authorized_keys`/CA-trust mutator)**: the
  applier that installs a trusted SSH CA and rolls it back on failure is now **wired
  into the `trstctl-agent` binary** behind a **default-off operator opt-in**
  (`--ssh-trust-add-ca`) that additionally requires **explicit confirmation**
  (`--ssh-trust-confirm`) before it will rewrite trust. The op is **additive** (it
  never removes existing
  trust), validates the new config with `sshd -t`, reloads, runs a separate
  operator-supplied post-reload health command (`--ssh-trust-health-cmd`), and
  **auto-rolls-back** to the last-known-good on any failure — so a bad rewrite
  cannot lock operators out. Reload success alone is not treated as health. Because
  weakening `sshd`/`authorized_keys` trust is a high-blast-radius
  mutation, the feature stays off unless the operator turns it on and confirms;
  with the flag off the agent only *discovers* SSH trust (inventory, above), it
  does not *mutate* it. Trust *removal* still requires its own explicit confirmation
  (the safe default).
- **Posture collectors and agents:** CT-log monitoring and path-based credential drift
  detection are now executed by the served discovery worker when operators create
  `ct_log` or `drift` sources; findings are tenant-scoped and alert intents are
  outbox-backed. Dedicated Posture dashboards, resolution workflows, and automatic
  remediation remain future UI/workflow work. The generic **agent/endpoint discovery**
  path is served through the mTLS `ReportInventory` channel and is visible through
  `/api/v1/agents`, `/api/v1/discovery/findings`, `/api/v1/graph`, and the Agents
  console. The **SSH-specific host/trust collector** still runs on the agent, not in a
  server-side discovery-worker scanner, because only the endpoint can safely inspect
  local SSH files and trust config; its metadata can flow through the served agent
  inventory report path. The discovery *control surface*, the **network** scan executor,
  **cloud-certificate discovery execution**, the agent-channel **inventory report** path
  for metadata-only local findings including trust-store anchors, and the **CBOM**
  scan/inventory API are served (above). The **credential
  graph** and **risk scoring** read APIs are already served (`/api/v1/graph*`,
  `/api/v1/risk/credentials`), and the **AI/RCA/MCP** surface is served behind
  `ai.enable_api`; they are not part of this not-yet-served bucket.
- **React console scale work:** the console itself is served (see "The React web
  console" below). What remains not yet served of the original F12 epic is cursor
  pagination and list virtualization for very large tables.

## The React web console: served by the binary

The React 18 + Vite + shadcn/ui single-page app (F12) is the **real embedded artifact
the running binary serves**:

- **The shipped binary serves the real console.** The release pipeline builds the SPA
  into the binary's embedded asset bundle; the built bundle is committed, so even a
  plain control-plane build (without the separate web-build step) serves the real
  console at `/` — hashed `/assets/index-*.{js,css}` and an `index.html` that
  references them — not the old "not built" placeholder. A test boots the served
  handler over the real embedded bundle and fails if it ever regresses to the
  placeholder, and a release gate (enabled with `TRSTCTL_REQUIRE_BUILT_UI=1`) blocks a
  release that would embed the placeholder.
- **Generated frontend↔backend contract.** The frontend's API types are **generated
  from the served OpenAPI contract**, not hand-duplicated: the generator emits the
  TypeScript types from the served API spec (pinned equal to the live served spec),
  and the API client re-exports those types so a backend field add/rename/remove that
  is not regenerated fails the TypeScript build. A CI regenerate-and-diff gate fails
  the build on drift — so a certificate status mismatch between frontend and backend
  can no longer recur silently.
- **Operational console routes.** The console has first-class routes,
  nav entries, typed API wrappers, and route-test coverage for the GA operator slice:
  **Profiles** (`/profiles`, profile list + create), **Graph** (`/graph`, graph inventory
  + blast-radius query), **Audit** (`/audit`, audit-event list + evidence export),
  **dual-control approvals** from the identity table, licensed **incident execution** (`/incidents`,
  replacement issue/deploy, compromised-issuer fleet reissuance, revocation queue,
  connector receipt, rollback evidence, and sealed audit bundle), and the existing
  **Assistant/RCA/MCP** console (`/assistant`). Deliberately **API-only / library-only**
  surfaces remain labeled here until they receive their own served UI: online
  break-glass issuance workflows (with API-served break-glass reconciliation but no
  always-online issuance workflow), secret-sync dispatch, connector-driven deploy actions, discovery
  scan scheduling, and very-large-list cursor/virtualized browsing.
- **Console UX hardening.** A **destructive-transition confirmation**
  (revoke/retire require an explicit, credential-named confirm dialog) and
  **429/`Retry-After` handling** (the API client surfaces a concrete "retry in Ns"
  hint) are served and tested. Still outstanding in the SPA:
  **cursor-based pagination** (the client reads only `.items` and ignores
  `next_cursor`) and **list virtualization** for large tables; both remain not yet
  served.

## Interactive OIDC, SAML, and LDAP / Active Directory browser login & sessions: served by the binary

The OIDC authorization-code login, SAML 2.0 Service Provider login, and LDAP /
Active Directory bind login + sessions are **served by the running binary** (behind
`auth.oidc.enabled`, `auth.saml.enabled`, and `auth.ldap.enabled`). OIDC mounts
`/auth/login` and `/auth/callback`; SAML mounts `/auth/saml/login`,
`/auth/saml/acs`, and `/auth/saml/metadata`; LDAP mounts `POST /auth/ldap/login`;
all three share `/auth/me` and `/auth/logout`. OIDC verifies the id_token's
**signature, issuer, audience, nonce, and temporal claims (exp/nbf/iat)**. SAML
verifies signed POST-binding assertions against configured IdP metadata through the
same isolated cryptography boundary. LDAP binds the user, then performs a configured
group search; production directories should use `ldaps://` while plaintext `ldap://`
is accepted only for loopback development fixtures. All paths set an **`HttpOnly` +
`SameSite=Strict` session cookie** (marked `Secure`
whenever the control plane serves TLS) plus a **double-submit CSRF token**. A session
cookie authorizes API calls under the **same RBAC + per-tenant database-isolation
scoping** as an API token; mutations on the cookie path require the CSRF header. When
browser sign-on is disabled the binary authenticates with scoped API tokens only,
exactly as before; an enabled-but-misconfigured OIDC, SAML, or LDAP block **fails
closed at startup**.

- **Per-user → tenant mapping is served.** Each authenticated user is mapped to its
  **real tenant** at session issue — by a configurable OIDC claim or SAML attribute
  (`auth.oidc.tenant_claim` / `auth.saml.tenant_claim`, optionally used directly as
  the tenant id), by an IdP or LDAP group → tenant table, or by an explicit
  subject/claim/group → tenant mapping (`auth.*.tenant_mappings`) — instead of
  collapsing every browser user to one
  tenant. A user that maps to **no tenant is rejected** (the login fails closed, never
  minting a session in a fallback tenant unless an operator explicitly opts into
  `allow_default_tenant`). Per-tenant database isolation then confines each session to
  its mapped tenant, so two SSO users in different tenants see only their own data via
  the served API. The legacy single default tenant is retained only as that opt-in
  fallback. This is the served half of the defense against cross-tenant leakage; a
  freshly logged-in user still cannot self-issue (issuance stays behind the served
  RA/policy gate and the requester scope excludes `certs:issue`).

## SCIM 2.0 provisioning: served by the binary

The SCIM 2.0 provisioning surface is **served by the running binary** behind
`auth.scim.enabled`. It mounts `GET /scim/v2/ServiceProviderConfig`,
`/scim/v2/Users`, and `/scim/v2/Groups`; bearer tokens are loaded from configured
token files, hashed, and bound to one tenant before a request body is trusted.
SCIM user create/update/PATCH writes the same tenant-member event path used by
RBAC. SCIM `active:false`, DELETE, or group removal changes the projected
tenant-member roles, so the next browser-session API request sees the new
authorization result.

Current SCIM limits are deliberate and fail closed: SCIM Bulk is not implemented;
password management and password-change flows are not implemented; SCIM groups do
not create new custom roles. A group's `displayName` or id must match a configured RBAC role
such as `admin`, `operator`, `viewer`, `auditor`, or `ra-officer`.
Directory writeback is not implemented. Token rotation is operator-managed by
writing a new token file and restarting the control plane so the new hash is loaded.

- **The AI surface — model adapter (F76), grounded RCA / NL query (F75/F77), and the
  guarded MCP tool server (F78) — now SERVED.** The AI surface is **mounted on the
  running binary** under `/api/v1/ai/*` and `/api/v1/mcp/*` (off by default —
  `ai.enable_api` — and **fail-closed** when off, so an upgrade does not silently
  expose it):
  - `POST /api/v1/ai/query` answers a **typed semantic / natural-language query** over
    the tenant's own data surfaces (owners, certificates, the credential graph, the
    CBOM, the event log), grounded and **citing real records** (F75);
  - `POST /api/v1/ai/rca` answers a **grounded root-cause / NL question** from cited
    real records gathered through the tenant-then-RBAC scoping seam, preferring
    "insufficient evidence" to a guess (F77);
  - `GET /api/v1/mcp/tools` + `POST /api/v1/mcp/tools/{tool}` expose the
    tenant-scoped MCP tools an external AI agent can list and invoke (F78).
    Investigation tools are **read-only by default**. Guarded write tools
    (`issue_certificate`, `rotate_certificate`) appear only when
    `TRSTCTL_AI_MCP_WRITE_TOOLS=true`; each write still requires `certs:issue`, an
    `Idempotency-Key`, and emits `mcp.tool.write`.

  Every route is **auth-gated** (API token or session, `graph:read`), **tenant-scoped**
  (the tenant is the authenticated principal's, **never** a request field, enforced by
  per-tenant database isolation), **rate-limited**, and **injection-inert** (a hostile
  string in a record is inert, cited data and cannot by itself trigger a write). The
  **AI model is air-gapped / opt-in** by default (`ai.enable_api`
  mounts the surface; no model is configured, so grounding + citations work and
  **nothing phones home**); when an operator opts into a cloud/local model, **every
  prompt crosses a redactor plus a residual-entropy refuse-gate** before any egress, so
  **no key/secret material leaves to a model** (secret bytes live only in wipeable,
  zeroed memory and never reach a prompt). The surface is proven end-to-end by
  acceptance tests (served grounded NL-query/RCA citing real records, cross-tenant
  denial, injection-inert + secret-redacted, and an MCP list+invoke). **Status:
  served.**
- **The secrets/identity frameworks — now SERVED (six of six).** Six of
  the secrets/identity frameworks are **mounted on the running binary** under
  `/api/v1/secrets/*` (off by default — `secrets.enable_api` — and fail-closed when
  off, requiring a KEK when on):
  - the workload **auth-method framework** (F58) backs
    `POST /api/v1/secrets/login` — a machine presents a token, Kubernetes SAT,
    AWS IAM signed `GetCallerIdentity` request, GCP identity JWT, Azure workload JWT,
    generic OIDC token, or generic JWT and receives a scoped, tenant-scoped session
    (distinct from the human OIDC SSO bridge). Token credentials MAC-bind tenant,
    audience, principal, and expiry; JWT methods require a tenant claim or
    tenant-pinned config; AWS IAM is tenant-pinned through allowed account/ARN config.
    `X-Tenant-ID` is only the lookup hint and mismatched tenant headers are rejected;
  - the **application secrets SDK** (F64) backs the secret store
    `POST/GET/PUT/DELETE /api/v1/secrets/store/...` (create, read, **rotate**, delete),
    `POST /api/v1/secrets/store/import` (all-or-nothing tree import),
    `GET /api/v1/secrets/store/{name}?resolve=true` (explicit `${secret.path}`
    reference expansion with cycle rejection),
    `GET /api/v1/secrets/store/history/{name}?version=N` (read one prior sealed
    version), and `POST /api/v1/secrets/store/recover/{name}` (point-in-time recovery
    to the next monotonic version); values are sealed at rest under the KEK and the
    latest-value read path fetches through the SDK client. `trstctl-cli run --secret
    ENV=path -- <cmd>` is served as a developer wrapper over the same read path and
    injects values only into the child process environment;
  - the **Vault/OpenBao compatibility shim** backs the common migration paths
    `GET /v1/auth/token/lookup-self`, Vault KV mount-discovery preflight for
    `secret/`, `POST/PUT/GET /v1/secret/data/{path}`, and
    `POST/PUT /v1/pki/issue/{role}` for stock `vault` CLI token lookup, KV v2
    put/get, and PKI issue. This is deliberately a subset over the native served
    secret store and dynamic PKI secret; it does not implement Vault mount
    management, Vault ACL policy authoring, cubbyhole, response wrapping, Vault
    transit paths, or every Vault/OpenBao secret engine;
  - **dynamic secrets** (F65) back `POST /api/v1/secrets/leases`,
    `GET /api/v1/secrets/leases/{lease_id}`,
    `POST /api/v1/secrets/leases/{lease_id}/renew`, and
    `POST /api/v1/secrets/leases/{lease_id}/revoke` — issue returns the backend
    credential once, later reads return metadata only, renew extends an active lease,
    revoke closes it, and the served leaseworker expires leases through an
    outbox-backed backend revocation queue. The concrete backend family covers
    `postgresql`, `mysql`, `mongodb`, `aws-iam`, `gcp-iam`, `azure-entra`,
    `kubernetes`, and `redis`; operators still have to provide the target connection
    and cloud credentials for the providers they expose;
  - **static secret rotation** (F37) backs `POST /api/v1/secrets/rotations` — the
    running control plane drives the four-phase stage, cutover, verify, retire flow
    through concrete PostgreSQL, MySQL, and AWS IAM rotators. A failed cutover or
    verification returns rollback metadata only, restores the previous consumer
    pointer when possible, and revokes the staged backend credential without returning
    secret material;
  - **PKI-as-a-secret / dynamic certificate leasing** (F67) backs
    `POST /api/v1/secrets/pki` — it issues a short-lived certificate **and its private
    key** (a usable TLS identity, `tls.X509KeyPair`-loadable) through the issuing CA in
    the out-of-process signer (so the CA key never enters the API process), recorded on
    the served revocation pipeline so a revoked dynamic-secret cert stops validating;
  - **secret sharing** (F68) backs
    `POST /api/v1/secrets/shares` + `.../redeem` — a one-time self-destructing share
    that redeems exactly once (a second redeem fails); the bearer token is never
    written to the audit/event log.

  Every served route is **auth-gated** (API token or session, `secrets:read` /
  `secrets:write`), **tenant-scoped** under per-tenant database isolation,
  **idempotent** (deduplicated by `Idempotency-Key`), and recorded as immutable events
  (so state is reconstructable from history); secret values are held in wipeable,
  zeroed memory (never as a string), never logged, and never returned beyond their
  design. The surface is proven end-to-end by acceptance tests.
- **Secret sync external stores (F68) — served, target-configured, and intentionally
  fail-closed.**
  The running binary mounts `POST /api/v1/secrets/syncs` and `trstctl-cli secrets syncs
  run`. A request reads one stored secret, writes a sealed tenant-scoped outbox row
  before any external write, delivers through the configured target pusher, records
  immutable sync events, and returns metadata only. Native pushers currently cover
  GitHub Actions, AWS Secrets Manager, and Kubernetes; Vercel, GitLab, Terraform Cloud,
  GCP Secret Manager, and Azure Key Vault use the JSON/manual pusher shape until those
  providers receive deeper first-class APIs. If a target is not configured, the route
  returns `503` and does not attempt an external call.
- **Transit/KMIP (F66) — served, with a narrow first KMIP profile.**
  The running binary now mounts `/api/v1/transit/*` and the `trstctl-cli transit`
  command group for tenant-scoped key create/rotate, encrypt/decrypt, rewrap,
  HMAC, sign, and verify. Transit keys never leave the process as exportable
  material, request plaintext uses wipeable `[]byte` buffers, keyrings are zeroized
  on shutdown, and mutating operations emit immutable `transit.*` audit events. The
  running binary also mounts an opt-in raw KMIP mTLS listener when
  `protocols.kmip.enabled` is true and `protocols.kmip.tenant_id`,
  `protocols.kmip.cert_file`, `protocols.kmip.key_file`, and
  `protocols.kmip.client_ca_file` are configured. That first served KMIP profile is
  intentionally bounded: it accepts verified client certificates, decodes TTLV with
  frame-size, field-count, and nesting-depth caps, serves AES-256 `SymmetricKey`
  Create/Get for stock PyKMIP clients, records
  `kmip.object.created`, and zeroizes in-memory key material on rekey/destroy/shutdown.
  Broader KMIP operations (wrapping, Locate/Revoke/Destroy over the wire, profile
  negotiation, appliance-specific templates, and tenant self-service listener
  management) remain future served work.
- **Notification channel authoring and test delivery (F29) — not yet tenant-served.**
  Expiry-alert dispatch, notification inbox list/get/read, and dead-letter requeue are
  served when operators wire notification channels into the process, but tenants cannot
  yet create, edit, list, or test notification channel configuration through the REST
  API, CLI, or console. Keep channel secrets in operator-managed secret references
  until that authoring surface is mounted.

## Authorization policy gates and ABAC overlays: served by the binary

The RBAC guard, ABAC deny overlay, OPA/Rego default-deny policy gate, RA scope split,
and dual-control approval are **enforced by the running binary** — not just in library
code. The RBAC guard runs on every guarded API route. When `auth.abac.enabled` is set,
the ABAC deny overlay runs after RBAC on guarded routes with request, actor,
environment, and time attributes; on the served lifecycle transition
(`POST /api/v1/identities/{id}/transitions`) for issue, deploy, and revoke,
trstctl adds identity resource tags before the deny check. The OPA/Rego lifecycle
policy gate then gates issue/deploy/revoke fail-closed before the orchestrator records
the transition or enqueues the mint/revoke effect. The gate is tenant-scoped under per-tenant database isolation,
recorded as immutable events (reconstructable from history), and runs the policy
engine on its own bounded worker lane so a policy flood fast-rejects rather than
starving other subsystems.

- **Registration-authority (RA) separation & dual-control approval — now served.**
  The served gate enforces the RA scope split: a privileged issue/revoke transition
  requires the `certs:issue` authority, so a `certs:request`-only requester (the
  `ra-officer`) **cannot self-issue** on the served path. When dual control is enabled
  (`ca.policy.require_approval`), a privileged action is denied until a **distinct**
  approver records an approval via `POST /api/v1/identities/{id}/approvals` (which
  itself requires `certs:issue`); a **self-approval is rejected** (the requester cannot
  approve their own request), backed by tenant-isolated approval-request and approval
  records. This is the served half of the "loaded gun" defense (the bootstrap token
  already withholds `certs:issue`; the served mint now enforces the RA split + dual
  control too). The full request→approve→issue state machine (notifications,
  time-bounded grants, JIT) remains the richer library model; the served gate enforces
  the core distinct-approver / no-self-issue invariant.
- **OPA/Rego policy gate — default-deny on issue/deploy/revoke — now served.** With
  `ca.policy.enabled` set, the served binary invokes the embedded policy engine on
  every issue/deploy/revoke transition: the request is **denied unless the deployed
  Rego policy explicitly allows it** (default-deny, fail-closed). The policy input
  carries the action, `tenant_id`, the actor (authenticated principal), and the bound
  profile name, so an operator can enforce a real Rego document at runtime. A
  non-compiling policy module is a hard startup error, an evaluation error denies, and
  a saturated policy pool sheds with a 503 (never an allow). The built-in base policy
  is default-deny, permits revocation, and requires a bound certificate profile to
  issue/deploy (composing with the profile-enforcement rule below). Enforcement is
  **off by default** (`ca.policy.enabled=false`) so an in-place upgrade does not
  silently start denying; the RA scope split is enforced for privileged transitions
  regardless of this flag.
- **ABAC deny overlay — now served.** With `auth.abac.enabled` set, the served binary
  compiles a `package trstctl.abac` Rego module at startup and evaluates it after RBAC.
  It is deny-only: it cannot grant access that RBAC refused. Every guarded route carries
  `input.permission`, `input.resource.request.method`, `input.resource.request.path`,
  actor roles, `input.env`, and UTC time fields; issue/deploy/revoke transitions also
  carry identity metadata and flattened identity attributes such as
  `input.resource.env` and `input.resource.tags.service`. This supports controls like
  "prod certs may issue only during a change window." Bad Rego is a startup error,
  evaluation errors deny with `403`, saturated policy workers return `503`, and
  decisions are recorded as `policy.abac.decision` events. ABAC policy authoring is
  config-driven today; there is not yet a tenant-facing policy-management UI/API.

**Served-leaf profile enforcement.** Independently of the policy flag, when a default
certificate profile is bound (`ca.default_profile`) the served mint validates the
request against the active profile version and rejects an out-of-profile request
before signing (an `issuance.profile_evaluated` deny event) — so the served mint is
profile-gated, not ungated.

**Regulated CA governance mode — one coherent posture switch — now served.**
Previously the policy gate, four-eyes dual control, the bound default profile,
revocation publication, and FIPS were each enabled independently, with no single mode
that refused to start unless they were all coherently present — a compliance
deployment could half-enable the posture and silently drop a control. That gap is
closed: with `ca.governance_mode=regulated` the running binary **fails startup**
unless **all** of the OPA policy gate (`ca.policy.enabled`), distinct-approver
four-eyes dual control (`ca.policy.require_approval` with a `>= 2` threshold), a bound
default certificate profile (`ca.default_profile`), revocation publication
(`ca.crl_distribution_points` and/or `ca.ocsp_servers`), and — when `ca.require_fips`
is declared — an active FIPS 140-3 module are present together, each with an
actionable error. A complete regulated config boots; the default (`standard`) posture
imposes no coupling. The switch is enforced in the served startup/config validation
path, where the FIPS power-on self-test already asserts the module when required. See
[configuration → regulated CA governance mode](configuration.md#regulated-ca-governance-mode).

## Plugin isolation: first-party in-process, third-party sandboxed

This is a deliberate, documented trust boundary (not an accident):

- **Shipped first-party CA and connector integrations run as trusted in-process
  Go code** — they are *not* sandboxed through the WASM host. Their **blast radius**
  if one is defective is the control plane's address space: the database connection
  pool (confined to the tenant by per-tenant database isolation) and the signer
  *client* handle (it can request signatures), but **not** the CA private key, which
  stays in the separate signer process. They are mitigated by code review, the
  conformance suite, the connector SDK's capability-scoped sandbox facade, and
  per-subsystem bounded worker lanes.
- **The WASM plugin host (wazero) is real and is the isolation boundary for
  third-party plugins.** A loaded plugin has no ambient capabilities and only the host
  functions its grant permits; the host holds no database pool or signer handle; and a
  deliberately misbehaving plugin is **proven contained** by test. Migrating the
  first-party integrations onto it is future work. See the
  [plugin trust model](security/threat-model.md).
- **Plugin extensibility is now served by the binary.** The WASM plugin host is
  **wired into the served control plane**: when `plugins.enabled` the running binary
  loads operator-supplied **CA plugins** from `plugins.ca_dir` and
  **connector plugins** from `plugins.connector_dir` (or the legacy connector alias
  `plugins.dir`). A signed CA plugin is listed under `GET /api/v1/external-cas` and
  issues through `POST /api/v1/external-cas/{id}/issue`; a signed connector plugin
  routes served `connector.deploy` work through the plugin's **capability sandbox**
  (the same capability-grant model the connector SDK uses) — tenant-scoped under
  per-tenant database isolation, recorded as immutable events, on the plugin's own
  bounded worker lane. The plugin runs in its own wazero runtime with **no database
  pool or signer handle**, an operation outside its grant is denied at runtime, and
  the surface is **off by default**. The shipped first-party CA/connector integrations
  still run as trusted in-process Go (see above); migrating those built-ins onto the
  host remains future work.
- **Served plugins are signature/provenance-verified.** The served loader admits a
  `.wasm` module **only after** its detached **Ed25519 signature** verifies (through
  the single isolated cryptography path) against the operator-configured
  **trusted-key set** (`plugins.trusted_key_files`), with an optional **content-digest
  pin** (`plugins.pinned_digests`). An **unsigned**, **wrong-key**, **byte-tampered**,
  or **unpinned** module is **refused** and the binary **fails closed at startup** —
  it never instantiates an unverified plugin. A raw unverified load path remains only
  for the in-process/conformance path; the served surface always runs the provenance
  gate first and keeps the wazero sandbox as defense-in-depth.

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
  as a failure. Still outstanding: real hosted DNS providers (Route53/Cloudflare).
  The ACME server is now **served by the running
  binary**: it is mounted on the control-plane TLS listener at `/directory` +
  `/acme/...` and brokers issuance through the orchestrator-backed path — signed in the
  isolated signer (so the CA key never enters the API process), tenant-scoped under
  per-tenant database isolation, recorded as immutable events, idempotent (deduplicated
  by `Idempotency-Key`), and profile-gated. A stock `golang.org/x/crypto/acme` client
  with an **ECDSA
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
  running binary**, each behind the same issuance seam as the API mint: signed in the
  isolated signer, tenant-scoped, recorded as immutable events, idempotent, and
  profile-gated:
  - **EST** at `/.well-known/est/...` (Bearer-API-token authenticated on top of TLS),
    **SCEP** at `/scep`, **CMP** at `/cmp` — mounted on the control-plane mux and
    exercised by served round-trip acceptance tests (a stock base64-PKCS#10 EST
    enroll, a CMS-enveloped SCEP `PKIOperation`, a CMP `p10cr`) that each download a
    real, signer-issued certificate verifying against the served CA and assert a
    `certificate.recorded` event in the tamper-evident log. SCEP/CMP use a sealed RSA
    *transport* identity at `protocols.ra_key_file` for CMS (deliberately **not** the
    CA key, which stays in the isolated signer); keep that file on shared persistent
    storage in HA so cached clients survive restarts and rolling deploys.
  - the **SPIFFE Workload API** is served as a **gRPC service on a Unix domain
    socket** (`protocols.spiffe.enabled`), so a `spiffe-helper`/go-spiffe/Envoy-SDS
    client dials the socket and fetches X.509-SVIDs, JWT-SVIDs, X.509 bundles, and JWT
    bundles. X.509-SVIDs are signed through the isolated signer; JWT-SVIDs use the
    signer-backed JWT handle and the served `ValidateJWTSVID` RPC validates them
    against the served JWT bundle. A served acceptance test drives the SPIFFE Workload
    API wire protocol (with the mandatory `workload.spiffe.io` metadata) over the
    socket and validates both SVID families. A required CI job also runs stock
    go-spiffe and stock `spiffe-helper` against that served socket; go-spiffe is a
    test-only dependency so the served binary does not take a new runtime dependency
    for the proof.
  - the **SSH CA** is served at `/ssh/...` (`protocols.ssh.enabled`): cert issuance
    plus the **OpenSSH binary KRL** at `/ssh/krl` (`sshd`'s `RevokedKeys` consumes it);
    a served acceptance test issues a user cert (verified with `ssh-keygen -L`),
    revokes it, and confirms the served KRL is the binary format. The SSH workflow API
    and CLI also serve status, explicit-confirmation trust-rollout evidence,
    attestation-gated user cert issuance, KRL revocation, and host retirement handoff.
    The SSH CA key lives in the isolated signer under its own handle constrained to
    SSH-cert signing.
  - the **RFC 3161 TSA** is served at `/tsa` (`protocols.tsa.enabled`): clients POST
    `application/timestamp-query` `TimeStampReq` bodies and receive
    `application/timestamp-reply` `TimeStampResp` bodies. The timestamping key lives
    in the signer under its own stable handle, the TSA certificate is persisted at
    `protocols.tsa_cert_file`, and the certificate carries the critical
    `timeStamping` EKU that stock OpenSSL enforces.
  - the **code-signing service** is served at `POST /api/v1/code-signing/sign` and
    `POST /api/v1/code-signing/keyless`, with matching CLI commands. It signs artifact
    digests only, derives the signer principal from the authenticated token/session,
    requires `keys:write` plus `Idempotency-Key`, records `codesign.*` events, and
    queues Rekor publication through the `transparency.rekor` outbox destination. The
    surface is fail-closed until the deployment composition supplies a
    `CodeSigningConfig` with a key resolver, Fulcio-style attestors, and transparency
    handler. Responses are trstctl JSON signature receipts; byte-for-byte external
    cosign bundle encoding remains deployment validation work.

  Each protocol surface is gated by `protocols.<name>.enabled` and binds a tenant via
  `protocols.<name>.tenant_id`. All protocol toggles default off until an operator
  explicitly binds the served endpoint to a tenant; if a protocol is enabled without a
  tenant, startup validation fails before the route is exposed (it must not mint or
  issue tenant-scoped evidence into a blank tenant — per-tenant isolation forbids it).
  All protocols activate only when an issuing CA is provisioned.
  - **Reference-implementation differentials.** Two protocols are cross-checked against
    an *independent* implementation, not just our own parser:
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
    go-spiffe `workloadapi` client fetches an X.509-SVID, fetches a JWT-SVID, fetches
    JWT bundles, and validates the JWT-SVID over the served UDS; stock `spiffe-helper`
    writes the served X.509-SVID, key, and trust bundle to disk.
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
  - **SSH KRL distribution format.** The SSH CA's key-revocation list is now emitted
    in the **OpenSSH binary KRL format**, the artifact `sshd`'s `RevokedKeys` and
    `ssh-keygen -Q -f` consume — verified end-to-end by a test that has stock
    `ssh-keygen` report a revoked certificate as revoked using trstctl's KRL (and a
    non-revoked one as valid). A legacy JSON revocation snapshot is retained for
    programmatic callers. The SSH CA is now **served** (`protocols.ssh.enabled`): cert
    issuance at `/ssh/...` and the binary KRL at `/ssh/krl`, the artifact a host's
    `RevokedKeys` consumes.
  - **Public-CA profile linter.** Issued certificates are checked by a built-in
    **structural RFC 5280 / CA-Browser-Forum profile linter** in the issuance test
    suite — version, serial bounds, validity ordering/length, basicConstraints, key
    usage, SAN presence, SKI/AKI presence, weak-signature and minimum-key-strength
    checks — and the suite is **red on a deliberately-broken profile**. The CI gate now
    also generates a PEM corpus for every emitted X.509 profile shape (served leaves,
    mTLS agent certificates, SPIFFE X.509-SVID, TSA, and the issuing CA), runs pinned
    **zlint** over the served CA plus that corpus, and uploads the generated fixtures
    and JSON lint transcripts as artifacts. This is a private-CA assurance gate (for
    your own internal PKI), not a claim that trstctl operates as a WebPKI public CA.
- **SPIFFE transport (Workload API):** the X.509-SVID *document* is spec-shaped (a
  single `spiffe://` URI SAN, correct key usage), and the Workload API is now
  **served as a gRPC service on a Unix domain socket** (`protocols.spiffe.enabled`).
  A `spiffe-helper`/go-spiffe/Envoy-SDS workload dials the socket for
  `FetchX509SVID`, `FetchX509Bundles`, `FetchJWTSVID`, `FetchJWTBundles`, and
  `ValidateJWTSVID`. The X.509-SVID workload key is minted server-side and returned in
  the response (per the spec); the X.509-SVID CA is the served issuing CA in the
  signer and the JWT-SVID signing key has its own signer handle. The Workload-API
  gRPC/protobuf contract is vendored verbatim from go-spiffe so the wire format is
  byte-identical without a build-time go-spiffe dependency.
- **SPIRE upstream authority:** the `trstctl-spire-upstream-authority` plugin is
  served for SPIRE X.509 upstream CA custody: SPIRE sends its local CA CSR to
  `/api/v1/ca/authorities/{id}/intermediates/csr`, trstctl signs it through the
  served CA hierarchy, and a real SPIRE server container mints an SVID chained to the
  trstctl root in CI. The plugin intentionally returns `Unimplemented` for SPIRE's
  optional JWT upstream publication RPC; it anchors X.509-SVID trust, while SPIRE's
  local JWT key remains SPIRE-managed for same-domain JWT-SVID use.
- **Attested issuance transport (REST):** `POST /api/v1/workloads/attested-issuance`
  is the served proof-before-trust mint for workloads that already have their own key
  pair. The request carries the attestation method, base64 proof payload, public key
  PEM, and requested TTL; the response carries the signer-issued X.509-SVID PEM,
  credential id, verified subject, expiry, and attestation metadata. The SPIFFE ID is
  derived from the verified attestation subject, not caller-supplied text. Acceptance
  coverage exercises a Kubernetes projected service-account token, an AWS
  instance-identity document with an emulated trusted root, idempotent replay, and a
  forged AWS document rejection.
- **AI-agent broker issuance (REST):** `POST /api/v1/broker/agent-identities` is
  served when the agent broker is configured with attestors, a policy module, trust
  domain, and signer-backed issuing CA. The route requires `certs:issue` and an
  `Idempotency-Key`; it verifies the agent proof, evaluates policy before signing,
  mints a short-lived X.509-SVID, records `certificate.recorded`, emits
  `agent.identity.issued` or `agent.identity.refused`, and projects the
  agent-to-credential edge into the graph. The React Workloads page still does not
  collect raw broker proof material; use the REST API or CLI for live broker mints.
- **Ephemeral / JIT issuance (REST):** `POST /api/v1/ephemeral` is served when
  ephemeral issuance is configured with attestors, approval TTL/threshold, trust
  domain, and signer-backed issuing CA. A requester with `certs:request` presents a
  proof and public key; trstctl verifies the proof, opens an approval request, and
  enqueues the approval notification intent in the same tenant transaction. A
  distinct approver with `certs:issue` records approval at
  `POST /api/v1/ephemeral/{request_id}/approvals`; the requester then calls
  `/api/v1/ephemeral` with a fresh `Idempotency-Key` to mint the short-TTL
  credential. Ephemeral API keys are served separately at
  `POST /api/v1/ephemeral/api-keys` and `trstctl-cli ephemeral api-keys issue`:
  callers provide `subject`, `scopes`, and `ttl_seconds`, the raw token is returned
  once, and the leaseworker emits `api_token.revoked` at expiry. The React Workloads
  page still does not collect raw proof material or render approval controls; use
  REST or `trstctl-cli ephemeral issue/approve` /
  `trstctl-cli ephemeral api-keys issue`.
- **Agent ↔ control-plane mTLS gRPC channel:** the agent steady-state channel is now
  **served by the running binary** when `agent_channel.enabled` (off by default — an
  upgrade does not silently open an agent port). The control plane mounts an
  **agent-facing gRPC listener** (default `:9443`) over **mutual TLS**, and an enrolled
  agent connects to it to (a) **heartbeat** its inventory/status — the server records
  the agent tenant-scoped under per-tenant database isolation and emits an
  `agent.heartbeat` event in the tamper-evident log — and (b) **renew its own
  certificate** before expiry — a fresh cert is minted through the **signer-custodied
  agent CA** (signed in the isolated signer through the single cryptography path),
  **idempotently** on the presented serial (deduplicated so a retry does not mint
  twice), recorded as an `agent.cert.renewed` event — and (c) **report local inventory**
  as metadata-only discovery findings, including public OS/Java/NSS/browser/Windows
  trust-store anchors and private-key-material locations/classifications from
  configured roots. Inventory reports create a tenant-scoped discovery source, run,
  finding rows, `discovery.*` events, and credential-graph nodes; they do not carry
  private keys, PEM/DER key bytes, or secret values, and secret-looking inline metadata
  keys are rejected before projection. The tenant is derived from the
  agent's **verified client-certificate SPIFFE SAN**, never a request field. The
  `GET /api/v1/agents` response also publishes the served
  `agent.mtls.ReportInventory` path and the endpoint source kinds accepted by that
  channel (`filesystem`, `pkcs11`, `windows-store`, `k8s-secret`, `trust-store`, and
  `private-key`), so the console can show a real endpoint-discovery capability panel
  instead of treating agent discovery as unavailable telemetry. The
  channel is behind its own bounded **agent worker lane** and per-connection gRPC
  stream cap, so a heartbeat or renewal storm sheds with `ResourceExhausted` rather than
  starving API, protocol, outbox, or signer capacity. Agents announce an explicit
  protocol/capability handshake and schedule heartbeats from the server hint with
  bounded jitter, so rolling upgrades and fleet restarts do not synchronize a thundering
  beat. The **agent CA key now lives in the isolated signer** under a stable handle, so
  it does **not** regenerate per boot — an agent's pinned CA **survives a control-plane
  restart** (the earlier in-process/per-boot stand-in is replaced when the channel is
  enabled, and the same signer-custodied agent CA also signs the bootstrap enrollment,
  so a bootstrap-enrolled agent is accepted on the steady-state channel). The shipped
  chart exposes the channel: when `agentChannel.enabled`, the control-plane **Service
  publishes the agent port `9443`** (`agent-grpc`), the container exposes it, and the
  **NetworkPolicy** admits it (from the configured `agentChannel.allowedCIDRs` plus the
  in-cluster peers the API admits) — so the fleet manifests
  (`deploy/kubernetes/daemonset.yaml`, the Windows MSI) that point agents at `:9443`
  reach a served port. This is distinct from the *isolated signer's* `:9443` (a
  signer-only Service under `signer.mode=isolated`, which admits only the control
  plane). An untrusted/unpinned agent client is rejected at the mutual-TLS handshake
  (fail-closed). Proven end-to-end by acceptance tests (real signer + embedded Postgres:
  enroll → heartbeat → endpoint inventory report → served API capability readback →
  Discovery findings → graph node, plus renew → idempotent retry → reject untrusted) and rendered-chart
  assertions.

## Revocation

Revoking a credential through the running binary is **real and recorded**, not a
no-op. Transitioning an identity to *revoked* drives the served outbox handler to:

- mark the issued certificate **revoked in the inventory** — via a projected
  `certificate.revoked` event, so the status is reconstructable from the log on a
  read-model rebuild, and the certificate API now returns `status` / `revoked_at` /
  `revocation_reason` so the revocation is **visible** on the served surface (a revoked
  cert reads `"revoked"`, not silently `"active"`); and
- project the certificate's serial into the **revocation read model** from the same
  event, so OCSP/CRL state is rebuilt from the log instead of from a side write.

The **online revocation-distribution surface is now served**: the running binary
mounts an RFC 6960 **OCSP responder** at `/ocsp/{tenant}` (GET base64-in-path and POST
`application/ocsp-request`) and an RFC 5280 **CRL endpoint** at `/crl/{tenant}`, and
runs a background **freshness scheduler** that regenerates each tenant's CRL ahead of
its `nextUpdate`. Trusted issue, renewal, revocation, protocol-enrollment, and
scheduler paths publish CRLs; public `GET /crl/{tenant}` is read-only and returns 404
until a CRL is already published for a tenant that has issued certificates. A query for
a revoked serial returns `revoked` over OCSP and the serial appears on the CRL within
the freshness window; a query for an issued-but-not-revoked serial returns `good`; an
unknown serial returns a signed `unknown`. These endpoints are **public by RFC design**
(relying parties check status without credentials) but run on the API worker lane, so
an OCSP/CRL flood sheds rather than starving the rest of the control plane.

OCSP responses and CRLs are **signed through the out-of-process signer**: the signing
op crosses the single isolated cryptography path using the same signer-held CA key the
leaf path uses, so the CA private key **never materializes in the control plane** —
only the digest crosses. Every query is tenant-scoped under per-tenant database
isolation. Each published CRL emits a `ca.crl.published` event that carries the CRL DER
and validity window, so the published-CRL read model is rebuilt from the event log.

This is exercised end to end in CI (issue → revoke → assert OCSP returns
`revoked` (and `good` before revocation) and the CRL lists the serial within the
freshness window, with both signatures verifying against the issuing CA, driven
over real HTTP against the assembled binary and the real out-of-process signer).

The **CDP/AIA pointers** stamped on issued leaves are operator-configured
(`ca.crl_distribution_points` / `ca.ocsp_servers`) because the
externally reachable URL is deployment-specific; point them at the binary's
`/ocsp/{tenant}` and `/crl/{tenant}` (behind your ingress) so relying parties
discover and fetch revocation status automatically. trstctl revocation is now
both authoritative in the product's own inventory/records **and** publishable to
external relying parties over served OCSP/CRL.

## Single sign-on

trstctl's interactive sign-on is **served for OIDC, SAML 2.0, and LDAP / Active
Directory**. OIDC supports the authorization-code flow against Microsoft Entra ID /
Azure AD, Okta, Ping, Google, Auth0, Keycloak, and similar providers. SAML serves a Service Provider with
SP-initiated login (`/auth/saml/login`), IdP-initiated login through the ACS
(`/auth/saml/acs`), and SP metadata (`/auth/saml/metadata`). SAML assertion
verification requires configured IdP metadata and accepts signed HTTP-POST binding
responses; it does not yet expose artifact binding, encrypted assertion decryption,
or SLO/logout propagation. LDAP / Active Directory serves username/password bind at
`POST /auth/ldap/login`, supports direct-bind or service-account user search plus
group search, and maps directory groups to tenant roles. It does not yet implement
Kerberos/GSSAPI, NTLM, password-change flows, nested-group expansion, or directory
writeback. API/CI access still uses scoped API tokens.

## CA key custody

The assembled issuing CA's key is now **persisted, sealed at rest** in the
signer's key store: a signer restart **preserves** the CA instead of
silently rotating it, and the key survives across restarts. Root/intermediate
m-of-n ceremonies and signer-backed leaf issuance are now served. Local PKCS#11
custody has a real cgo module binding that is proved against SoftHSM for
token-side RSA-2048 generate/sign, but the default release binaries remain static
and use the sealed local key file unless an operator builds and wires the
signer/control-plane package for the PKCS#11 module. Online break-glass emergency
issuance and break-glass rotation/cross-sign workflows are still future work.
Break-glass bundle reconciliation is served separately at
`POST /api/v1/breakglass/reconcile`. The key-encryption key is a local file by default.
See the [key-ceremony runbook](runbooks/key-ceremony.md),
[incident response](runbooks/incident-response.md), and
[disaster recovery](disaster-recovery.md).

**In-memory custody of the reference-path CA keys.** The served CA-hierarchy path
does not use these in-process reference keys: it binds each served root/intermediate
to an isolated-signer handle. The library reference manager still holds live ECDSA
signing keys in **locked, wipeable secret buffers** (`mlock` + `MADV_DONTDUMP`)
rather than as a bare unprotected key on the garbage-collected heap for the lifetime
of the in-process CA; the key is reconstructed only for the instant of each
signature and the transiently parsed copy is best-effort zeroized afterward (the
same hardening the isolated signer uses). This narrows - but, given Go's runtime,
does not eliminate - the window in which an unprotected key sits in dumpable heap; it
is complemented process-wide by `RLIMIT_CORE=0` / `PR_SET_DUMPABLE=0`.

**BYOK / HSM key lifecycle.** trstctl provides a full bring-your-own-key / HSM key
lifecycle behind the single isolated cryptography path (an in-process path for local
keys and a remote-key-lifecycle path for HSM/KMS-resident keys), covering
**generate-or-import → rotate → revoke → zeroize** for CA/issuing signing keys and the
secrets key-encryption key (KEK):

- every transition is recorded as an **immutable event** and carries the key's
  identity, version, and public key — never its private bytes;
- key material lives only in **locked, zeroizable memory** (wipeable secret buffers),
  never as a string; on rotate the superseded material is destroyed and on zeroize the
  buffer is wiped, after which the key can no longer sign or wrap (fail-closed);
- for an **HSM/KMS-resident** key the private key never enters the control-plane
  address space at all: rotate mints a successor at the provider, revoke disables
  the key (the provider refuses further signatures), and zeroize schedules the
  provider's destruction of the material — the durable custody story.

The **HSM/KMS-resident lifecycle is now served end to end**: the running control plane
exposes `POST /api/v1/managed-keys` (generate) and
`/api/v1/managed-keys/{rotate,revoke,zeroize}`, with a matching `trstctl managed-keys
{generate,rotate,revoke,zeroize}` CLI. Each verb is tenant-scoped under per-tenant
database isolation, idempotent (deduplicated by `Idempotency-Key`), and recorded as
immutable events; the three **destructive** transitions (rotate/revoke/zeroize) require
a **distinct-approver dual-control approval** — the same four-eyes machinery the
issuance gate uses — before the provider is ever called, so no single operator can
rotate, disable, or destroy a managed key. The surface is served only when a KMS/HSM
custody backend is configured; otherwise the routes fail closed.

For cloud custody, AWS KMS is wired into that served path through `managed_keys`
configuration. The backend uses the official AWS SDK v2 KMS client. The acceptance
suite starts LocalStack, generates a KMS-resident RSA-2048 managed key through the
real API, rotates it, zeroizes the successor, and revokes a second key; when standard
`AWS_*` credentials are present, the same test also runs against real AWS KMS. The
current startup config is static and provider-selected: it does not load runtime
crypto plugins or let policy choose provider algorithms at request time.

For local HSMs, the PKCS#11 backend has a real native binding in addition to the
injected unit-test seam. The CI acceptance initializes a SoftHSM token in a
container, creates a sensitive non-extractable RSA-2048 signing key on the token,
signs through the module, and verifies the public key through the same backend
conformance harness used by software and cloud KMS backends. The static default
build keeps cgo disabled; PKCS#11 deployments opt into the cgo build and module
configuration explicitly.

Still **library-tier** (reachable from no served verb yet): the **in-process** key
lifecycle for the local CA/issuing signing key and the secrets KEK (generate-or-import
→ rotate → revoke → zeroize is implemented and end-to-end tested but not yet exposed as
its own served route), plus online **m-of-n break-glass issuance**, rotation, and
cross-signing. Break-glass reconciliation is served at
`POST /api/v1/breakglass/reconcile`, but emergency issuance remains the offline
operator ceremony. The signer's at-rest CA key is still sealed under a local
key-encryption file by default. See the
[key-ceremony runbook](runbooks/key-ceremony.md),
[incident response](runbooks/incident-response.md), and
[disaster recovery](disaster-recovery.md). The remaining external residual is the
**product NIST CMVP certificate** (see
[compliance → FIPS](compliance.md#fips-cryptography--a-fips-capable-build-path)),
a lab process software cannot perform.

**Signer UDS peer-uid is Linux-only.** The signing service's
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

trstctl's cryptography sits behind one isolated path, and the post-quantum support
lives there — ML-DSA, ML-KEM, the hybrid scheme, and SLH-DSA — all built on
Cloudflare's CIRCL. What is available today:

- **ML-DSA** (FIPS 204; `mldsa44` / `mldsa65` / `mldsa87`) — the NIST-standard
  lattice signature.
- **ML-KEM** (FIPS 203; `mlkem512` / `768` / `1024`) — the NIST-standard key
  encapsulation. trstctl can generate ML-KEM keys, encapsulate to an ML-KEM public key,
  and decapsulate the resulting ciphertext; all three parameter sets are checked against
  FIPS 203 known-answer vectors. The served HTTPS and mTLS listeners prefer
  `X25519MLKEM768` for TLS 1.3 hybrid key exchange when a peer supports it, with
  classical TLS 1.3 groups retained for compatibility.
- **SLH-DSA / SPHINCS+** (FIPS 205; `SLH-DSA-SHA2-128s` / `128f` / `192s` / `256s`) —
  the NIST-standard stateless **hash-based** signature. Its security rests only on the
  hash function, so it is the conservative choice for long-lived roots where you want
  assumptions independent of the lattice schemes; the trade-off is much larger
  signatures.
- **A hybrid signature** (`HybridEd25519Dilithium3`) — classical Ed25519 paired with
  ML-DSA, so breaking either component alone does not forge a signature.

Private key material is held in locked, zeroized buffers and parsed only for
the moment of each operation, exactly like classical keys. The isolated signer can now
generate and use signer-held ML-DSA and SLH-DSA keys over its UDS or mTLS gRPC channel,
and those keys are sealed in the signer key store so a restart does not silently rotate
them. ML-KEM is not exposed as a signer key because it is encapsulation, not a signature;
use it as the key-establishment primitive for protocol wiring rather than as an issuing
CA key.

The served CA can mint a hybrid transition leaf: the certificate remains a normal
ECDSA P-256 leaf for stock TLS clients, while a signed ML-DSA-44 + ECDSA-P256 composite
binding is carried inside the certificate for PQ-aware verifiers. That makes the
migration deployable without forcing every client to understand draft composite public
keys on day one. The ACME, EST, SCEP, and CMP served enrollment paths all run through
that same issuer, so a CSR with the hybrid proof can be profile-gated and issued through
those protocols using the `Hybrid-ML-DSA-44-ECDSA-P256` profile algorithm label.

The discovery side knows these algorithms too — the **CBOM** scanner recognizes ML-DSA,
ML-KEM, and SLH-DSA / SPHINCS+ as quantum-safe when it finds them in your estate. Because
all cryptography enters through one isolated path, each scheme is a contained boundary
implementation (a CIRCL scheme plus known-answer tests), with no ripple into the rest of
the system. The served CBOM inventory exposes this posture through
`GET /api/v1/cbom/assets`: classical signing algorithms are mapped to ML-DSA/FIPS 204
targets, weak TLS protocol or cipher findings are mapped to ML-KEM/FIPS 203, DSA is
mapped to SLH-DSA/FIPS 205, and `migration_progress` shows how much of the observed
estate is already post-quantum-ready.

What is **not yet** end-to-end is pure ML-DSA subject certificates through every stock
client, a multi-key SPIFFE Workload API response for useful hybrid SVID private-key
delivery, and automated rollout for every TLS protocol/cipher finding. The served PQC
migration trigger now covers CBOM certificate-key assets: it queues ACME re-issuance
through the outbox, mints the deployable `Hybrid-ML-DSA-44-ECDSA-P256` transition leaf,
projects `migration_progress`, and supports evented rollback. The crypto primitives,
isolated-signer signing path, served hybrid leaf assembly, ACME/EST/SCEP/CMP hybrid
issuance, and hybrid TLS key exchange are in place; the remaining work is broader
protocol/client compatibility and deployment automation. See
[Lifecycle & PQC](features/lifecycle-and-pqc.md) for the current state of that tooling.

## Kubernetes deployment

The control plane ships a production-shaped **Helm chart** (`deploy/helm/trstctl`):
the API/UI with the **signing service isolated** (its own locked-down, network-
unreachable sidecar), external PostgreSQL and NATS as the default, a default-deny
`NetworkPolicy`, and TLS.

- **Kubernetes Operator scope.** A **focused** CRD-driven operator ships today:
  the `trstctl-operator` binary (it rides inside the same multi-binary
  control-plane image and is run by `deploy/operator/operator.yaml` via an
  entrypoint override) reconciles `TrstctlControlPlane` custom resources into a
  managed control-plane Deployment. The **Helm chart** remains the richer path
  for the full production install. The operator keeps the managed Deployment's
  replica count, image, PostgreSQL DSN Secret reference, NATS URL/replica knobs, sidecar-signer
  socket/volumes, and managed-key provider enablement matching each resource's
  `spec`, and writing the observed phase back to the resource status. It is a
  real, level-based reconcile loop (poll, diff, converge), not a stub; it speaks
  the Kubernetes API directly (no client-go/controller-runtime). The shipped
  operator manifest runs **two replicas** and `--leader-elect`; the replicas
  coordinate with a real `coordination.k8s.io` Lease so exactly one reconciles
  while the other remains a hot follower. It is still focused: it does **not** yet
  manage Services, ingress, `NetworkPolicy`, Secret creation, or the cross-pod
  isolated-signer Service topology. For a complete, production-shaped
  control-plane install (ingress/service wiring, generated secrets,
  default-deny `NetworkPolicy`, cross-pod signer mTLS) the **Helm chart**
  (`deploy/helm/trstctl`) remains the richer, recommended path.
- **cert-manager external issuer.** The Kubernetes agent ships a real trstctl
  `Issuer`/`ClusterIssuer` controller for cert-manager. It marks the trstctl
  issuer resources Ready, signs matching `CertificateRequest`s through a served
  trstctl issuance endpoint using a mounted API token, and is proven in CI on
  `kind` with real cert-manager from `Certificate` to TLS `Secret`. It is still a
  small poll-based controller rather than an informer/work-queue controller; that
  is an operational efficiency tradeoff, not a functional gap.
- **Multi-replica HA.** The Helm chart runs the control plane **multi-replica by
  default** (`replicaCount: 2`, `RollingUpdate maxUnavailable: 0`, PodDisruptionBudget,
  pod anti-affinity), and running >1 replica is **safe**: **leader election** (a
  PostgreSQL session-scoped advisory lock) gates the continuous background workers —
  the outbox dispatcher, audit retention, idempotency/outbox GC, the projection tailer,
  the CRL scheduler, and the read-model snapshot worker — to exactly one replica so
  they never double-apply, with automatic failover to a follower on leader loss; all
  replicas serve reads. A **shared signer key store**
  (`persistence.signerKeysAccessMode: ReadWriteMany`) means every pod's locked-down
  sidecar signer (the isolated key-holder process) loads the SAME sealed issuing-CA
  key, so all replicas are the same CA (first-boot provisioning is serialized by an
  advisory lock). For a single signer pod that serves all replicas **independently**,
  set `signer.mode: isolated`: the signer runs as its own pod reached over a
  **cross-node mTLS gRPC channel** — TLS 1.3, AEAD-only, with the control plane and the
  signer each **pinning** the other's certificate (an untrusted or merely
  CA-signed-but-unpinned peer is rejected). This is now **implemented**: the
  `trstctl-signer` binary serves `--mtls-listen` and the control plane dials it with
  `signer.mtls_address`; the chart renders the signer Deployment/Service/NetworkPolicy
  on `:9443` when you supply the `signer.mtls.*` certificate material. The default
  co-located sidecar (UDS) topology remains the simplest single-pod option and is not
  required to change for the HA above. See
  [disaster recovery → High availability](disaster-recovery.md). (The agent,
  separately, runs as a DaemonSet across all nodes.)
- **Cross-cluster federation is passive read-state replication.** A passive cluster can
  import a peer event log, keep a durable per-peer cursor, and project the imported
  tenant/trust/certificate/audit read state locally for failover. It is intentionally
  not an active-active write conflict resolver: keep one writable region for a tenant
  at a time, stop or fence primary writes before promotion, and use
  `TRSTCTL_FEDERATION_RPO` / `TRSTCTL_FEDERATION_RTO` as measured runbook targets.

## Non-functional targets: what is measured vs. aspirational

We separate NFRs that have **executable evidence** from ones that are **aspirational
and not yet measured** in CI, so neither is silently over-claimed.

- **Performance & scale NFRs are measured.** The hot-path latency/throughput SLOs and
  the capacity model are pinned to committed measurement receipts by an executable
  smoke gate (`make perf-smoke`) and a served realistic/peak live-load gate
  (`make perf-live`), and sustained-load endurance is pinned by a **soak gate**
  (`make soak`) that fails on a leak slope or an SLO breach. These are local
  eval/self-test scale denominators, not a substitute for a customer-specific
  multi-hour load test at your own capacity tier.
- **Usability outcome NFRs are aspirational and unmeasured.** Targets such as a
  **timed first-run / time-to-first-certificate** wall-clock budget and any
  **operator-satisfaction / NPS** goal are **design aspirations**, not facts the
  product measures: there is **no automated CI measurement** of first-run wall-clock
  time or operator satisfaction, and no published timed-first-run or NPS receipt.
  The getting-started flow is exercised for *correctness* end-to-end (and issuance is
  *latency*-measured per the SLOs above), but the human *time-to-success* and
  *satisfaction* numbers are not benchmarked. Treat any such figure as a goal to
  validate with real operators, not a guarantee.

## How to read the roadmap against this

The [README capability table](https://github.com/ctlplne/trstctl#capabilities)
describes what is **built and tested**; this page tells you what is **served by the
binary today**. When the two differ, this page is the authority for what you can
rely on at runtime.
