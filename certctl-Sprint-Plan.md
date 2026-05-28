# certctl — Sequential Sprint Backlog

**Companion to:** the PRD (v0.4) and the root `CLAUDE.md`.
**Purpose:** a sequential, dependency-ordered list of small sprints, each sized to be
one focused agent session that produces one reviewable PR. Each sprint is written so
it converts cleanly into a prompt.

## How to read a sprint card

Every card carries the same fields. *Implements* lists the PRD feature (F) and
architecture (AN) IDs the sprint delivers. *Depends on* lists sprints that must be
merged first. *Goal* is the one-or-two-sentence intent. *Scope* states what is in and,
where it matters, what is deliberately out. *Acceptance* is the set of testable checks
that define done for this sprint (these become the failing tests written first).

## The drop-in prompt

Every card below is self-contained: it carries its own goal, scope, dependencies, and
acceptance criteria, and the standing rules and working loop live in `CLAUDE.md`, which
the agent reads on every task. A sprint prompt therefore restates none of that — you
only name the sprint. Keep this backlog in the repo (for example at
`docs/sprint-backlog.md`) so a sprint ID resolves to a real card for the agent.

Use this prompt verbatim, changing only the ID. One sprint per prompt:

> **Implement sprint [ID] from the sprint backlog, completely.** Write the failing
> tests for its acceptance criteria first, then implement, then make lint + test + CI
> green, then open one PR scoped to this sprint.

That is the whole prompt. The card supplies the *what*; `CLAUDE.md` supplies the *how* —
read the named card, confirm its dependencies are merged, hold the non-negotiables, stay
inside its scope, and finish with everything green. If you ever need to bend scope for a
one-off, add a sentence after the template; otherwise the default path is just the ID.

## Sequencing philosophy

The bedrock and its enforcing linter come before any feature (Epoch 0–1). A walking
skeleton validates the event-sourcing spine before breadth (Epoch 2). The signing
service and the SSH trust-rewrite each get a design spike before their build sprint,
because each is a place where a mistake is catastrophic. Repetitive breadth (CA
plugins, connectors, attesters, SDKs) uses a template sprint plus one small sprint per
instance. Foundation epochs are necessarily horizontal; once the spine exists, feature
sprints are vertical slices that each produce something demonstrable.

The cards below are fully detailed through Phase 1 (Epochs 0–7), where foundational
correctness matters most and you will start. Phase 2 and Phase 3 (Epochs 8–9) are
given at sprint granularity with goal, IDs, dependencies, and key acceptance — ask me
to expand any of them into full prompt-ready cards when you reach them, since their
detail will firm up as Phase 1 lands.

---

# PHASE 1 — CLM Foundation + Architectural Bedrock

## Epoch 0 — Project bedrock and guardrails

### S0.1 — Repository, module layout, and CI scaffolding
- **Implements:** project skeleton (no features).
- **Depends on:** none.
- **Goal:** Stand up the Go module, the directory layout from CLAUDE.md, and a CI
  pipeline that builds, tests, and lints an empty skeleton.
- **Scope:** Go module init; the package directories; a `Makefile`/`Taskfile` with
  `build`, `test`, `lint`, `run`; CI workflow running all three on every PR;
  reproducible-build flags; basic `cmd/certctl` that boots and exits cleanly.
- **Acceptance:** `make build`, `make test`, and `make lint` all succeed on the empty
  skeleton; CI runs them on a PR and reports status; the binary starts and shuts down
  cleanly with a `--version` flag.

### S0.2 — The architecture linter (`tools/certctllint`)
- **Implements:** enforcement of AN-3, AN-1, AN-5, AN-8.
- **Depends on:** S0.1.
- **Goal:** Build the custom `go/analysis` linter that makes the non-negotiables
  un-violable, and wire it CI-blocking. This is the single most leveraged sprint in
  Phase 1 — do it before any feature.
- **Scope:** Start with the two highest-value rules fully working — no `crypto/*`
  outside `internal/crypto` (AN-3), and no repository query missing a `tenant_id`
  filter (AN-1) — plus working-but-narrow rules for no-`string`-in-key-packages (AN-8)
  and idempotency-on-mutations (AN-5) that will tighten as those subsystems land.
- **Acceptance:** each rule fails a deliberately-violating fixture and passes a clean
  fixture; the linter runs in CI and blocks merge on violation; rules are individually
  testable; a documented escape hatch exists only via fixing the rule, not via blanket
  ignores.

### S0.3 — Config, structured logging, and the error model
- **Implements:** cross-cutting plumbing; RFC 7807.
- **Depends on:** S0.1.
- **Goal:** Provide configuration loading, structured JSON logging, and the
  problem+json error type the whole API will use.
- **Scope:** config from environment plus file, including the "bundled vs external
  datastore" switches; `slog`-based JSON logging; an RFC 7807 problem+json error type
  and helpers; no business logic.
- **Acceptance:** config loads and validates from both sources with precedence rules
  tested; logs are structured JSON with consistent fields; problem+json serializes to
  the RFC shape and round-trips in tests.

## Epoch 1 — Crypto and signing core

### S1.1 — The `internal/crypto` boundary with a software backend
- **Implements:** AN-3.
- **Depends on:** S0.2.
- **Goal:** Define the backend-agnostic crypto interfaces and implement the software
  (Go stdlib) backend for RSA and ECDSA, with nothing else in the tree importing
  `crypto/*`.
- **Scope:** `Signer`, `KeyGenerator`, and related interfaces; software backend; key
  and algorithm types; the boundary is the only place `crypto/*` appears.
- **Acceptance:** generate and sign with RSA and ECDSA through the interface; the
  AN-3 linter rule is green across the tree; swapping backends requires no caller
  changes (proven by a fake backend in tests).

### S1.2 — Memory-safe key handling primitives
- **Implements:** AN-8.
- **Depends on:** S1.1.
- **Goal:** Provide the `[]byte`-based, `mlock`'d, non-dumpable, explicitly-zeroed key
  buffer primitives that all key material flows through.
- **Scope:** secret buffer type; `mlock` and `MADV_DONTDUMP`; explicit zeroization;
  `memguard` integration or equivalent; the AN-8 linter rule tightened to cover these
  packages.
- **Acceptance:** key buffers are mlocked and excluded from core dumps (verified on
  Linux); zeroization is proven by test; a fuzz test exercises the zero path; the AN-8
  rule flags any `string` in these packages.

### S1.3 — Signing service: design spike
- **Implements:** AN-4 (design only).
- **Depends on:** S1.1, S1.2.
- **Goal:** Produce the threat model and protocol design for the isolated signing
  service before building it, because it is the one component whose compromise ends
  the company.
- **Scope:** a short threat-model and design doc covering the process boundary, the
  gRPC-over-UDS protocol, the minimal dependency set, memory-safety obligations, and
  the fuzzing plan. No production code beyond protocol stubs.
- **Acceptance:** the design doc is reviewed and committed under `docs/design/`; the
  protocol is specified precisely enough to implement; the dependency budget is
  explicit.

### S1.4 — Signing service: implementation
- **Implements:** AN-4, AN-8.
- **Depends on:** S1.3.
- **Goal:** Build `cmd/certctl-signer` as a separate process that signs over gRPC/UDS,
  with no HTTP, no SQL, and a minimal audited dependency surface.
- **Scope:** the signer binary; gRPC server on a UDS; sign requests served by the
  software backend; memory-safe handling per AN-8; fuzzing of the protocol parser; the
  control plane launches it as a child process in single-node mode.
- **Acceptance:** the signer runs as its own process; the control plane signs a test
  CSR through it over UDS; the protocol parser passes its fuzz corpus; a static check
  confirms no HTTP server and no SQL driver are linked into the signer.

### S1.5 — PQC algorithms behind the boundary
- **Implements:** F16.
- **Depends on:** S1.1, S1.4.
- **Goal:** Add ML-DSA, ML-KEM, and hybrid as first-class algorithms behind the AN-3
  boundary, proving crypto-agility paid off.
- **Scope:** PQC backends/algorithms; policy-selectable algorithm choice; a crypto
  inventory classification hook that tags credentials by algorithm and
  quantum-vulnerability status; note the FIPS-build caveat from the PRD.
- **Acceptance:** generate and sign with ML-DSA; select algorithm by policy; the
  change touches only `internal/crypto` and the signer (demonstrating AN-3); inventory
  classification returns correct algorithm/vulnerability tags.

## Epoch 2 — Event-sourced spine and multi-tenancy

### S2.1 — Event log on NATS JetStream
- **Implements:** AN-2.
- **Depends on:** S0.3.
- **Goal:** Provide the append-only event log as the source of truth, embedded and
  file-backed for single-node and external-cluster-ready for production.
- **Scope:** event envelope schema; append and replay; embedded JetStream for
  single-node; external-cluster configuration; the `Event` entity.
- **Acceptance:** events append and replay deterministically; embedded mode works with
  no external services; switching to an external cluster is config-only; ordering and
  durability are tested.

### S2.2 — PostgreSQL projections and tenant isolation
- **Implements:** AN-1, AN-2.
- **Depends on:** S2.1, S0.2.
- **Goal:** Build the PostgreSQL schema with `tenant_id` everywhere and RLS policies,
  plus projection workers that derive read state from the event stream.
- **Scope:** migrations; `tenant_id` on every table; RLS policies; the `Tenant`
  entity; projection workers; single-tenant runs with one tenant.
- **Acceptance:** events project into Postgres read models; RLS denies a cross-tenant
  read in tests; the AN-1 linter rule is satisfied by all repository code; rebuilding a
  projection from the log reproduces state.

### S2.3 — Walking skeleton: one end-to-end command
- **Implements:** spine validation.
- **Depends on:** S2.1, S2.2.
- **Goal:** Prove the whole spine with one trivial command flowing API → event →
  projection → read, before any breadth.
- **Scope:** a throwaway-simple command (for example, register a tenant) implemented
  end-to-end through the real spine; an integration test against real Postgres and
  embedded NATS.
- **Acceptance:** the command emits an event, a projection updates, and a read returns
  the result; the integration test exercises the real spine, not mocks.

### S2.4 — Idempotency on mutations
- **Implements:** AN-5.
- **Depends on:** S2.3.
- **Goal:** Make every state-changing operation idempotent via an `Idempotency-Key`
  recorded with the operation.
- **Scope:** idempotency key storage and lookup in the orchestrator path; replay
  returns the original result; concurrent-retry safety.
- **Acceptance:** a replayed key returns the cached result without re-executing;
  concurrent identical requests produce one effect; the AN-5 linter rule is tightened
  to require key handling on mutating handlers.

### S2.5 — Outbox dispatcher
- **Implements:** AN-6.
- **Depends on:** S2.4.
- **Goal:** Route every external call through an outbox written in the same
  transaction as the state change, dispatched by a separate worker.
- **Scope:** the `outbox` table; transactional write alongside state; the dispatch
  worker; at-least-once delivery with idempotent effect; observable retries.
- **Acceptance:** a crash between state write and dispatch recovers and still
  delivers; duplicate dispatch yields one effect; retry state is observable in tests.

### S2.6 — Bulkheads and backpressure
- **Implements:** AN-7.
- **Depends on:** S2.5.
- **Goal:** Give each subsystem its own bounded worker pool and fast-reject behavior so
  no subsystem can starve another.
- **Scope:** a reusable bounded-pool abstraction; per-subsystem queues; structured
  backpressure errors; wiring for the subsystems that exist so far.
- **Acceptance:** a saturated pool rejects fast with a structured error and does not
  block other pools; a load test demonstrates isolation between two subsystems.

## Epoch 3 — Data model, orchestration, API, auth

### S3.1 — Core data model and tenant-guarded repositories
- **Implements:** data model; AN-1.
- **Depends on:** S2.2.
- **Goal:** Implement the top-level entities and their repositories, all tenant-scoped.
- **Scope:** `Identity` (X509Certificate | SSHCertificate | SSHKey | Secret | APIKey |
  WorkloadIdentity), `Owner`, `Issuer`, `DeploymentTarget`, `Agent`, `PolicyBinding`,
  `Attestation`, `Tenant`; repositories; migrations.
- **Acceptance:** entities persist and load via tenant-guarded repositories; the AN-1
  rule is green; the `Issuer` model distinguishes an X.509 CA from the chainless SSH CA.

### S3.2 — Orchestrator and lifecycle state machine
- **Implements:** orchestrator core.
- **Depends on:** S3.1, S2.5.
- **Goal:** Provide the lifecycle state machine for an identity and the job scheduling
  around it.
- **Scope:** states (requested → issued → deployed → renewing → revoked → retired);
  transition rules emitting events; invalid-transition rejection; outbox-driven side
  effects.
- **Acceptance:** valid transitions emit the right events; invalid transitions are
  rejected with structured errors; transitions are reconstructable from the log.

### S3.3 — REST API v1 with OpenAPI 3.1
- **Implements:** F10.
- **Depends on:** S3.2, S2.4.
- **Goal:** Expose resource-oriented REST with cursor pagination, problem+json errors,
  and idempotency on mutations.
- **Scope:** `/api/v1/` CRUD plus lifecycle operations for core resources; generated
  OpenAPI 3.1 spec; cursor pagination; idempotency headers honored.
- **Acceptance:** the OpenAPI spec is generated and valid; contract tests cover CRUD
  and lifecycle; mutations honor idempotency; errors are problem+json.

### S3.4 — gRPC agent transport over mTLS
- **Implements:** F15.
- **Depends on:** S3.2, S1.4.
- **Goal:** Stand up the agent-facing gRPC channel with mTLS, platform-issued
  rotating client certificates, and no plaintext path.
- **Scope:** gRPC server for agents; mTLS with TLS 1.3 and AEAD-only suites enforced
  at build time; platform-issued client certs with 24h TTL and auto-rotation; server
  cert pinning by the agent.
- **Acceptance:** an agent establishes mTLS and is refused without a valid client
  cert; client certs rotate before expiry; a build-time check rejects non-AEAD suites;
  there is no plaintext fallback.

### S3.5 — RBAC
- **Implements:** F8.
- **Depends on:** S3.3.
- **Goal:** Add role-based access with project/team scoping and custom roles.
- **Scope:** built-in roles; custom roles; project/team scopes; enforcement
  middleware on the API.
- **Acceptance:** allow/deny is enforced per role and scope with tests; custom roles
  work; scoping respects tenant boundaries.

### S3.6 — OIDC and SAML SSO
- **Implements:** F13.
- **Depends on:** S3.3.
- **Goal:** Provide OIDC and SAML 2.0 login plus scoped API tokens, never gated behind
  a paid tier.
- **Scope:** OIDC bearer for UI/CLI; SAML 2.0; API tokens with scopes for CI/CD.
- **Acceptance:** an OIDC login flow issues a session; SAML assertion is validated;
  API token scopes are enforced; nothing here is gated.

### S3.7 — Audit log surfaces
- **Implements:** F9.
- **Depends on:** S3.3, S2.1.
- **Goal:** Expose query, search, filter, and export over the event-sourced audit log,
  including a signed evidence bundle.
- **Scope:** audit query/search/filter API and CLI/UI hooks; signed
  evidence-bundle export for auditors; the log itself remains the AN-2 source of truth.
- **Acceptance:** audit queries return correct slices of the log; a point-in-time
  query works; an exported evidence bundle verifies its signature.

## Epoch 4 — Certificate issuance, plugin host, CAs, ACME

### S4.1 — Certificate inventory
- **Implements:** F1.
- **Depends on:** S3.1.
- **Goal:** Model and store certificate metadata as the inventory backbone.
- **Scope:** cert metadata (subject, SAN, issuer, validity, owner, deployment
  location); ingest and query paths.
- **Acceptance:** certificates store and query with full metadata; inventory queries
  are tenant-scoped and paginated.

### S4.2 — Plugin host with capability sandbox
- **Implements:** F20.
- **Depends on:** S2.6.
- **Goal:** Build the WASM plugin host with capability-based permissions and a
  conformance suite, used by both CA plugins and connectors.
- **Scope:** wazero (or extism) host; capability grants (for example, "write
  filesystem only at path X"); the plugin SDK and conformance suite; sandboxing such
  that a plugin cannot exceed its grant at runtime.
- **Acceptance:** a hello-world plugin runs sandboxed; a plugin attempting an
  un-granted operation is denied at runtime; the conformance suite validates a sample
  plugin; the host is bulkheaded per AN-7.

### S4.3 — First CA plugin (Let's Encrypt)
- **Implements:** F4.
- **Depends on:** S4.2, S2.5, S1.4.
- **Goal:** Issue real certificates through one upstream CA via the SDK, on the
  outbox and idempotency paths.
- **Scope:** the Let's Encrypt CA plugin; issuance via outbox (AN-6) with idempotency
  (AN-5); signing through the signer.
- **Acceptance:** a real certificate is issued end-to-end through the plugin; a retried
  issuance does not mint two certs; the call is observable in the outbox.

### S4.4 — Built-in ACME server
- **Implements:** F5.
- **Depends on:** S4.3.
- **Goal:** Serve RFC 8555 ACME, brokering to a configured upstream CA, with the three
  standard challenge types.
- **Scope:** ACME endpoint; HTTP-01, DNS-01, TLS-ALPN-01; brokering to the upstream
  CA; differential tests against Boulder; property tests and fuzzing on the parser.
- **Acceptance:** cert-manager enrolls successfully against the server; the standard
  ACME compliance suite passes; the parser passes its fuzz corpus; differential tests
  agree with Boulder on the covered cases.

### S4.5 — Lifecycle automation
- **Implements:** F6.
- **Depends on:** S4.3, S3.2.
- **Goal:** Automate renewal, revocation, rotation, and expiration alerting.
- **Scope:** renewal at a configurable threshold; revocation; rotation; expiration
  alerts emitted to the notification surface.
- **Acceptance:** a cert auto-renews at threshold; revocation propagates; rotation
  produces a new credential and retires the old; alerts fire before expiry.

### S4.6 — CA plugin template
- **Implements:** F4 (template).
- **Depends on:** S4.3.
- **Goal:** Extract the Let's Encrypt plugin into a reusable CA-plugin template so each
  remaining CA is a small, near-identical sprint.
- **Scope:** a documented template and scaffolding for a CA plugin; the shared test
  harness.
- **Acceptance:** generating a new CA plugin from the template builds and passes the
  conformance suite with only CA-specific code filled in.

### S4.7–S4.13 — Remaining CA plugins (one small sprint each)
- **Implements:** F4.
- **Depends on:** S4.6.
- **Goal:** Add each remaining upstream CA from the template: **DigiCert CertCentral**,
  **Sectigo SCM**, **internal Microsoft ADCS** (DCOM/RPC), **EJBCA**, **Smallstep**,
  **AWS Private CA**, **GCP CAS**, **Azure Key Vault CA**.
- **Scope (each):** one CA plugin built from the S4.6 template.
- **Acceptance (each):** the plugin issues against that CA (or a faithful test
  double); it passes the conformance suite; it rides outbox and idempotency.

## Epoch 5 — Agent and deployment connectors

### S5.1 — Agent core (Linux) with bootstrap and local key ops
- **Implements:** F3 (agent base), EPIC-10, F15.
- **Depends on:** S3.4, S1.2.
- **Goal:** Build the Linux agent: register via bootstrap token or attestation, talk
  mTLS, and perform all key operations locally.
- **Scope:** agent binary; one-time bootstrap token and attestation registration; mTLS
  with rotating client cert; local key generation; private keys never leave the host.
- **Acceptance:** the agent registers and establishes mTLS; keys are generated locally
  and never transmitted; client cert rotates; the agent survives a control-plane
  restart.

### S5.2 — Agent key/cert destinations: filesystem and PKCS#11
- **Implements:** F3.
- **Depends on:** S5.1.
- **Goal:** Support filesystem and PKCS#11 (HSM) as key/cert destinations on the host.
- **Scope:** filesystem destination with correct permissions; PKCS#11 destination.
- **Acceptance:** a cert installs to the filesystem and to a PKCS#11 token (SoftHSM in
  tests) with verified permissions.

### S5.3 — Windows agent and certificate store
- **Implements:** F3; agent packaging.
- **Depends on:** S5.1.
- **Goal:** Bring the agent to Windows with CryptoAPI/cert-store support and an MSI
  installer.
- **Scope:** Windows build; Windows certificate store destination; signed MSI; service
  registration.
- **Acceptance:** the agent installs via MSI, registers as a service, and installs a
  cert into the Windows store; the binary is signed and its SHA-256 published.

### S5.4 — Kubernetes agent (DaemonSet) and secret/cert-manager bridge
- **Implements:** F3, F7 (K8s).
- **Depends on:** S5.1.
- **Goal:** Run the agent as a DaemonSet and integrate with Kubernetes secrets and
  cert-manager.
- **Scope:** DaemonSet packaging; direct K8s secret destination; cert-manager bridge.
- **Acceptance:** the agent runs as a DaemonSet, writes a cert into a K8s secret, and
  bridges to cert-manager in a kind/k3s test cluster.

### S5.5 — Connector SDK and template
- **Implements:** F7, F20.
- **Depends on:** S4.2.
- **Goal:** Provide the connector SDK and a template so each deployment target is a
  small sprint.
- **Scope:** connector SDK on the plugin host; capability grants for deployment;
  template and shared harness; outbox-driven delivery.
- **Acceptance:** a sample connector built from the template deploys via the sandbox
  with only granted capabilities and passes the conformance suite.

### S5.6–S5.13 — Deployment connectors (one small sprint each)
- **Implements:** F7.
- **Depends on:** S5.5.
- **Goal:** Add each initial connector from the template: **NGINX**, **Apache**,
  **IIS**, **HAProxy**, **F5 BIG-IP**, **AWS ACM**, **Azure Key Vault**, **GCP
  Certificate Manager**. (Kubernetes shipped in S5.4.)
- **Scope (each):** one connector built from the S5.5 template.
- **Acceptance (each):** the connector deploys a renewed cert to that target (or a
  faithful test double) idempotently via the outbox, and passes the conformance suite.

### S5.14 — Drift detection
- **Implements:** F18.
- **Depends on:** S5.2.
- **Goal:** Have the agent reconcile on-host credential state against declared state and
  act per policy.
- **Scope:** reconciliation of certs/credentials on the host vs the control plane;
  detection of replacement, deletion, permission change, relocation; per-class
  alert-only / alert-and-block / auto-remediate.
- **Acceptance:** each drift type is detected; each remediation mode behaves
  correctly; drift events are audited.

## Epoch 6 — Discovery, graph, monitoring, scoring

### S6.1 — Network handshake scanner (TLS)
- **Implements:** F2.
- **Depends on:** S4.1, S2.6.
- **Goal:** Discover certificates by non-invasive TLS handshakes over operator-defined
  ranges, bounded and backpressured.
- **Scope:** TLS-handshake scanner over IP/port ranges; merge into inventory;
  bounded-pool execution per AN-7.
- **Acceptance:** the scanner discovers certs over a test range and merges them;
  throughput is bounded and does not starve the API; it is non-invasive.

### S6.2 — Agent-based certificate discovery
- **Implements:** F3 (discovery).
- **Depends on:** S5.2.
- **Goal:** Inventory certificates the agent can see locally.
- **Scope:** discovery in filesystem, Windows store, PKCS#11, and Kubernetes secrets;
  merge into inventory.
- **Acceptance:** local certs across all four sources are discovered and reconciled
  into inventory.

### S6.3 — SSH credential discovery and inventory
- **Implements:** F42.
- **Depends on:** S6.1, S6.2.
- **Goal:** Bring SSH into the inventory: host keys via an SSH-handshake probe and user
  keys/`authorized_keys`/`sshd` trust via the agent, flagging orphaned standing access.
- **Scope:** SSH-handshake extension to the scanner; agent inventory of host keys, user
  keys, `authorized_keys`, `known_hosts`, and `sshd` trust config; orphan and
  standing-access flagging; feed into graph and risk scoring.
- **Acceptance:** SSH host keys are discovered by probe; the agent inventories on-host
  SSH material; orphaned keys are flagged; results appear in the inventory.

### S6.4 — Credential graph
- **Implements:** F21.
- **Depends on:** S6.2, S3.1.
- **Goal:** Model the inventory as a queryable graph of workloads, identities,
  credentials, resources, and connections.
- **Scope:** graph model; REST queries; a Cypher-style query for power users; the
  substrate for blast-radius, attestation chains, and scoring.
- **Acceptance:** the graph answers reachability and blast-radius queries over a seeded
  fixture; both REST and Cypher-style queries return correct results.

### S6.5 — Certificate Transparency monitoring
- **Implements:** F17.
- **Depends on:** S4.1.
- **Goal:** Watch CT logs for any certificate issued for the organization's domains and
  alert on shadow IT or rogue issuance.
- **Scope:** CT log watching across the standard ecosystem; detection of
  unexpected issuance; alerts into the shared notification surface.
- **Acceptance:** a newly logged cert for a watched domain raises an alert; known-good
  issuance does not; alerts share the expiration-alert surface.

### S6.6 — Credential risk scoring
- **Implements:** F19.
- **Depends on:** S6.4.
- **Goal:** Compute a composite risk score per credential to answer "what should I
  rotate first."
- **Scope:** score from age, exposure (graph degree), privilege class, rotation
  history, owner activity, inferred sensitivity; sortable, filterable, exposed in the
  API.
- **Acceptance:** scores compute over a fixture and rank sensibly; the score is
  sortable and filterable via the API; inputs are individually tested.

## Epoch 7 — CLI, UI, distribution, telemetry, docs (Phase 1 GA)

### S7.1 — CLI with full parity
- **Implements:** F11.
- **Depends on:** S3.3.
- **Goal:** Provide a CLI with feature parity to the API, suitable for CI/CD.
- **Scope:** commands across the API surface; machine-readable output; auth via API
  tokens.
- **Acceptance:** every core API operation has a CLI command; output is scriptable;
  CI-friendly auth works.

### S7.2 — Web UI shell, auth, and dashboards
- **Implements:** F12.
- **Depends on:** S3.6.
- **Goal:** Stand up the React/Vite/shadcn UI shell with auth and inventory dashboards.
- **Scope:** UI shell; OIDC login; dashboards; dark/light with system default;
  keyboard navigation; WCAG 2.1 AA baseline.
- **Acceptance:** login works; dashboards render inventory; accessibility checks pass
  on the shell; the UI is served from the binary in embedded mode.

### S7.3 — UI lifecycle workflows and first-run wizard
- **Implements:** F12; UX targets.
- **Depends on:** S7.2, S4.4, S5.1.
- **Goal:** Deliver search and lifecycle workflows plus a first-run wizard that hits the
  sub-15-minute time-to-first-cert target.
- **Scope:** search; issue/renew/revoke/deploy workflows; the "connect a CA, install an
  agent, issue your first cert" wizard; guiding empty states.
- **Acceptance:** a fresh install issues a first cert within 15 minutes via the wizard;
  a first agent registers within 5 minutes; lifecycle actions work from the UI.

### S7.4 — Distribution: signed OCI images, SBOM, Compose
- **Implements:** distribution.
- **Depends on:** S1.4, S0.1.
- **Goal:** Ship reproducible, signed, SBOM-bearing container images on GHCR plus a
  one-command Compose evaluation.
- **Scope:** distroless/scratch images under 20MB; cosign signing; CycloneDX SBOM;
  reproducible build; GHCR primary with Docker Hub mirror; `docker compose up` eval;
  external-datastore configuration documented and supported.
- **Acceptance:** images build reproducibly, are cosign-signed, and ship an SBOM;
  `docker compose up` brings up an evaluable control plane; pointing at external
  Postgres/NATS is a tested config.

### S7.5 — Opt-in telemetry
- **Implements:** F-telemetry (Section 8).
- **Depends on:** S3.3.
- **Goal:** Provide opt-in, off-by-default, non-PII telemetry.
- **Scope:** coarse metrics (instance count, anonymized ID, version, OS, credential
  count buckets); off by default; no credential metadata ever.
- **Acceptance:** telemetry is off unless enabled; payloads carry no PII or credential
  content; opt-in is explicit and documented.

### S7.6 — Documentation site and getting-started
- **Implements:** docs.
- **Depends on:** S7.3, S7.4.
- **Goal:** Publish the docs site and a getting-started path matching the sub-15-minute
  goal.
- **Scope:** docs site; install, getting-started, troubleshooting, uninstall; plugin
  and connector authoring guides.
- **Acceptance:** a new user reaches a first cert in under 15 minutes following the
  docs; install/uninstall are documented for all supported platforms.

**Phase 1 GA gate:** full CLM with ACME, 9 CA plugins, 8 connectors, agent on three OS
families, SSH discovery, CT monitoring, drift, risk scoring, graph, RBAC, SSO, audit,
signed distribution, and docs — all on the AN-1…AN-8 bedrock with the linter green.

---

# PHASE 2 — Workload Identity & Hardening (sprint-level; expand on demand)

- **S8.1 — KMS/HSM backends behind AN-3 (F26).** Add PKCS#11, AWS KMS, Azure Key
  Vault, GCP KMS, TPM, and YubiHSM as backends (one small sprint each, off a backend
  template). *Acceptance:* root/intermediate and the SSH CA key can be protected by
  each backend; change is confined to `internal/crypto` and the signer.
- **S8.2 — SPIFFE Workload API (F24).** Issue X.509-SVID and JWT-SVID over a Unix
  domain socket, compatible with SPIRE-aware apps. *Acceptance:* a SPIRE-aware client
  fetches and validates an SVID; differential test against a known-good implementation.
- **S8.3 — Workload attestation chain (F30).** Make attestation a first-class graph
  entity; add attesters (TPM quote, AWS IMDSv2, GCP metadata, Azure IMDS, K8s projected
  SAT, GitHub OIDC, Sigstore Fulcio) one small sprint each. *Acceptance:* each issuance
  records a verifiable attestation; attestations are queryable in the graph.
- **S8.4 — Ephemeral credential issuance (F25).** Sub-hour, configurable-to-minutes
  certs issued only against a valid F30 attestation. *Acceptance:* issuance is refused
  without attestation; TTLs honored; revocation-by-expiry verified.
- **S8.5 — EST server (F22).** RFC 7030 enrollment. *Acceptance:* a device enrolls;
  differential test against libest; parser fuzzed.
- **S8.6 — SCEP server (F23).** RFC 8894 enrollment, MDM-compatible. *Acceptance:* an
  MDM-style client enrolls; parser fuzzed.
- **S8.7 — Policy engine GA (F28).** OPA/Rego over issuance, deployment, revocation.
  *Acceptance:* policies gate operations; property-based tests on the evaluator.
- **S8.8 — Notification integrations (F29).** Slack, Teams, PagerDuty, OpsGenie,
  webhooks, email (one small sprint each off a template). *Acceptance:* each channel
  delivers via the outbox; failures retry observably.
- **S8.9 — Additional connectors (F27).** FortiGate, Palo Alto, Cisco ASA/ISE, Citrix
  ADC (one small sprint each off the S5.5 template).
- **S8.10 — SSH certificate authority (F43).** Sign short-lived host and user certs
  with principals, validity, extensions; KRL maintenance; rides AN-2/3/4. *Acceptance:*
  a host and a user cert are signed and validated by stock OpenSSH; KRL revokes.
- **S8.11 — SSH trust-rewrite design spike (F44 design).** Threat-model and design the
  `sshd`/`authorized_keys` rewrite with additive-first, validated-reload, rollback, and
  break-glass — *before* building it, because it can lock operators out of production.
  *Acceptance:* reviewed design doc; lockout-failure modes enumerated with mitigations.
- **S8.12 — SSH deployment and trust configuration (F44 build).** Implement the agent
  trust rewrite per the spike. *Acceptance:* host cert installed and `sshd` configured
  additively; a forced misconfiguration auto-rolls-back without lockout; never removes
  existing trust without confirmation.
- **S8.13 — Attestation-gated SSH user certs (F45).** Short-lived SSH user certs gated
  on F30. *Acceptance:* a user cert issues only against a valid attestation; standing
  raw-key access is replaced by attested, expiring access in the test scenario.
- **S8.14 — Credential compromise workflow (F31).** One-action revoke + reissue +
  rotate with graph-computed blast-radius preview. *Acceptance:* blast radius is
  correct over a fixture; the action is audited and reversible where applicable.
- **S8.15 — Fleet re-issuance (F32).** Re-issue at scale for X.509 CA incidents *and*
  SSH CA key compromise (rotate CA, re-sign, redistribute `TrustedUserCAKeys`, publish
  KRL). *Acceptance:* a simulated SSH CA compromise re-establishes trust fleet-wide with
  staged rollout and health-check rollback.
- **S8.16 — JIT issuance with approvals (F33).** Dual-control, time-bounded,
  policy-scoped approvals with Slack/Teams. *Acceptance:* sensitive classes require
  approval; grants expire; approvers are policy-scoped.
- **S8.17 — Break-glass procedures (F34).** Offline issuance ceremony as a degraded
  signing-service mode with m-of-n quorum and reconciliation on recovery; covers SSH
  lockout. *Acceptance:* offline issuance produces a signed bundle that reconciles with
  the control plane; runbook shipped.
- **S8.18 — Helm chart and Kubernetes Operator.** Signing service as its own pod with
  dedicated security context and network policy; external Postgres/NATS/KMS guidance.
  *Acceptance:* a production-shaped cluster deploys via the operator with the signer
  isolated.
- **S8.19 — External pen test and remediation.** Commission the test; triage and fix.
  *Acceptance:* findings remediated or risk-accepted with rationale.

**Phase 2 gate:** SPIFFE + ephemeral + attestation, EST/SCEP, SSH CA + safe
deployment, the incident-response surface (compromise, fleet re-issuance, JIT,
break-glass), HSM backends, and a hardened K8s deployment.

---

# PHASE 3 — Secret & Token Lifecycle (sprint-level; expand on demand)

- **S9.1 — Secret store discovery (F35).** Read-only inventory connectors for Vault,
  AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, and Kubernetes secrets (one
  small sprint each). *Acceptance:* each enumerates secrets without mutating them and
  merges into inventory/graph.
- **S9.2 — API key/token inventory (F36).** Discover via CSP APIs (AWS IAM access
  keys, GCP SA keys, Azure SP secrets), GitHub Actions secrets, CI/CD stores (one small
  sprint each). *Acceptance:* keys/tokens are inventoried and scored.
- **S9.3 — Secret rotation engine (F37).** Policy-driven rotation with rollback safety
  for supported backends. *Acceptance:* a rotation succeeds and a failed rotation rolls
  back cleanly.
- **S9.4 — Ephemeral API key issuance and SDKs (F38).** Short-lived, workload-bound API
  keys plus SDKs for Go, Python, Node, and Java (one small sprint per language).
  *Acceptance:* keys issue with TTL and bind to a workload; each SDK fetches and
  refreshes them.
- **S9.5 — Code/CI secret scanning bridge (F39).** Ingest trufflehog/gitleaks findings
  into inventory. *Acceptance:* findings appear in inventory and graph with provenance.
- **S9.6 — Multi-tenant operationalization (F40).** Tenant provisioning APIs,
  per-tenant admin scopes, operator tooling, and an independent isolation test suite —
  activating the AN-1 boundary, not building it. *Acceptance:* tenants provision and
  isolate; the isolation suite passes.
- **S9.7 — Cross-region federation (F41).** Regional control planes federate for data
  residency with shared policy, federated identity, and replicated audit. *Acceptance:*
  two regions federate with residency respected and audit replicated.
- **S9.8 — Managed offering GA and commercial licensing plumbing.** Stand up the
  managed topology and the commercial/enterprise/MSP licensing path. *Acceptance:* the
  managed tier provisions tenants; licensing entitlements are enforced without gating
  open-source features.

**Phase 3 gate:** non-certificate credential discovery and lifecycle, ephemeral API
keys, operationalized multi-tenancy and federation, and the managed offering — closing
the unified "every non-human identity" scope.

---

## A note on the two riskiest sprints

S1.3/S1.4 (the signing service) and S8.11/S8.12 (the SSH trust rewrite) are the two
places where a defect is catastrophic — one ends the company on compromise, the other
can lock a customer out of production. Both are split into a design spike followed by a
build sprint for exactly that reason. Resist the urge to collapse them back into single
sprints, and treat their PRs as the ones that most deserve careful review.
