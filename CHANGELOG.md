## [Unreleased]

### Changed

- PCAS operator/security guides now live in the public documentation. Edition
  references identify PCAS, AGID, XREC, VDEC, PQC and remediation as core;
  obsolete family-specific gate targets are replaced by direct integration and
  conformance commands while the core/EE boundary gate remains. The smaller
  commercial tree measured 70.7% coverage; its enforced floor rises from 65%
  to 70%. Patent claim traceability remains under `ee/docs/`.

- Managed tenant provisioning saves the reviewed request and its original
  idempotency key before sending it. Operators can recover an uncertain result
  from the same account after reloading or reopening the browser, without
  generating a conflicting registration request. The server checks the reviewed
  tenant and operator before creation or replay so another tab's account switch
  cannot silently change the account used for provisioning.

- Managed tenant provisioning now accepts its existing provider metadata under
  the required event privacy policy, while retaining closed field validation.

- Authority agreement reports now show only the authenticated tenant's
  authorities, counts, resolution metrics and collection status. Reconciliation
  replay keeps witness ownership separate across tenants and rejects conflicting
  event tenants before changing projection state.

- Core PQC migration and rollback remain available after a commercial license
  expires, with tenant authorization and idempotency checks preserved. Edition
  disclosures now place PQC in Free Core and the operator guide reflects the
  current rehearsal command.

- Remediation is part of Core: incident and guided remediation routes now mount
  without a commercial license in both normal and Core-only builds. Tenant
  isolation, RBAC, policy, idempotency and outbox requirements are unchanged. The
  credential-compromise workflow library moved from `ee/incident` to
  `internal/incident` under BUSL-1.1.

- **Licensing.** The core moved from the Mozilla Public License 2.0 to the
  Business Source License 1.1 (Licensor certctl LLC): production use is permitted
  under the Additional Use Grant, the Free tier needs no signed license, and each
  release converts to MPL-2.0 four years after it is published. `clients/` stays
  MPL-2.0; `ee/` stays proprietary. Every core file's SPDX header reads
  `BUSL-1.1`.
- **The patent-pending families and PQC are core.** PCAS (`internal/succession`,
  `internal/translog`, `internal/rpverify`), AGID (`internal/agentid`), XREC
  (`internal/reconcile`), VDEC (`internal/decommission`) and PQC (`internal/pqc`,
  `internal/pqcruntime`, `internal/pqcmigration`, `internal/kmip`) moved out of
  `ee/` and attach in every build through `cmd/*/attach_families.go`; the
  `pcas`, `agent-delegation`, `reconcile`, `vdec` and `pqc` license features are
  gone (a license file that still names them parses and grants nothing extra).
- **Migration ledger.** The `-- SPDX-License-Identifier:` line is outside a shipped
  migration's content digest; a ledger row recorded by an earlier binary under the
  previous identifier is recognized and re-stamped with `checksum_adopted_at`.
- **The Terraform provider is its own MPL-2.0 module.** `terraform-provider-trstctl`
  moved from `cmd/terraform-provider-trstctl` and `internal/terraformprovider` to
  `clients/terraform` (module `trstctl.com/terraform-provider`), licensed MPL-2.0
  with the rest of `clients/`. Its module path sits outside `trstctl.com/trstctl`,
  so the compiler refuses any import of the control plane's `internal/` packages:
  the provider reaches trstctl only through the served REST API. `make build`,
  `make reproducible-check`, `make sdk-test` and the registry release script
  build and test it from that directory, and the Terraform SDK modules are no
  longer requirements of the core module.
- **No published pricing.** Reference list prices and wholesale bands are gone
  from the docs (`docs/pricing.md` is removed), the README and the editions API:
  `GET /api/v1/editions` no longer serves `reference_price_bands`, and
  `pricing_posture` is now `commercial_posture`, stating that Enterprise and
  Provider terms are agreed per customer and not yet published. The console's
  editions panel no longer renders a price table.

## [0.6.3] - 2026-09-19

Tagged after 0.7.0 on the same line of development; it carries one change.

### Changed
- CI: CodeQL is scoped to shipped product code, so analysis time goes to the
  binaries that ship rather than to tooling and fixtures.

## [0.7.0] - 2026-09-16

### Fixed
- Provider authority and customer service state are enforced on every
  provider-plane mutation, and completed credential requests are recovered
  rather than dropped.
- Live tenant policy is isolated per tenant, and the lifecycle surfaces show
  the actual authority that governs each identity.
- Tenant authority is preserved through governed lifecycle recovery.
- Local bootstrap token creation is recorded through events, so the audit
  trail covers it like every other issuance.
- Retained-batch subscription callbacks are joined before cleanup in the
  events tests, removing a teardown race.

### Changed
- The console is English-only (R07); the locale plumbing that shipped no
  translations is gone.
- Documentation explains the first-member role provisioning handoff.

## [0.6.0] - 2026-09-15

The development milestone that closed the summer hardening train: 1,762
commits since 0.5.4. The last weeks before the tag repaired the verified
lifecycle and operator journeys, bounded retained-history transport and
decoding, activated existing SSH trust on retry with effective-config
validation, retained verified PostgreSQL archives in server test shards,
made the lint tool distinguish fresh upsert keys from exclusive locks, and
refused repeat signing when retained issuance needs a rebuild. The dated
entries below are the train's own log.

### Bundled PostgreSQL authenticates executable bytes before startup (2026-09-09)

- The evaluation database verifies its independent committed archive checksum
  before extraction or execution, including on a cold download. Maven's checksum
  sidecar remains an additional transport check.
- Each start extracts authenticated bytes into a fresh private directory. The
  archive cache includes platform, version and digest; stale extracted binaries
  cannot survive a pin change. Existing database data and legacy caches remain
  intact.
- Rooted extraction rejects unsafe paths, links and file types, and enforces
  expansion limits.
  Complete archives and executable trees are published atomically. Startup errors
  preserve their original cause and never stop an unproven existing server.
- Regression tests call the actual startup wrapper and check executable markers,
  tampered archives, extraction limits and concurrent publication. Legacy test
  and developer-tool loaders remain outside this served-path provenance claim.

### Lint tool failures cannot qualify unchecked source (2026-09-08)

- Formatting and architecture lint stop on failed prerequisites, including an
  unavailable temporary file or a failed analyzer build.
- The EE lint gate validates the full scanner report and exit status, requires
  every configured linter, retains diagnostics and refuses malformed results.
  It reports potential baseline reductions without editing the baseline file.
- The EE scanner also bounds output while running and stops its process group
  on timeout or cancellation. A scanner that leaves children behind fails.
- Regression tests inject tool failures into the actual Make recipes and verify
  that incomplete checks fail before later work can hide them.

### Dark-segment enrollment relay failover is observable and stock-ACME-safe (A4, 2026-08-12)

- **A relay returned an ACME directory whose absolute URLs named the control
  plane.** A stock client followed the second URL directly, so the claimed dark-
  segment path failed even though isolated `/directory` and `/acme/*` proxy tests
  passed. Relays now require one stable `--enroll-proxy-public-url` and preserve
  that HTTP authority while the socket still dials only the configured control-
  plane endpoint. Signed request bodies and protocol responses remain byte-for-
  byte pass-through, and the proxy still attaches no agent credential.
- **Control-plane endpoint failover was mistaken for relay redundancy.** Each
  certificate-bound network relay now reports its operator-named
  `--enroll-proxy-segment`, public URL, verified/unavailable/unverified upstream counts,
  process-lifetime forwarded/refused/failure counters, and last forward/failover
  times on its authenticated heartbeat. The immutable event stream rebuilds the
  tenant projection; `GET /api/v1/agents`, generated SDKs, and the Protocols
  console show the exact per-segment relay rows and redundancy count.
- A configured endpoint starts **unverified**, not healthy. Only a completed
  response proves health; retry-cooldown expiry merely permits another probe.
  A real HTTP 502 from the control plane remains the client's response, while
  only an out-of-band transport failure changes upstreams.
- The assembled acceptance starts two relay subprocesses behind one segment URL.
  A stock `golang.org/x/crypto/acme` client registers through the primary, the
  primary process dies, and the same client completes a real signer-backed order
  through the secondary. Its transport refuses the control-plane authority and
  records zero attempted direct routes.

### The repository has an intake path and a code of conduct (2026-08-02)
- **README.md and CONTRIBUTING.md told readers to open an issue; nothing was
  behind that invitation.** `.github/ISSUE_TEMPLATE/` now carries a bug report
  and a feature request as GitHub issue forms, each requiring only what a
  maintainer needs to reproduce or judge the report — version/commit, what
  happened versus expected, and steps for a bug; the problem, the proposal, and
  whether it lands in core or `ee/` for a feature.
- **A vulnerability could be filed as a public issue in one click.** SECURITY.md
  says not to; nothing enforced it at the point of filing. Blank issues are now
  disabled and a contact link routes a would-be reporter to SECURITY.md before
  the new-issue form, with a second link to `docs/limitations.md` so a
  not-yet-served subsystem is not reported as a defect.
- **CODE_OF_CONDUCT.md adopts the Contributor Covenant 2.1 verbatim**, with the
  enforcement address taken from the one SECURITY.md already publishes rather
  than a second address that could drift. A guard in `docs/issue_intake_test.go`
  pins all of it, including that the two addresses stay the same.

### Broker-issued agent credentials can be task-scoped (B-7, 2026-07-26)
- **Only the chain-bound delegation path could bind a credential to one
  authorized task.** The broker's single-hop path — the one an AI/MCP agent
  actually uses — could not carry an AGID-05 task envelope at all, so a broker
  badge had standing scope and nothing narrower. `POST
  /api/v1/broker/agent-identities` now accepts `task_envelope_base64` and
  returns the `task_envelope_digest` the credential binds, which the caller
  can recompute to confirm the scope it authorized.
- **An envelope the build cannot verify is refused, not ignored.** This is the
  rule that makes the binding worth anything: silently issuing an *unscoped*
  credential in place of the scoped one a caller asked for is precisely the
  outcome an attacker would engineer, so a Community / core-only build (which
  attaches no gate) rejects the request. Requests carrying no envelope are the
  ordinary single-hop badge, untouched — INV-A10 zero removal holds.
- **The gate reuses the delegation gate's own verification**
  (`taskenv.VerifySignatureAndExpiry`): requester signature over the canonical
  bytes, resolved through an operator-provisioned trust store on the signer
  floor that the caller cannot inject into, plus the expiry window. The bound
  digest is computed from the envelope that just passed, so a substituted
  envelope cannot be bound in place of the signed one, and the binding is
  emitted into the audit chain (AN-2) rather than living only in a response.

### A migration can be reviewed before it runs (B-3, 2026-07-26)
- **You could start a fleet-wide re-issuance; you could not look at it first.**
  `POST /api/v1/pqc/migrations/plan` (and `trstctl-cli migration plan`,
  Enterprise PQC) previews the plan — which assets would be re-issued and to
  what, which TLS findings would be rolled out, and **the residuals it will
  not touch** — with no run id, no outbox row, and no event. The residual list
  is the half that makes the preview honest: a plan that only showed what it
  *will* do would overstate coverage.
- **The preview cannot lie about the migration.** It calls the same
  `BuildPlan` the start path calls, over the same CBOM assets, so a divergence
  between preview and execution would have to be a divergence inside the plan
  builder itself — not two implementations drifting apart.
- The licensed READ seam grew the response writers it was missing
  (`WriteJSON`/`WriteError`/`WriteProblemUnauthorized` beside the existing
  `Tenant`), so a licensed GET renders errors in exactly the core's
  problem+json shape instead of inventing its own.

### Signing history is verifiable after the fact (B-4, 2026-07-26)
- **Code signing served the two mutations and nothing that answered
  afterward.** You could sign with a managed key or keylessly, but nothing
  told you which identities had signed or whether the transparency-log entry
  actually landed. `GET /api/v1/code-signing/identities` (and `trstctl-cli
  code-signing identities`) lists recent operations with their identity kind
  and each one's transparency state — `verified`, `pending`, `failed` with its
  reason, or `not-published` — plus the two counts a reviewer asks for first.
- **Verification is not a second source of truth.** Rekor publication rides
  the outbox, and the handler refuses to acknowledge an entry whose signed
  receipt does not verify — so a delivered outbox row *is* a verified entry,
  and the view reads that state rather than a parallel flag that could drift
  from it. The query reads no sealed command bytes, so the plaintext identity
  assertion and artifact digest never leave the signer boundary through it.

### The SSH estate outside the CA is readable (B-2, 2026-07-26)
- **The SSH surface covered the credentials trstctl issues and nothing about
  the ones it does not.** CA status, trust rollouts, attested user certs and
  revocation were all served, while discovered SSH keys sat in the inventory
  with no view answering the operator's actual question: which hosts still
  have standing key-based access that certificate rotation cannot reach.
  `GET /api/v1/ssh/fleet` (and `trstctl-cli ssh fleet`) rolls those keys up
  per host — key count, standing-access count, orphaned count, key types,
  sources, observation window — ordered worst host first, so the hosts most
  needing to come under the CA sort to the top.
- **The not-under-CA claim is structural, not inferred.** Every row behind the
  view is a raw key, because a certificate minted by the SSH CA is never
  stored as an `ssh_key`; each host therefore carries `under_ca: false`
  explicitly, and the response repeats the count so a dashboard does not have
  to restate the invariant. Metadata only — fingerprints, types, locations —
  never private key material.

### The connector catalog reports its sandbox contract (B-6, 2026-07-26)
- **The catalog described what a connector deploys, never what it may do.**
  An operator authorizing a privileged deployment could not see the two facts
  that matter: what the connector is permitted to touch, and what happens on a
  redelivery. Each catalog row now carries `native` (this build has a native
  implementation), `capabilities` (the declared sandbox grant — `fs.read`,
  `fs.write`, `net.dial`, `process.exec`, sorted), and `replay_safety`
  (`reconciled` when the receiver converges on retry, otherwise
  `at-most-once`).
- **Read from the live registry, not written beside the description**, so the
  catalog cannot drift into claiming a capability the process would not
  enforce. Reporting never constructs a connector. A connector this build does
  not implement natively reports no capabilities and the conservative
  at-most-once contract, and a control plane assembled with no registry claims
  nothing at all.

### The running system is readable from the console (B-5, 2026-07-26)
- **`/admin/system` showed posture, not the system.** It rendered what the
  product *claims* — edition, support tier, scale plan — but not the readout
  an operator wants when something looks wrong. That answer existed only on
  `/healthz` and `/readyz`, which are unauthenticated infrastructure probes
  shaped for a load balancer. `GET /api/v1/platform/system` (and
  `trstctl-cli platform system`) reports the build version/commit/date, the Go
  toolchain, process start time and uptime, the **live** AN-4 signer topology
  (`child`/`external`/`none` — what is actually attached, not what the config
  intended), whether the FIPS module is routing `crypto/*`, and per-dependency
  reachability for the database, event log, and signer.
- **It reuses the same probes as `/readyz`**, so the console and the load
  balancer can never disagree about whether the spine is up — the failure mode
  that makes an operator distrust both. Probes are bounded at 3s so a hung
  dependency degrades this endpoint instead of hanging the caller, and the
  readout carries no addresses, DSNs, or configuration values: a component is
  reachable or it is not.

### Worker-pool backpressure is readable from the API (B-1, 2026-07-26)
- **AN-7 stops being invisible to operators.** Every subsystem has had its own
  bounded pool since the first commit, but the only way to see one backing up
  was to scrape the metrics endpoint. `GET /api/v1/operations/bulkheads` (and
  `trstctl-cli operations bulkheads`) now reports each pool's workers,
  capacity, queue depth, computed saturation, and its
  submitted/completed/rejected/panicked counters — so "is a queue backing up,
  and which one" is one authenticated read. The snapshot is process-wide
  operational telemetry: subsystem names and numbers, never tenant or
  credential data. A control plane assembled without the bulkheaded surfaces
  answers `served: false` rather than 404, because "nothing is saturated
  because nothing is wired" is a truthful answer. Unbounded pools report 0%
  instead of dividing by zero. The new operation carries the whole contract
  chain in the same change: OpenAPI golden, the pinned SDK spec, generated FE
  types, and the feature-catalog mapping with its count ratchets raised
  deliberately.

### The Kubernetes issuer controller elects one reconciler (B1 residue, 2026-07-26)
- **N nodes stop reconciling the same cluster-scoped objects.** The agent ships
  as a DaemonSet, so every pod was reconciling the same trstctl
  `Issuer`/`ClusterIssuer`/`TrustBundle` resources — harmless, because signing
  and status writes are idempotent, but it multiplied API-server work and
  audit noise by the node count. A `coordination.k8s.io` Lease
  (`trstctl-agent-issuer-controller`, 30s, identity from the downward API's
  `POD_NAME`) now elects one reconciler with a compare-and-swap on
  `resourceVersion`, so a stale renewal loses instead of stomping the holder;
  a follower takes over within one lease duration. Missing Lease RBAC logs
  once and reconciles anyway — duplicated idempotent work beats no controller
  at all. Covered by tests for single-leader election, the cold-start create
  race, and expiry takeover.

### A maintainer transfer document (D7, 2026-07-26)
- **The operational knowledge leaves one head.** `MAINTAINERS.md` is written
  for someone who did not build this: the system's mental model in a
  paragraph, the architecture linter's eight analyzers and how to extend one
  (including why there is no `//nolint` escape hatch), the three invariants
  that have **no** analyzer and lean on dependency-closure tests instead, a
  map of where the danger is (crypto boundary, signer process, RLS store, the
  three attach seams), what each meaningful CI gate failing actually means,
  how release publishing is gated, and why the docs are grep-tested. Pairs
  with the nine existing runbooks as the transfer set.

### Dependency license audit runs in CI (D9, 2026-07-26)
- **Copyleft contamination is now caught by us, not by diligence.**
  `make license-audit` resolves every module actually linked into the shipped
  binaries (`trstctl`, `-signer`, `-agent`, `-operator`), classifies each
  license, and fails on strong copyleft (AGPL/GPL/LGPL/SSPL/CDDL/EPL) or a
  module with no recognizable license text; it runs beside govulncheck in CI
  and uploads a JSON receipt. Current state: **83 modules, zero copyleft** —
  41 Apache-2.0, 21 MIT, 19 BSD, 1 MPL-2.0, 1 public-domain. The classifier
  matches license *titles* in priority order rather than grepping for "GPL",
  because MPL-2.0's own Exhibit B names the GNU GPL as a compatible secondary
  license — a naive scan reports every MPL dependency as a GPL finding.

### Contribution terms: DCO for core, CLA only for `ee/` (D2, 2026-07-26)
- **The IP terms are written down before the first outside contribution.**
  `CONTRIBUTING.md` states the split plainly: core is MPL-2.0 and accepts
  patches under the **Developer Certificate of Origin** (`git commit -s`, no
  copyright assignment), while the proprietary `ee/` tree requires a signed
  CLA — with the honest note that most `ee/` requests can be met by a core
  change plus a seam, which stays DCO-only. A blanket CLA would tax every
  drive-by fix in core; DCO-only everywhere would leave the commercial tree
  undistributable. README links it and a PR template carries the checklist.

### Migration runs get a CLI (A0.4a, 2026-07-26)
- **`/api/v1/pqc/migrations` is no longer curl-only.** `trstctl-cli migration
  start | status | rollback` drives the licensed crypto-migration surface
  through the same route table every other command uses, with the
  `Idempotency-Key` discipline the mutating routes require. Against an
  unlicensed server the routes are absent, so the CLI reports 404 — the
  honest answer for a feature that edition does not serve. Documented in
  docs/cli.md with a worked example and mapped into the feature catalog
  (F16), so the CLI-vs-feature parity gate covers it.

### Break-glass succession is wireable; the dead migration twin is gone (A0.4b, 2026-07-26)
- **PCAS class-downgrade break-glass can now actually be configured.** The
  production minter passed a nil verifier, so a downgrade was refused
  unconditionally and `NewSignedBreakGlassAuthorizer` had only test callers.
  The signer now loads an operator-provisioned break-glass authority PUBLIC
  key from `<signer-keystore>/pcas-breakglass-authority.pem` (the same
  operator-provisions-trust pattern as the XREC plan bundle — never a
  control-plane input) and, when present, accepts a valid single-use token
  signed by that authority with durable spent-state inside the custody dir.
  Absent stays fail-closed; **present-but-unparseable fails startup** rather
  than looking configured while behaving as if it were not.
- **Deleted the dead fleet-migration twin.** `ee/pqcmigration.Orchestrator`
  (the discover→stage→reissue→track loop) and the whole `ee/fleet` package
  had zero non-test callers — both were shadowed by the differently
  architected served implementation (`ee/pqcmigration` api/server/plan) and
  by core's served CA-compromise fleet re-issuance. Removing them deletes
  ~400 lines of code that read as shipped and was not.

### Agent collector scope stated; api_key failures name their cause (A0.2c, 2026-07-26)
- **The unwired agent collectors are disclosed, not implied.** PKCS#11 token,
  Windows certificate/trust store, and in-cluster Kubernetes Secret
  collection exist as the injected-enumerator boundary in
  `internal/agent/discovery` but the shipped agent constructs no enumerator
  for them — limitations.md now says **not offered** and the package says so
  at the constructors, so nobody reads them as served. Adding one is an
  enumerator plus a flag, which is the point of the seam.
- **An `api_key` source with neither observations nor findings now says so.**
  It used to fall through to the generic "no server-side connector is
  configured for discovery source kind api_key", which read as "api_key is
  not served" when the real cause was an empty config.

### secret_store sources gain a real executor (A0.2b, 2026-07-26)
- **The creatable-but-never-runnable kind is gone.** `secret_store` sources
  now dispatch through the same served secret-manager connectors as
  `cloud_secret` (aws-secrets-manager, gcp-secret-manager, azure-key-vault,
  hashicorp-vault — the kinds share the providers config shape), instead of
  dead-ending in the generic "no server-side connector" fallback. Providers
  outside the served set (infisical, kubernetes-secrets, cicd-store) fail
  with the connector's specific "unsupported provider" refusal; building
  those listers stays demand-driven P-track work. Empty-provider errors are
  now kind-aware.

### Discovery schedules tick server-side (A0.2a, 2026-07-26)
- **"Continuous monitoring" stops needing an external cron.** A leader-only
  scheduler (`RunDiscoveryScheduler`, started with the CRL and lifecycle
  workers) sweeps every minute and queues a run for each enabled schedule
  whose source has no in-flight run and no run newer than its
  `interval_seconds` — through the exact event + projection + outbox path an
  operator-initiated run takes (AN-2/5/6), tagged
  `requested_by: discovery-scheduler`. A failed run counts as an attempt so a
  broken source retries next interval instead of hot-looping; one sweep
  queues at most 100 runs per tenant (AN-7 ahead of the bulkheaded worker).
  The due decision is a real-PostgreSQL integration test under RLS,
  including in-flight suppression, failed-run backoff, the sweep limit, and
  tenant isolation.

### Decision: the issuing CA key stays classical, on purpose (A0.3g, 2026-07-26)
- **Post-quantum keys are subject keys, not issuer keys, and that is now a
  recorded decision instead of an undisclosed ceiling.** Rationale: (1) a
  pure ML-DSA issuer breaks every stock TLS client that must chain to it,
  while an ML-DSA *subject* under a classical issuer interoperates today —
  the hybrid/pure subject leaf is where the market is; (2) the harvest-now/
  decrypt-later threat targets confidentiality (KEM), not the issuer
  signature: a classical issuing CA can be rotated to a PQ issuer when
  clients are ready, and nothing already issued becomes forgeable
  retroactively before then; (3) the mechanics (`signOpaqueTBS`'s classical
  allowlist, the hardcoded ECDSA-P256 issuing handle) are one contained
  boundary change behind `internal/crypto` when the CA-hierarchy PQC work
  (P8/F57 follow-up) schedules it — the crypto-agility property this
  architecture sells. limitations.md already discloses the ceiling; the
  roadmap owns the lift.

### The PQC census proofs run in CI on every push (A0.3f, 2026-07-26)
- **"PQC issuance is proven" stops depending on someone remembering a build
  tag.** A new required check, `pqc e2e (dodproof)`, runs
  `TestDODPQCProductionAssembly` — stock-OpenSSL pure ML-DSA-65 EST
  enrollment, the two-entry hybrid SVID Workload API response, and the
  CBOM→migration TLS rollout with rollback — against the exact shipped
  artifact on every push. The job gates loudly on an ML-DSA-capable stock
  OpenSSL (>= 3.5) so runner drift cannot silently skip the proof; the check
  is pinned into branch-protection.json, docs, and a guard test.

### The additional Workload-API SVID is audited like the classical one (A0.3e, 2026-07-26)
- **The licensed second SVID stops being invisible to the event log.** The
  Workload API's additional-issuer mint now emits the same
  `spiffe.svid.issued` audit event and credential-graph node the classical
  SVID gets, with its hint in the payload (`x509-additional:<hint>`), so
  posture can tell the pair apart. Profile parity note: the classical SVID's
  EKUs are equally fixed by the SVID signing profile, so the additional
  issuer's serverAuth/clientAuth EKUs are parity, not drift; and like every
  Workload-API SVID it is deliberately ephemeral — audited, graphed, but not
  an inventory row.

### Direct-API issuance scope decided; dead licensed twin removed (A0.3d, 2026-07-26)
- **The identity API's server-side classical keygen is a decision, not a
  gap.** `issuanceDispatcher.issueLicensed` was assigned at boot and called
  nowhere — a dormant seam diligence would flag. It is deleted; the
  dispatcher documents that ephemeral NHI identities take server-generated
  classical keys by design, and CSR-based enrollment (including licensed
  subject algorithms) belongs to the enrollment protocols through
  `protocolIssuer`, whose licensed twin is live and tested.

### ACME's algorithm transparency is pinned by test (A0.3c, 2026-07-26)
- **"ACME never parses the CSR" is now a contract, not an accident.** A new
  test drives a full RFC 8555 order with a real client and finalizes with a
  CSR whose proof-of-possession the core parser rejects; the order completes
  and the CA seam receives byte-identical CSR data. If anyone "hardens"
  finalize with a core-parser check — breaking the licensed issuer's
  ownership of subject-algorithm verification — this test fails and names
  the seam contract.

### Profiles can name post-quantum algorithms when licensed (A0.3b, 2026-07-26)
- **`allowed_key_algorithms` stops failing closed on licensed labels.**
  `crypto.Classify` gains a licensed-classifier seam
  (`InstallLicensedAlgorithmClassifier`, filled by attachPQC with
  `ee/pqc.ClassifyAlgorithm`), so profile authoring accepts ML-DSA / SLH-DSA
  / hybrid signature labels — and still rejects ML-KEM labels, which cannot
  sign certificates. Enforcement stays exact-match: a profile listing
  `ML-DSA-65` admits pure ML-DSA-65 CSRs; a hybrid enrollment carries a
  classical subject key and remains governed by its classical family label.
  Unlicensed binaries keep failing closed on all of it.

### CMP gains the licensed-CSR seam (A0.3a, 2026-07-26)
- **CMP can now carry subject algorithms the core toolchain cannot check.**
  `ParseCMPRequest` previously verified the carried PKCS#10 with the strict
  core parser *before* any licensed parser could see it, so CMP hard-rejected
  what EST already accepted. `ParseCMPRequestWithVerifier` delegates exactly
  the inner-CSR check to an injected verifier — PKIMessage protection stays
  core-verified, unconditionally — and the served mount binds the same
  licensed-aware verifier EST uses. Covered by seam tests proving the
  verifier is consulted with the exact CSR bytes, a refusing verifier fails
  closed, and tampered protection still dies even with an accepting
  verifier. (SCEP intentionally keeps the core-only path: its CMS reply
  cannot be delivered to a signature-only subject key — a protocol limit
  documented in limitations.md, not a code gap.)

### Terraform provider + Python SDK become published artifacts (B6, 2026-07-26)
- **The provider's acceptance test now actually runs.** CI drives a REAL
  `terraform apply` (pinned terraform 1.9.8, SHA256SUMS-verified download)
  through the provider's plan/apply/read/delete loop on every push —
  previously `TRSTCTL_RUN_TERRAFORM_ACC` was set nowhere and the test was
  dead weight.
- **Release tags publish the provider in the Terraform Registry layout.**
  `scripts/release/terraform-registry-assets.sh` builds per-OS/arch zips
  (binary named `terraform-provider-trstctl_v<version>`), the protocol-6.0
  registry manifest, and a GPG-signed SHA256SUMS; the release job uploads them
  as GitHub Release assets with SLSA provenance. Signing requires the
  protected `terraform-registry-signing` environment — unsigned assets are
  refused rather than emitted.
- **The Python SDK ships to PyPI and the Release.** A release job stamps the
  tag version into `clients/sdk/python`, builds sdist+wheel, `twine check`s
  them, uploads them as Release assets with SLSA provenance, and pushes to
  PyPI via the protected `pypi-publishing` environment (`PYPI_API_TOKEN`) —
  missing credentials fail loud, never skip silently.

### SPIRE upstream-authority plugin ships (B2, 2026-07-26)
- **The SPIRE plugin is now an obtainable artifact, not a build-from-source
  exercise.** `trstctl-spire-upstream-authority` joins `make build`'s `CMDS`
  and the reproducible-binary check, and every release tag publishes
  `trstctl-spire-upstream-authority-linux-{amd64,arm64}` GitHub Release assets
  with a SHA-256 manifest and their own SLSA provenance
  (`trstctl-spire-upstream-authority.intoto.jsonl`), gated on the same
  test/required-checks contexts as every other publishing job. SPIRE loads the
  plugin from its own host (`plugin_cmd`), so it deliberately stays out of the
  container image; docs/limitations.md now states the exact distribution
  contract instead of a bare "served".

### CBOM licensed posture — real FIPS targets (A0.1, 2026-07-26)
- **A licensed binary's CBOM now names its migration targets.** The MPL core
  still emits edition-neutral `licensed-*` placeholders and recognizes no
  licensed algorithm family — that fence is deliberate and unchanged. A new
  seam, `cbom.InstallLicensedPosture`, is filled from the tagged PQC attach
  block with `ee/pqc/cbomposture.CBOMTargetFor` +
  `ee/pqc/cbomposture.CBOMClassifyKey`, so with
  FeaturePQC licensed the inventory maps classical signatures →
  **ML-DSA-65 (FIPS 204)**, key establishment → **ML-KEM-768 (FIPS 203)**, and
  deprecated DSA → **SLH-DSA-SHA2-128s (FIPS 205)**; ML-DSA / ML-KEM / SLH-DSA
  / SPHINCS+ / Kyber / Dilithium / hybrid labels classify as strong and not
  quantum-vulnerable instead of "unrecognized"; and pure post-quantum assets
  carry `future-ready` — which makes `percent_migrated` a live number instead
  of a structural zero. Hybrid assets deliberately stay `migration-required`:
  they are quantum-safe today but the migration endpoint is the pure
  post-quantum algorithm. Covered by `ee/pqc/cbom_test.go`, including a mixed
  classical + post-quantum estate reporting 25% migrated.

### Static console demo enablement (demo.trstctl.com, 2026-07-25)
- **The console can now ship as a zero-backend static demo.** A build-time
  flag (`VITE_TRSTCTL_DEMO=1`, set only by the demo-site build in
  trstctl-website) makes preview mode available in a production bundle,
  lands the visitor signed-in on the showcase, and — new for preview
  everywhere — activates transport isolation: the API client refuses every
  server call before fetch, with translated error copy (2 new keys per
  catalog; digests re-pinned, machine translations flagged for review).
  The product embed never sets the flag, and a new embed-purity gate
  (`internal/webui/demo_purity_test.go`) fails the build if the committed
  console ever carries the preview identity.

### Design-review remediation (R-01…R-09, 2026-07-25)
- **Every form control in the console now actually has a style.** An external
  design review found — and we verified — that `.ui-input`, the class worn by
  ~145 inputs/selects/textareas across 11 pages, was defined in no stylesheet,
  ever: every form field rendered as raw native browser chrome (white fields
  in the flagship dark theme). The family now exists (token-correct field,
  36px to pair with buttons, themed select/textarea/file variants,
  aria-invalid state), native checkboxes/radios ride a gold `accent-color`,
  and a new foundation guard fails the build if any referenced `ui-*` class
  has no rule — it immediately caught a second stillborn class (`ui-button`,
  10 raw buttons now on the Button primitive).
- **Forms became primitives (DESIGN.md rule 14).** `Input`/`Select`/
  `Textarea` plus a `Field` unit that owns label/description/error and their
  aria wiring; piloted on Request Credential's zod+RHF form; raw-control
  counts in pages are budget-ratcheted downward (migrate-when-touched).
- **Focus is its own token (rule 2, both themes).** Focus rings rode
  `--brand-accent`, which is gold-family in light mode — collapsing the
  gold-acts/mint-focuses semantics. A dedicated `--focus` token keeps mint in
  both themes, swept through every focus ring, with a 3:1 non-text contrast
  guard and a mint-hue-family pin.
- **Discipline sweeps.** Eyebrow: nine hand-rolled tracked-uppercase clusters
  (Secrets ×8, Login) plus shell/pqc/styleguide stragglers migrated to the
  primitive, with a tracking ratchet. Shell toggles moved to the Button
  primitive, killing a focus ring class that resolved to no configured color.
  Dead tokens deleted (`--console-accent`, unused density rungs) — the suite
  was certifying them as alive. Rule 15 codifies Card-vs-`ui-panel` and
  DataGrid-vs-`ui-table` criteria; monolith pages split as touched
  (web/AGENTS.md). Repo-wide prettier normalization un-reds CI's
  format:check after the dependency refresh.

### Live dashboard tiles (S-N1, 2026-07-24)
- **Home's numbers stay current without an operator reflex.** The Dashboard's
  eight resources moved off `useResource` onto the query layer with a live-tile
  contract (certctl's PERF-H1 pattern): KPIs poll every 30s and the audit rail
  every 60s while the tab is visible, hidden tabs poll nothing, and returning
  to the tab refreshes exactly the live queries immediately. The optional-probe
  readers (NHI inventory, secrets count, open incidents, recent audit) now fail
  soft to their empty fallbacks, so a missing or erroring optional endpoint can
  never stall the first-run gate or error the whole dashboard.

### Per-locale catalog split (S-C10, 2026-07-24)
- **The entry chunk drops a third: 239 → 163 kB brotli.** The es-ES and de-DE
  production catalogs moved to per-locale modules loaded on demand by the
  I18nProvider; English (the source catalog) and the pseudo transforms stay
  eager. Until a lazy catalog resolves, lookups fall back to English — never
  to raw keys — and the tree re-renders translated the moment the module
  lands (covered by a new in-session locale-switch test). Strings are
  byte-identical to their pre-split location, so the translation-review
  digests did not move; the `satisfies` completeness contract survives in the
  split modules, and the entry size-limit budget is lowered to 185 kB to lock
  in the win.

### Compact locale wire catalogs (AUD-121, 2026-08-12)
- **Reviewed translations keep their keys; the browser stops downloading those
  keys twice.** A checked generator emits value-only lazy runtime catalogs in
  the canonical English message order, then reconstructs the keyed map when a
  locale loads. Keyed es/de sources, type-level completeness, placeholder
  checks, and review digests remain authoritative and byte-identical. The build
  rejects stale generated mirrors, and the 640 kB all-JavaScript ceiling stays
  unchanged.

### Console engineering train (S-C4 / S-C5 / S-C8 / S-C9, 2026-07-24)
- **S-C5 — the data and form layers arrive.** TanStack Query is the console's
  query layer (`src/lib/query.tsx`; provider in `AppRoutes`), piloted on
  Owners: the cache is the row truth, mutations write through and invalidate —
  the refetch `useResource` never had. Mutation forms go schema-first with
  zod + react-hook-form, piloted on Request Credential with per-field errors.
  Adoption policy in `web/AGENTS.md`: new surfaces use the new layers;
  existing pages migrate when touched.
- **S-C9 — typography primitives and a real merge fix.** `Eyebrow` and `Num`
  encode the micro-label and inline-data rules; `text-2xs` replaces the five
  `text-[10px]` arbitraries. The Eyebrow test exposed a latent bug: cn()'s
  tailwind-merge dropped the custom font-size tokens as color conflicts —
  fixed by registering the token scale, for every cn() call site.
- **S-C8 — Storybook workbench.** Storybook 10 (react-vite + a11y addon)
  renders stories against the real tokens with a dark/light toolbar; six
  starter story files cover the primitives and shared components. Coverage
  extended 2026-07-24 to the data-heavy set — DataGrid (sorting, selection +
  bulk slot, and all five list states), the full chart palette (tones,
  StatTile, Meter, BucketBar, time bars, Donut, Sparkline/AreaTrend),
  CredentialChip, the DetailDrawer/Dialog overlays, and StatePrimitives —
  10 titles / 38 stories in the static build.
- **S-C4 — Playwright e2e + visual regression, authored.** Shell smoke (rail,
  scoped sidebars, palette, the `?tab=` redirect) and masked dark-theme visual
  baselines, targeting the seeded demo stack (`npm run e2e`). Browsers were
  not installable in the authoring sandbox — first local run generates
  baselines (`--update-snapshots`).
- **Contracts.** `web/AGENTS.md` is the console's leaf contract; DESIGN.md
  rules 5/6/12 updated to the primitives and the workspaces-vs-lenses ruling;
  the root AGENTS.md now states the AN-4/6/7 enforcement asymmetry plainly;
  the visual-asset audit (design-audit/10) confirms nothing reader-facing
  depicts the retired chips shell.

### IA train closeout (S-C3 / S-C6 / S-C7, 2026-07-24)
- **S-C3 — the console code-splits by page.** Every authenticated surface is a
  lazy route chunk (70 chunks; the entry is the shell + vendor + the typed
  i18n catalogs), with a Suspense boundary at the shell outlet that announces
  loading. The compressed budget is enforced by `npm run size` (size-limit:
  entry, largest page chunk, and total shipped JS); Vite's raw-size warning
  threshold sits just above the entry so a new oversized chunk still trips it.
  Follow-up noted: per-locale catalog splitting would shrink the entry further.
- **S-C6 — the command palette groups by space and speaks verbs.** Route
  results render under space headings in rail order (Home first; spaceless
  routes last under Routes), Enter-activates-first agrees with the visible
  order, and four permission-gated verb entries land where the verb happens:
  Rotate a secret, Grant workload access, Issue SSH user certificate, and
  Preview blast radius.
- **S-C7 — the workspaces-vs-lenses rule is now written down.** A tab becomes
  a sidebar route only when it is a distinct served workspace (own evidence,
  own workflows, own name); an alternate view over the same object domain
  stays a URL-addressable in-page tab. Rulings: Secrets' six workspaces are
  routes (S-C2); Certificates' four tabs and Discovery's four tabs are lenses
  and stay. Home's five inventory counters now deep-link into their spaces,
  completing the every-number-is-a-link pass.

### Secrets workspaces as routes (S-C2, 2026-07-23)
- **The Secrets mega-page's six workspaces are sidebar routes now.** The store
  keeps `/secrets`; **Secret engines** (`/secrets/engines`), **Machine access**
  (`/secrets/access`), **One-time shares** (`/secrets/sharing`), **CI scanning**
  (`/secrets/scanning`), and **Sync targets** (`/secrets/sync`) each own a row
  in the Secrets space sidebar, grouped Store & engines / Access & sharing /
  Delivery & scanning. The in-page tab strip is gone; historical
  `/secrets?tab=` deep links redirect permanently with their remaining query
  intact (the C-A1 `/platform` precedent). Every route carries its own H1 and
  title (naming parity), RBAC gate, and feature evidence; the rail-row budget
  consciously grows by five (ceiling 38).

### Unified shell (spaces IA, 2026-07-23)
- **The console is now five spaces behind an icon rail.** The S-B2
  chips-in-sidebar module switcher became a left rail of spaces that each own
  every surface of one concern — *Certificates & PKI*, *Secrets*,
  *Workload & SSH*, *Posture & response*, and *Platform* — with Home carrying
  the Dashboard, Journeys, and the needs-action worklists. The URL decides the
  active space (deep links light up their owning space; picking a space lands
  on its first permitted route), the per-space audit lenses and 34-row rail
  budget survive, and no route URL, nav label, or feature ID changed, so
  bookmarks and API couplings are untouched. Operator docs (web-console, the
  demo click-through, platform-and-api) describe the new shell.
- **DA-02 closed — the secrets auth-method console.** Secrets → Access now grants
  workload credentials in-console (scoped standing tokens or TTL-bound ephemeral
  keys, reveal-once, list + revoke), projects the configured machine-auth methods
  (issuer, audience rules, scopes, source) with a per-tenant, event-sourced
  disable/enable overlay enforced at the login exchange, and serves the
  issued-session ledger (`GET /api/v1/secrets/sessions`) with idempotent,
  event-sourced revocation (`machine_sessions` projection, migration 0086).
  New API surface: `GET /api/v1/secrets/auth-methods`,
  `POST /api/v1/secrets/sessions/{id}/revoke`,
  `POST /api/v1/secrets/auth-methods/{name}/disable|enable` — with CLI parity
  (`secrets auth-methods list|disable|enable`, `secrets sessions list|revoke`).
- **The `/platform` grab-bag became three routes** — `/admin/access`,
  `/admin/system`, `/admin/editions` — each deep-linkable and fetch-scoped.
  This is the train's only URL change and every historical `/platform` (and
  tab) link redirects permanently; rollback is a nav-config revert.
- **DA-10:** incident intake uses identity pickers and served vocabularies —
  no more pasting raw UUIDs on faith. **DA-14 closed as a class:** the i18n
  extraction ratchet (now AST-based) reads zero hardcoded user-facing strings
  and is sealed at zero. **47-day readiness** panel now lives on the global
  home, ahead of the 2027-03-15 100-day step.
- **Locales:** Spanish is joined by **German (de-DE)** as a production locale;
  both catalogs are completeness-enforced by the type system. Long-tail
  machine-seeded entries are enumerated for human translation passes.
- Rail budget consciously re-set 32 → 34 rows for the admin split; entity-noun
  consolidation deliberately deferred behind an evidence checklist.

### Security & hardening
- Remediation pass (R0–R9) hardening the served, multi-tenant profile: served
  end-to-end **revocation** (a revoked credential stops validating in the product's
  inventory/records), an idempotent first-API-token bootstrap, served X.509 issuance
  with CDP/AIA/SKI and certificate-profile enforcement, quorum-gated cross-signing,
  versioned event envelopes with version-aware projections, bounded/tenant-scoped
  lifecycle history, and TTL'd idempotency keys.
- Supply chain: GitHub Actions and base/runtime images pinned by digest, the
  embedded-PostgreSQL binary pinned against a committed provenance manifest, a
  CycloneDX SBOM and `govulncheck` gate in CI, CODEOWNERS over the root-of-trust
  paths with required code-owner review, and checksum-verified CI tool installs.
- Docs/observability honesty: a reality-tested `docs/limitations.md` that states
  served-vs-library status for every advertised capability, so the binary cannot
  silently over-claim.

### Added
- `CHANGELOG.md` (this file), linked from the README and SECURITY.md (DOCS-005).

### Changed — web console information architecture (IA train)

*Superseded within this release: the module-switcher chrome below evolved into
the five-space unified shell (see "Unified shell (spaces IA)" above). The
defect-class guards it introduced — `naming_parity`, `nav_completeness`,
`module_map`, demo-data isolation, docs IA parity — carry forward unchanged
and still gate the spaces IA.*

- **Option A — refined rail.** The sidebar is re-grouped into four question-shaped
  bands (Inventory / Issue & automate / Detect & respond / Govern & administer) and
  every previously hidden product surface (CA hierarchy, certificate profiles, SSH
  trust, code signing, operations, notifications, privacy, integrate, API explorer)
  is now visible in navigation. One name per surface: nav label, page `<h1>`, and
  document title agree everywhere (a permanent `naming_parity` guard enforces it).
  Platform gains a dedicated **Editions & license** tab, quarantining commercial
  licensing rows off the operational Access and System tabs.
- **Option B — module workspaces.** A top-of-rail **Module** switcher (Certificates &
  PKI, Secrets, SSH, Signing, Fleet) scopes the middle band to one product; the
  cross-domain global planes (identities, discovery, risk, posture, graph, incidents,
  approvals, governance, audit) stay visible under every module. Module homes carry a
  thin served KPI strip that deep-links into filtered lists. The shared audit stream
  gains per-module lenses via `?module=` with a clearable scope chip — one stream, one
  hash chain, N lenses, never per-module silos.
- **Dashboard integrity & renew.** Real-mode dashboards render served data only (the
  fabricated demo trend/activity/bands are gone) and the four action KPIs are wired to
  live counts; the expiring-certificate worklist and detail drawer now offer Renew,
  wired to the identity lifecycle transition.
- **No route/URL changes.** The entire IA change is navigation chrome; every route
  keeps its path, so deep links, journeys, and muscle memory survive. Permanent CI
  guards (`naming_parity`, `nav_completeness`, `module_map`, demo-data isolation, docs
  IA parity) keep the fixed defect classes from returning.

## [0.5.4] - 2026-06-27

### Added
- Expanded the shipped console from a basic shell into task-oriented workspaces for
  certificate lifecycle, secrets, discovery, NHI risk and posture, CA hierarchy,
  incidents, governance, privacy, integrations, and platform operations. The same
  train added feature-to-route coverage guards, generated API types, responsive
  navigation, localization, accessibility checks, and a read-only preview identity.
- Served the next platform integrations: secret rotation/sync and scanning,
  SSO/SCIM/ABAC and break-glass administration, a cert-manager issuer controller,
  Terraform and Python clients, signed compliance evidence, OTLP export, passive
  federation, JIT access, signed WASM plugins, and cloud managed-key custody.
- Introduced the single-repository open-core edition boundary: core/Enterprise/
  Provider status, offline license seams, Provider metering/branding/isolation, and
  explicit Enterprise fences for remediation, federation, managed-key/KMIP custody,
  and governance evidence.

### Changed
- Reworked the console around shared data grids, task-first navigation, responsive
  mobile/desktop layouts, theme controls, and served-state disclosures instead of
  advertising routes without product wiring.

### Security
- Required independent signer authorization, replay-safe issuance recovery,
  encrypted disaster-recovery backups, bounded public protocol/request state,
  bounded outbox execution, default-private optional AI egress, digest-pinned
  deployment artifacts, and release-gate checks before publishing.

## [0.5.3] - 2026-06-18

### Fixed
- Stopped the release workflow from uploading unsigned Windows agent artifacts.
- Corrected the release workflow's shellcheck failure.
- Prepared the compose-profile artifacts consumed by the repository lint gates.

## [0.5.2] - 2026-06-18

### Security
- Hardened tenant offboarding, tenant-bound machine login, byte-backed secret and
  provider credentials, signer content authorization, ceremony purpose binding,
  certificate-profile EKU enforcement, SSRF-protected notifications, bounded
  request parsers, and the local-development plaintext transport exception.
- Made the architecture analyzer run as a repository-wide vet tool and added
  regression guards for tenancy, crypto custody, signer isolation, idempotency,
  outbox/bulkhead behavior, release provenance, and served-surface wiring.

### Fixed
- Routed lifecycle renewal and ACME revocation through persisted platform state,
  rebuilt agent/profile projections from events, made CRL reads side-effect free,
  versioned legacy secret events, and made rotation/reconciliation replay-safe.
- Productized disaster recovery with streamed restore, under-replicated JetStream
  fail-closed behavior, fair outbox leasing, online lease indexes, migration-lock
  polling, isolated-signer Helm wiring, and pinned agent enrollment transport.
- Added stock-client conformance for ACME, EST, SCEP, CMP, and RFC 3161, then fixed
  their CI/release fixtures, OPA v1 policy compatibility, and SCEP AES envelopes.

## [0.5.1] - 2026-06-16

### Added
- Added and exercised SCEP, CMP, MDM enrollment, the constrained-device EST client,
  SPIFFE workload identity and attesters, incident response, SSH CA workflows, code
  signing, PQC migration, the secrets/dynamic-secret/KMIP stack, discovery and
  governance, and the grounded read-only AI/MCP surface.
- Wired the assembled binary to serve issuance protocols, OIDC sessions, the React
  console, signed WASM plugins, the steady-state agent channel, the Kubernetes
  operator, cross-node signer mTLS, FIPS builds, and BYOK/HSM key lifecycle.

### Security
- Completed the first broad hardening sweep across revocation, signer
  abuse-resistance and dual control, tenant isolation, parser bounds and fuzzing,
  event-spine resilience, deployment defaults, release signing/provenance, and
  architecture guard tests.

## [0.5.0] - 2026-06-13
- Hardening milestone toward an enterprise-GA bar for the self-hosted, multi-tenant
  profile: isolated signer custody (sealed CA key persisted across restarts), the
  assembled control-plane server (`cmd/trstctl` → `internal/server`) serving the
  event spine, projections, orchestrator, and REST API, and the architecture linter
  (`tools/trstctllint`) enforcing AN-1/AN-3/AN-5/AN-8 in CI.

## [0.4] - 2026-05-31
- Pre-release development milestone.

## [0.3] - 2026-05-31
- Pre-release development milestone.

## [0.2] - 2026-05-31
- Pre-release development milestone.

## [0.1] - 2026-05-31
- Initial tagged development milestone.

[Unreleased]: https://github.com/ctlplne/trstctl/compare/v0.5.4...HEAD
[0.6.3]: https://github.com/ctlplne/trstctl/releases/tag/v0.6.3
[0.7.0]: https://github.com/ctlplne/trstctl/releases/tag/v0.7.0
[0.6.0]: https://github.com/ctlplne/trstctl/releases/tag/v0.6.0
[0.5.4]: https://github.com/ctlplne/trstctl/releases/tag/v0.5.4
[0.5.3]: https://github.com/ctlplne/trstctl/releases/tag/v0.5.3
[0.5.2]: https://github.com/ctlplne/trstctl/releases/tag/v0.5.2
[0.5.1]: https://github.com/ctlplne/trstctl/releases/tag/v0.5.1
[0.5.0]: https://github.com/ctlplne/trstctl/releases/tag/v0.5.0
[0.4]: https://github.com/ctlplne/trstctl/releases/tag/v0.4
[0.3]: https://github.com/ctlplne/trstctl/releases/tag/v0.3
[0.2]: https://github.com/ctlplne/trstctl/releases/tag/v0.2
[0.1]: https://github.com/ctlplne/trstctl/releases/tag/v0.1
