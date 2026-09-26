# Current limitations & what's not yet served

trstctl is pre-1.0 and under active hardening. This page states plainly what the
running binary serves today versus what is built and tested as library code but
not yet wired into the served product, and which surfaces are explicitly Phase 2.
Maturity is separate from edition gates: Community self-host includes the core
control plane; Enterprise and Provider capabilities activate by an offline signed
license behind the `ee/` boundary. trstctl's core is source-available under `LICENSE`
(BUSL-1.1, converting to MPL-2.0 four years after each release); Enterprise,
Provider and other license-gated features are proprietary material under
`ee/LICENSE`, while PQC and the patent-pending families ship in the core.

If a capability matters to your evaluation, check this page before relying on it.

## The 60-second boundary summary

Read this first; use the exhaustive ledger below only for the capability you plan
to operate.

| Question | Short answer | What to verify next |
| --- | --- | --- |
| Can I run the core control plane myself? | **Yes.** Inventory, lifecycle state, ownership, policy, audit, the REST API, CLI, web console, PostgreSQL tenant isolation, and the separate signer are served. | Complete the [blank evaluation](getting-started.md), then rehearse [production operations](journeys/run-in-production.md). |
| Does every integration work immediately? | **No.** Protocols, connectors, HSMs, cloud discovery, SSO, and commercial workflows are conditional on explicit configuration, reachable infrastructure, and sometimes a signed license. | Open the relevant feature page and the matching matrix row below before promising it. |
| Does “delivered” mean a workload is serving the credential? | **No.** Delivery records what the connector did. Only a successful endpoint handshake earns **verified**. | Review the [served status vocabulary](#served-status-vocabulary-what-each-status-claims) and configure a verification address. |
| Is a green System page a production certification? | **No.** It proves the running process's bounded checks, not an external penetration test, customer topology, disaster-recovery rehearsal, or third-party certification. | Use the [production journey](journeys/run-in-production.md), threat model, and your own acceptance controls. |
| Is every feature production-mature? | **No.** trstctl is pre-1.0. The tables below distinguish Served, Conditional, Partial, and Roadmap without turning source code into a product claim. | Search this page for the feature ID or plain-language capability name. |

The safe decision rule is simple: **served** says the running binary has a real
path; **verified** says the required external effect was observed; neither word
replaces your deployment-specific acceptance test.

## Historical scheduled-rotation detail

The current live event generation does not serve arbitrary provider error text
from schema-v1 scheduled-rotation terminal events. Upgrade sanitation replaces
that one field with a fixed status-specific class before reads, projections,
retention, or export can proceed. This guarantee applies only to repository-
controlled live history. Backup/export files and signed or WORM audit archives
created before sanitation are external copies: trstctl cannot rewrite them and
does not claim they were erased. Operators must govern those copies under their
existing custody and retention policy.

## Feature served-state matrix

This matrix is the canonical served-state table for the feature catalog. The docs
test suite checks every `F*` row below against
`internal/featureparity/feature-map-backlog.json` and runs the repo-native wiring
census against the current source tree. A feature cannot claim Served while a
mapped capability is still library-only, a stub, or unknown; a stale generated JSON
receipt cannot certify it.

- **Served** means the running binary serves the capability end to end.
- **Conditional** means the served path exists but depends on configuration,
  license activation, or an operator-supplied backend.
- **Partial** means a real served path exists, with explicit residual work called
  out below.
- **Library-only** means built and tested, but not yet served by the binary: library
  code exists with tests, but is not yet wired into the served API.
- **Roadmap** means Phase 2 or later work with no current served product claim.

<!-- feature-served-state-matrix:start -->
### Served

| ID | Feature | Primary docs |
|----|---------|--------------|
| F1 | Certificate inventory | docs/features/discovery-and-inventory.md |
| F2 | Network discovery | docs/features/discovery-and-inventory.md |
| F42 | SSH credential discovery and inventory | docs/features/discovery-and-inventory.md, docs/features/ssh.md |
| F49 | Agentless cloud certificate discovery | docs/features/discovery-and-inventory.md |
| F35 | Secret store discovery | docs/features/discovery-and-inventory.md, docs/features/secrets.md |
| F36 | API key / token inventory | docs/features/discovery-and-inventory.md, docs/features/secrets.md |
| F17 | Certificate Transparency monitoring | docs/features/observability-and-risk.md |
| Discovery coverage & provenance | Served: coverage is measured against **operator-declared segments** rather than against what discovery happened to find, with a per-segment staleness SLO, declared exclusions carrying their reason, and a named blind-spot register. Every certificate carries provenance — which source last observed it, of what kind, and when — distinct from when trstctl first recorded it. Headlined on the Discovery console. **Nothing is rollable into coverage until an operator declares a segment**: an inventory built from findings can describe what it found and nothing else, so an estate with no declarations reports no coverage rather than 100% | [Coverage, provenance and blind spots](#coverage-provenance-and-blind-spots) |
| Revocation through external issuers | Served for **letsencrypt (ACME), vaultpki and ejbca** — each proven end to end against that authority's own protocol, asserting the AUTHORITY was contacted rather than that the call returned nil. Every other issuer kind reports `revoke: false` on the served capability matrix with a note naming where to revoke instead. A documented vendor endpoint trstctl does not drive is **not** counted as a capability. Revocation that cannot reach the authority **fails visibly**; there is no silent no-op | [Per-issuer capabilities](#per-issuer-capabilities) |
| Upstream domain validation (DNS-01 as an ACME client) | Served: obtaining a certificate FROM a public CA now negotiates the challenge type the authority offers and solves DNS-01 unattended, reusing the provider configs already persisted for the server direction. **Wildcard issuance from a public CA works for the first time** — DNS-01 is the only challenge that can authorize one. Two independent opt-ins, both default off: `upstream_dns01` on the ACME authority (which also requires that authority's own `caa_issuer_domain`) and `allow_upstream_dv` on each DNS-01 provider config. The console shows a domain-validation column beside every configured issuer — unattended or manual, with the reason — and an upstream authorization freshness panel reporting when each identifier last actually proved control, as against when it last rode a reuse. DNS-01 only: http-01 upstream would need an inbound listener this architecture does not have | [Upstream domain validation](#upstream-domain-validation) |
| F18 | Drift detection | docs/features/observability-and-risk.md |
| F19 | Credential risk scoring | docs/features/observability-and-risk.md |
| F52 | CBOM and cryptographic observability | docs/features/observability-and-risk.md |
| F48 | Private/enterprise CA hierarchy management | docs/features/issuance-and-cas.md, docs/runbooks/key-ceremony.md |
| F53 | Certificate profiles and registration-authority model | docs/features/issuance-and-cas.md, docs/guides/profile-authoring.md |
| F46 | ACME Renewal Information (ARI) | docs/features/issuance-and-cas.md, docs/features/acme-and-dns.md |
| F47 | X.509 revocation infrastructure | docs/features/issuance-and-cas.md |
| F25 | Ephemeral credential issuance | docs/features/workload-identity.md |
| F30 | Workload attestation chain | docs/features/workload-identity.md |
| F59 | Non-human identity lifecycle management | docs/features/workload-identity.md, docs/features/discovery-and-inventory.md |
| F61 | AI-agent / NHI identity broker | docs/features/workload-identity.md |
| F44 | SSH deployment and trust configuration agent | docs/features/ssh.md, docs/design/ssh-trust-rewrite.md |
| F45 | Attestation-gated short-lived SSH user certs | docs/features/ssh.md |
| F6 | Lifecycle automation | docs/features/lifecycle-and-pqc.md |
| F33 | Just-in-time issuance with approval flows | docs/features/incident-and-jit.md |
| F38 | Ephemeral API key issuance | docs/features/secrets.md |
| F28 | Policy engine | docs/features/policy-and-governance.md, docs/cli.md, docs/web-console.md |
| F29 | Notification integrations | docs/features/policy-and-governance.md |
| F8 | RBAC | docs/features/policy-and-governance.md |
| F9 | Audit log surfaces | docs/features/policy-and-governance.md, docs/observability.md, docs/configuration.md |
| F10 | REST API | docs/features/platform-and-api.md |
| F11 | CLI | docs/features/platform-and-api.md, docs/cli.md |
| F12 | Web UI | docs/features/platform-and-api.md |
| F14 | Single-binary distribution | docs/features/platform-and-api.md |
| F15 | Encrypted control-plane transport | docs/features/platform-and-api.md |
| F40 | Multi-tenant deployment topology | docs/features/platform-and-api.md |
| F20 | Plugin SDK with capability sandboxing | docs/features/extensibility-plugins.md |
| F21 | Credential graph | docs/features/graph-query-ai.md |
| F79 | Privacy and data-subject controls | docs/features/policy-and-governance.md, docs/privacy-data-catalog.md, docs/web-console.md, docs/configuration.md |

### Conditional

| ID | Feature | Primary docs |
|----|---------|--------------|
| F3 | Agent-based discovery | docs/features/discovery-and-inventory.md |
| F5 | Built-in ACME server | docs/features/acme-and-dns.md |
| F69 | DNS-01 challenge automation | docs/features/acme-and-dns.md |
| F70 | DNS-provider plugin framework | docs/features/acme-and-dns.md |
| F71 | CNAME delegation for validation isolation | docs/features/acme-and-dns.md |
| F72 | CAA policy enforcement and management | docs/features/acme-and-dns.md |
| F73 | Multi-method domain-validation policy | docs/features/acme-and-dns.md |
| F74 | Automated wildcard issuance and renewal | docs/features/acme-and-dns.md |
| F22 | EST server | docs/features/enrollment-protocols.md, docs/guides/est-enrollment.md |
| F23 | SCEP server | docs/features/enrollment-protocols.md |
| F55 | CMP server | docs/features/enrollment-protocols.md |
| F54 | Embedded / IoT enrollment agent | docs/features/enrollment-protocols.md |
| F56 | Intune / MDM enrollment integration | docs/features/enrollment-protocols.md |
| F24 | SPIFFE Workload API | docs/features/workload-identity.md |
| F43 | SSH certificate authority | docs/features/ssh.md |
| F50 | Code-signing service | docs/features/code-signing-and-timestamping.md |
| F51 | Timestamping authority | docs/features/code-signing-and-timestamping.md |
| F26 | HSM integration | docs/features/issuance-and-cas.md, docs/configuration.md, docs/compliance.md, docs/limitations.md |
| F7 | Deployment connectors initial set | docs/features/deployment-connectors.md |
| F27 | Additional deployment connectors | docs/features/deployment-connectors.md |
| F31 | Credential compromise workflow | docs/features/incident-and-jit.md, docs/features/discovery-and-inventory.md |
| F32 | Fleet re-issuance for CA compromise | docs/features/incident-and-jit.md |
| F34 | Break-glass procedures | docs/features/incident-and-jit.md |
| F37 | Secret rotation engine | docs/features/secrets.md |
| F39 | Code/CI secret scanning bridge | docs/features/secrets.md |
| F63 | Native secret store | docs/features/secrets.md |
| F65 | Dynamic secrets | docs/features/secrets.md |
| F66 | Encryption-as-a-service and KMIP | docs/features/secrets.md |
| F68 | Secret sync / platform integrations | docs/features/secrets.md |
| F67 | PKI as a secrets engine | docs/features/secrets.md |
| F58 | Platform auth-method framework | docs/features/secrets.md |
| F60 | Secret sharing and secret-change approvals | docs/features/secrets.md |
| F62 | Cryptographic compliance reporting & posture dashboards | docs/features/policy-and-governance.md, docs/compliance.md |
| F13 | SSO/OIDC | docs/features/platform-and-api.md |
| F41 | Cross-cluster / multi-region federation | docs/features/platform-and-api.md |
| F75 | Unified semantic query layer | docs/features/graph-query-ai.md |
| F76 | Pluggable AI model adapter | docs/features/graph-query-ai.md |
| F77 | Grounded RCA and natural-language query | docs/features/graph-query-ai.md |
| F78 | trstctl MCP server | docs/features/graph-query-ai.md |

### Partial

| ID | Feature | Primary docs |
|----|---------|--------------|
| F4 | CA-agnostic outbound issuance | docs/features/issuance-and-cas.md |
| F16 | Crypto-agility and PQC readiness | docs/features/lifecycle-and-pqc.md |
| F57 | PQC migration orchestration | docs/features/lifecycle-and-pqc.md |
| F64 | Developer secrets experience | docs/features/secrets.md, docs/cli.md, docs/journeys/manage-secrets.md |

### Library-only

| ID | Feature | Primary docs |
|----|---------|--------------|

### Roadmap

| ID | Feature | Primary docs |
|----|---------|--------------|

<!-- feature-served-state-matrix:end -->

### Feature pages without an `F*` catalog row

A feature page can document a surface that carries no `F*` catalog ID, so the
generated matrix above cannot hold it. Those pages record their served state
here instead, in the same vocabulary, so no page in the feature catalog is
statusless.

| Page | Served state | Why it has no `F*` row |
|---|---|---|
| docs/features/agent-delegation.md | Conditional | Part of the core since 2026-09-20. `attachAgentDelegation` in `cmd/trstctl/attach_families.go` attaches the `/api/v1/agent-delegation/*` routes and the `agentid.issue-chain-bound` outbox worker in every build, and the signer refuses a chain-bound mint until the operator provisions the root-anchor, reachability-verdict, and attestor trust floors under the signer key store. |
| docs/features/client-sdks.md | Served | The generated clients under `clients/sdk/` track the served OpenAPI 3.1 contract; they package the REST API rather than adding a capability of their own. |

## Census proof modes

The served denominators quoted in the README and on this page are checked against the
repo-native census gate (`tools/dodcensus/manifest.json` in the repository) (`make dod-gate` emits the
local `wiring-census.json` receipt). Proof modes are not uniform:
**12 of 81 census rows launch the shipped binary**;
**69 of 81 are proved through the production-assembled handler** — the production
`buildRunDeps` output driving the assembled `Server.Handler` in-process, with a
hand-built `Deps` rejected. Only the process launch differs, so each served row names
the mode that proved it. This vocabulary is for maintainers and auditors; a customer
reads the README's one-line summary and the journeys.

## Status at a glance

One line per domain below, for a reader who wants the answer without the prose.
"Served" here always means the running binary, not a library package.

| Domain | Status | Detail |
|---|---|---|
| Core inventory, lifecycle, connectors, discovery | Served end to end | [Served by the running binary today](#served-by-the-running-binary-today) |
| Tenant offboarding & audit retention | Served; PostgreSQL rows erased, event log/archive follow separate retention | [Tenant offboarding boundary](#tenant-offboarding-boundary) |
| Library-only backlog | Empty — nothing is stuck library-only right now | [Built and tested, but not yet served](#built-and-tested-but-not-yet-served-by-the-binary) |
| Conditional/partial residuals | Real served spine; specific operator-facing edges remain | [Conditional, partial, and residual boundaries](#conditional-partial-and-residual-boundaries) |
| Served status strings | Every status is registered with what the code actually did; CI blocks a status spelled stronger than its own flags | [Served status vocabulary](#served-status-vocabulary-what-each-status-claims) |
| CA hierarchy expiry horizon | Served; year-scale bands, re-alerting on each tightening, leaf-validity-compression check, horizon on the CA API and console | [The CA calendar](#the-ca-calendar-year-scale-hierarchy-expiry) |
| ACME external account bindings | Served; kid persisted on the account, per-credential identifier scope / quota / window enforced fail-closed, runtime disable. Rotation stays a config operation | [Protocols](#protocols) |
| Certificate Transparency monitoring | Served as a headline Discovery capability: exact source replacement, active versus retired watchlist history, immutable per-log success/failure with independent checkpoint progress, unexpected-issuance findings, and remediation hand-off. Covers only the domains and logs configured | [Served by the running binary today](#served-by-the-running-binary-today) |
| Key custody per credential kind | CI-checked table; every enrollment protocol, and the identity API given a CSR, generate keys in your environment. Three paths still generate one in the control plane, each named with its successor | [Key custody](custody.md) |
| Key custody per credential | Served: custody is recorded on the certificate row at issuance from what the issuing path actually did, returned by the certificate API, and shown on the certificate in the console. Certificates issued before this shipped, and every certificate found by discovery, read as **not recorded** — which is a different statement from any custody claim, and is never rendered as reassurance | [Key custody](custody.md) |
| Agent job ledger | Served: agents claim, lease, extend, report and lose work over the mTLS channel; aggregate waiting/claimed health is on Operations. The shipped agent census executes `connector.deploy`, `connector.test`, `connector.rollback`, `endpoint.renew`, `endpoint.verify`, `discovery.run`, `revocation.probe`, `adcs.inventory`, `trust.distribute`, `cmdb.sync`, `mdm.sync`, `ticket.sync`, and `agent.upgrade`; each row's role and agent constraints select the eligible host agent or network relay. Nothing is claimable until an operator names that kind in `agent_channel.claimable_job_kinds` — including `connector.rollback`, which must be enabled separately from deploying | [The agent job ledger](#the-agent-job-ledger-served-executors-and-signed-receipts) |
| Agent job receipts | Served: every terminal report is signed by the agent with the key behind its channel certificate, verified against the certificate that authenticated, stored with the event, and refused fail-closed with an audit event when it does not verify. A successful host-generated renewal uses the v2 statement, which also binds the installed certificate fingerprint plus origin, storage, exportability, and generator; the projected custody event is replayable. Verified and refused counts, and the reason for the most recent refusal, are on Operations. The signature is over the report's facts and a digest of its text — it attests what the agent SAID, not that the appliance changed | [The agent job ledger](#the-agent-job-ledger-served-executors-and-signed-receipts) |
| Renewal windows, canaries and SLOs (D6) | Served: maintenance windows restrict when the scheduler may renew (`lifecycle.maintenance_windows`, e.g. `Mon,Tue,Wed,Thu,Fri 22:00-06:00 Europe/London`); a closed window **defers** with a recorded reason naming when it reopens, never drops. Fleet re-issuance is a durable outbox-backed batch state machine: start publishes only the canary, an accepted signed agent receipt is required to advance, pause/halt stores the cursor and reason, and resume/restart reuses deterministic ids. Any failed verification fails the gate and any unverified replacement keeps it `not_evaluated`; later batches remain unpublished after a canary failure. Renewal success SLO with error-budget burn on `GET /api/v1/operations/renewal-slo`, window and target both operator inputs | [Renewal windows, canaries and SLOs](#renewal-windows-canaries-and-slos) |
| Endpoint verification (D2) | Served: after a deploy the host agent handshakes the changed listener — the only observation of whether the **reload took effect** — and a network relay probes the same endpoints as a client would, which is the only witness for an appliance. Divergence is classed (`fingerprint`, `sans`, `chain`, `expired`, `not_yet_valid`) because the remedies differ; `unreachable` is neither a pass nor a divergence. Results are signed: the probe transcript's digest travels inside the agent's receipt, so a verdict is checkable rather than asserted. **Verification is opt-in per target**: an endpoint with no configured listener address is never verified and never claims to be. `verified %` on the dashboard is a percentage of OBSERVED endpoints and the tile is hidden entirely until something has been observed. Sweeps re-probe hourly; divergence raises a `critical` alert (unreachable: `warning`) through the notification outbox; automatic rollback to the predecessor is available per target, opt-in and off by default | [Endpoint verification](#endpoint-verification) |
| Connector rollback | Served through two honest execution models. **f5, kemp, netscaler, a10** re-bind a fingerprint-named object already on the appliance. All 14 host connectors restore the one encrypted predecessor bundle retained only by the exact enrolled host agent, run the connector reload, and reverify the listener when configured. Deploy and rollback share a serialized per-target lane. Unsupported cloud/appliance/plugin routes return `409` and write no rollback-shaped receipt. Automatic rollback after `verify_failed` is opt-in per target; manual rollback uses the same job and signed transcript | [The agent job ledger](#the-agent-job-ledger-served-executors-and-signed-receipts) |
| CA migration waves (H2) | Served for internally issued X.509 identities on host-agent connectors: read-only assessment, reviewed exact-authority manifest, durable trust-before-leaf waves, signed trust/live gates, pause/resume, halt, and newest-first rollback | [Migration waves](#conditional-partial-and-residual-boundaries) |
| Agent roles (host / network relay) | Served: an operator grants host and/or network at enrollment, the CA stamps it into the certificate, and the claim path refuses out-of-role work. Role badges on Agents. Agents redeem credential material just-in-time, once per job attempt. **Connector deploys carry a per-row role demand** stamped at enqueue from the shipped vantage census — an F5 deploy is claimable only by a relay, an nginx deploy only by a host agent, a cloud-store deploy by no agent. The control-plane dispatcher structurally refuses host-stamped and legacy host-family rows before native lookup or I/O, so 14 host families execute only on the enrolled host agent; an unavailable agent leaves pending work, never a control-plane fallback | [Agent roles](#agent-roles-a-vantage-in-the-certificate) |
| React web console | Served: real embedded Vite build at `/`, generated API types | [The React web console](#the-react-web-console-served-by-the-binary) |
| OIDC/SAML/LDAP browser login & tenancy | Served behind config flags; each user maps to a real tenant | [Browser login & sessions](#interactive-oidc-saml-and-ldap-active-directory-browser-login-sessions-served-by-the-binary) |
| SCIM 2.0 + NHI inventory/posture | Tenant SCIM requires Enterprise SSO; SCIM Bulk and directory writeback not implemented | [SCIM 2.0 provisioning](#scim-20-provisioning-served-by-the-binary) |
| AI / RCA / MCP surface | Served, off by default, air-gapped unless an operator opts in | [AI, RCA, and MCP surface](#ai-rca-and-mcp-surface) |
| Secrets, identity frameworks, transit/KMIP | Served (six of six frameworks); Vault shim is a partial subset | [Secrets and identity frameworks](#secrets-and-identity-frameworks) |
| RBAC / ABAC / OPA policy gates | Served, fail-closed, off by default | [Authorization policy gates](#authorization-policy-gates-and-abac-overlays-served-by-the-binary) |
| Plugin isolation | First-party runs trusted in-process; third-party is WASM-sandboxed and signature-verified | [Plugin isolation](#plugin-isolation-first-party-in-process-third-party-sandboxed) |
| Protocols: ACME/EST/SCEP/CMP/SPIFFE/SSH/TSA | Served end to end, each behind its own enable flag | [Protocols](#protocols) |
| Revocation (OCSP/CRL) | Served, signed by the isolated signer | [Revocation](#revocation) |
| Single sign-on detail | Served; Kerberos/GSSAPI, NTLM, and SLO not yet implemented | [Single sign-on](#single-sign-on) |
| CA key custody / HSM / BYOK | Sealed local key store by default; six of six HSM/KMS backends served | [CA key custody](#ca-key-custody) |
| Post-quantum cryptography | ML-DSA/ML-KEM/SLH-DSA available; compatibility-bounded proofs | [Post-quantum cryptography](#post-quantum-cryptography-issuance-algorithms) |
| Kubernetes deployment | Helm chart plus a focused Operator; Operator doesn't manage networking yet | [Kubernetes deployment](#kubernetes-deployment) |
| Performance & usability NFRs | Perf/scale measured in CI; usability evidence-gated, no NPS claim yet | [Non-functional targets](#non-functional-targets-what-is-measured-vs-aspirational) |

## Served by the running binary today

The `trstctl` binary assembles and serves a control plane: the tamper-evident event
log, the read models it projects, the lifecycle orchestrator, and the REST API, with
the signing service supervised as a separate out-of-process child so private keys
never live in the API process. What you can do end to end against the running binary:

- Inventory and lifecycle for owners, issuers, identities, and certificates:
  create, read, list (keyset-paginated), and drive the lifecycle state machine.
- Connector delivery and rotation evidence: deployment attempts emit
  `connector.delivery.recorded` receipts and scheduled renewals emit
  `lifecycle.rotation.recorded` runs, both readable through the API, CLI, and
  console. The receipt is routing/status metadata only — no private key or secret
  bytes are returned. Rotation replay compares `completed_at` at PostgreSQL's
  microsecond precision: sub-microsecond bits that cannot survive the first database
  write are one observation, while a difference of one stored microsecond still fails
  closed as changed terminal evidence. This lets exact JetStream replay converge
  without weakening the run ID, tenant, outbox, binding, outcome, or sequence checks.
- Automated endpoint binding: first call the effect-free
  `POST /api/v1/lifecycle/endpoint-bindings/preview` with the exact platform,
  private, or external issuer. The preview reports CA identity, key custody, target
  revision, writes, queued effects, recovery, verification, and a request
  fingerprint while performing zero writes and zero external calls. Sending that
  unchanged fingerprint to `POST /api/v1/lifecycle/endpoint-bindings` creates the
  X.509 identity for an existing owner, provisions or references the connector
  target, pins the chosen issuer, and queues issue/deploy work through the outbox.
  Missing, unavailable, or changed issuers fail closed; the worker does not
  substitute the built-in CA. The leader scheduler later renews through that same
  pinned authority and sends the successor through `connector.deploy`.
- Certificate key custody, corrected (B5 re-audit): the four custody columns
  (`key_origin`, `key_storage`, `key_exportable`, `key_generated_by`) are now
  actually persisted. They were added to the schema, set by the issuing code and
  served by the API, but `projections.CertificateRecorded` had no fields for them
  and the projector's INSERT never listed them — so every projected certificate
  recorded blanks while three layers of the system agreed custody had been
  captured. B5 was signed off in that state. The `key_origin` half surfaced while
  implementing B2, because B2's own claim depended on it; the other three surfaced
  only on re-audit. A regression test now reads the DATABASE rather than asserting
  a struct field was assigned — the distinction that made this invisible — and a
  structural test fails if a custody field exists on the row without a matching
  field on the event that carries it.
- Host-generated endpoint keys (B2): a deployment target whose config sets
  `executor: "agent"` opts out of credential-bearing delivery entirely. When the
  lifecycle scheduler renews an identity bound to such a target, the issuance
  dispatcher queues an `endpoint.renew` job INSTEAD OF MINTING — the branch is at
  mint time, not deploy time, because once a certificate has been minted for a
  server-keygen identity the control plane already holds a private key and no later
  refusal can unmake that. A host agent then claims the job, generates the subject
  key on the machine that will serve it, sends a PKCS#10 up through `SignJobCSR`,
  installs the returned certificate with its locally held key, and verifies the
  listener. The rotation run is recorded as succeeded on the HANDOFF, not on a
  certificate: the certificate does not exist until the agent's CSR arrives, and
  D3's three-state truth reports the rest. The control plane never holds
  that private key, and `enforceExecutorParity` REFUSES — rather than silently falling
  back — any deploy that would carry key bytes to such a target, so a target cannot
  read as migrated while still receiving keys. Scope, stated exactly: this is per
  target and opt-in; targets without the marker keep the control-plane path unchanged,
  which is the supported default and not a defect. Renewal is host-vantage only — a
  network relay cannot claim `endpoint.renew`, because generating a key for an
  appliance it merely reaches would reintroduce the custody hop this removes. The CSR
  is authorized against the names the job payload already carries, so an agent cannot
  widen its request. `GET /api/v1/endpoints/key-custody` and the Connectors console
  report, per target, which path it is on and how much of the estate has moved.
- Expiry-alert delivery: the leader lifecycle scheduler honors the configured alert
  window, writes `notification.expiry` outbox work, stamps `alerted_at` in the same
  transaction so one certificate does not spam, and the outbox worker dispatches
  through operator-wired Slack, Teams, email, SMS, SIEM, webhook, PagerDuty Events
  v2, or OpsGenie Alert v2 channels. The dispatcher holds credentials in locked
  memory and wipes them on shutdown; the payload carries the owner, approver
  escalation recipients, severity, and threshold-day metadata. This is runtime
  delivery, not a tenant channel-management API.
- Deployment connector orchestration serves target metadata, identity binding,
  outbox intent, receipts, provenance-verified WASM dispatch, and all 24 advertised native connectors.
  Device proof (E1): every appliance family — a10, cisco, f5, fortigate, kemp,
  netscaler, paloalto — now carries a faithful in-process double of its management
  API and tests that drive the REAL connector against it, and the connector catalog
  reports which families have that proof. This is a different claim from the
  conformance suite every connector passes: conformance runs against an in-memory
  double that accepts any request, so it proves a connector respects its capability
  grant and is replay-deterministic while proving nothing about whether the device
  would have accepted the call. For an appliance, whose entire implementation is an
  API conversation, that was the only untested part. Each suite is verified
  load-bearing by stubbing the connector's Deploy to return nil and confirming the
  tests fail. A guard test refuses a family that claims device proof without both an
  emulator package and a test that drives it.
  Single-box demo (A5): `trstctl --demo` serves the control plane AND starts a
  colocated host agent. Evaluating this product otherwise needs two installs, and
  until both exist nothing the product is FOR can be shown — no deploy executes, no
  endpoint verifies, no renewal lands on a host. It is also the cheapest defense
  against the defect this program keeps finding: six capabilities have been
  complete, tested and unreachable from the running binary, and every one would have
  been obvious the first time somebody drove it end to end on one machine.
  The agent is EXEC'd, never linked. `cmd/trstctl-agent` must not link the control
  plane and a guard pins that; importing it here to save a process would put both on
  the same side of the boundary the architecture rests on, and the demo would stop
  exercising the real channel. Two binaries over the real gRPC channel is what a
  deployment does, so the demo tests the actual path.
  `--demo` FORCES two settings and reports both rather than applying them quietly:
  the agent channel (off by default — correct for production, fatal for a demo,
  because the agent has nothing to dial) and a conservative claimable-job set
  (`discovery.run`, `endpoint.verify`, `connector.test`). An empty claimable
  allowlist is the trap worth naming: the job ledger is served, hands nothing out,
  and the agent enrolls successfully and idles while every surface looks healthy —
  the most misleading possible demo. `connector.deploy` is deliberately NOT enabled;
  an evaluation box must not mutate an appliance somebody pointed it at by accident.
  Settings an operator did set are never overwritten.
  A missing agent binary is a FATAL error naming where it looked and how to build
  one, not a warning. `--demo` is an explicit request for a colocated agent, and a
  run that serves the control plane while silently omitting the agent is exactly the
  "looks like it worked" outcome the flag exists to prevent. The bootstrap token is
  minted through the SERVED enrollment API — not by reaching into the store, because
  reaching in would let the demo work while the served enrollment path was broken —
  and written to a 0600 file, never passed as an argument, since process arguments
  expose bearer credentials and the agent refuses them for that reason.
  Also fixed here: `agent_channel.claimable_job_kinds` was the ONE AgentChannel
  field with no environment key, so a container deployment could enable the channel
  and had no way to let an agent claim anything. `deploy/demo/docker-compose.yml`
  set no agent-channel variables at all while its seed job advertised enrollment
  tokens nothing could redeem; it now enables the channel and the same conservative
  claimable set.
  SECURITY FIX (provider plane, 2026-08-05): the provider plane authenticated NOBODY.
  `operatorFromRequest` parsed `Authorization: Bearer provider:<id>:<email>` for SHAPE
  and returned an operator with `Role: OperatorAdmin` and `MFA: true` — no verification
  of any kind, and multi-factor asserted on the caller's behalf. `/provider/` is mounted
  on the root mux behind only a bulkhead whenever the provider plane is licensed, so on
  any provider-tier binary tenant create, suspend, offboard and break-glass were
  reachable by anyone who knew the token format. The format was in the source.
  Break-glass was worse: `consentBreakGlass` did not authenticate at all and took the
  consenting subject from the REQUEST BODY, so the operator who requested emergency
  access named whatever approver they liked and consented to their own grant with a
  second call. Two-person control defeated by a JSON string.
  Fixed by requiring a configured `OperatorAuthenticator`. Every other dependency in the
  provider Config falls back to a working stand-in; this one deliberately does not,
  because the safe stand-in for "who is this caller" does not exist and a placeholder is
  precisely how the original behavior came to ship. A nil authenticator now refuses
  every request — an unconfigured provider plane is closed, not open — and the consenting
  subject is the authenticated caller, with a `subject` in the body REJECTED rather than
  ignored so an integration cannot keep sending one and believe it has effect.
  Unauthenticated requests answer 401 rather than 403: "I do not know who you are" is a
  different statement from "I know, and you may not".
  Both bypasses are mutation-verified against the real handler. The consent test creates
  a real tenant and a real grant first — an earlier version used a made-up grant id and
  the mutation check showed it caught the regression only because a nonexistent grant
  404s, so its primary assertion never fired. Note that this CLOSES a surface that was
  open: a provider-tier deployment must now wire an authenticator before `/provider/`
  serves anything, which is a deliberate breaking change and the right direction.
  THE AUTHENTICATOR NOW EXISTS (L1): `provider.oidc` in the config federates
  operator identity to the provider's own IdP — bearer tokens verified OFFLINE
  against a pinned JWKS (`jwks_file`/`jwks_json`; the plane never fetches keys
  from a URL the token's minter might control), issuer, audience, expiry and
  nbf all required, and ROLE AND MFA read from claims the IdP signed
  (`role_claim` values mapped by `admin_values`/`operator_values`; `mfa_claim`,
  default `amr`). A token the IdP vouches for that matches NO configured role
  is refused outright — federation is not enrollment, and the IdP vouching for
  the whole workforce must not make every employee someone who can suspend
  customers. A single-factor operator authenticates and is then refused
  mutations (403 at the act, not 401 at the door — the gap is MFA and the
  error should say so). Federation answers WHO; the per-customer delegation
  still answers WHICH customers, and the combined test proves a federated
  admin delegated one customer cannot suspend another.
  SAML AND SCIM ARE NOW SERVED (AUD-58): Provider SAML mounts a separate SP at
  `/provider/v1/auth/saml/login`, `/acs`, and `/metadata`, verifies signed
  assertions plus issuer/audience/time/request correlation and mapped role/MFA,
  then issues a Provider-only HttpOnly session protected by double-submit CSRF.
  Provider SCIM mounts `/provider/scim/v2`; its file-backed bearer is hashed and
  wiped at startup. Join/update/leaver changes are immutable operator events.
  When SCIM is enabled, OIDC and SAML query that directory row every request,
  so a deprovisioned operator's still-valid credential is refused immediately
  and the same projection revokes all standing customer authority. Provider
  admin + MFA list/grant/revoke/role routes expose identity source, customer,
  operation, expiry, last use, and retained revocation evidence. SCIM Bulk and
  arbitrary custom Provider roles are not implemented; group remove/replace is
  refused in favor of an explicit User `active:false`/DELETE leaver event.
  Crypto migration sequencing (M2): `GET /api/v1/graph/crypto-readiness` and a Risk
  console panel order every observed crypto asset by WHO DEPENDS ON IT, not by
  severity alone. The CBOM already said which algorithms are weak; it could not say
  which change is hard. Sorted by severity only, a forgotten lab box exhibiting
  RSA-1024 outranks a load balancer twelve services authenticate through, and the
  migration gets planned in the wrong order by a table that looked authoritative.
  The traversal walks BACK from a crypto asset along EXHIBITS to the resources using
  it, then BACK again along CONNECTS_TO / GRANTS_ACCESS / DEPLOYED_TO to the parties
  that depend on those resources. Both hops are reverse because every edge involved
  points from the dependent toward the thing depended on — a first cut walked
  out-edges from the resource, found nothing, and reported zero dependents for
  everything while looking perfectly well-formed, which is the worst failure
  available to a surface whose whole job is counting dependents. Each dependent is
  served with the resource it was reached through, so a sequencing recommendation can
  be checked rather than trusted, and owners are attributed so a blocker has names
  against it.
  Two honesty constraints are built into the wording rather than left to the reader.
  Dependents are what DISCOVERY HAS OBSERVED: the graph is built from scans, so an
  asset with zero dependents renders identically to one sitting on a resource nothing
  has scanned, and no row is ever labeled safe to rotate — the recommendation for a
  weak asset with no observed dependents says in words that zero observed is not zero.
  And a CBOM usage recorded with NO LOCATION has no place on the graph and no
  computable blast radius; it is counted separately as unplaceable rather than sorted
  to the bottom, because an asset that cannot be placed is unmeasured, not low-risk.
  AUD-64 fixes the production source and direction of those claims. A host/network
  reporter sends a metadata-only `service_dependency` finding through the tenant-bound
  `agent.mtls.ReportInventory` channel. Source kind and finding kind must BOTH be
  `service_dependency`; `workload`, `target`, and the target `ref` must be present and
  agree; and the verified agent certificate stamps the observing host. The immutable
  discovery event survives restart/rebuild. `graph.Build` joins the exact workload name
  to that tenant's owner row and emits workload -> resource `CONNECTS_TO`; an unknown
  owner or mismatched target fails the graph read rather than silently reporting zero.
  Credential owner attribution separately follows the INCOMING production `OWNS` edge
  (workload -> credential), so tests no longer reverse that relationship. Scope: this
  sequences only dependencies an agent actually reports. It does not infer network traffic,
  and its ordering is only as complete as the reporters feeding it.
  AUD-65 makes this one exportable workflow instead of a Risk-only readout.
  `GET /api/v1/graph/crypto-readiness` is the canonical tenant dataset consumed by
  Risk and CBOM/Posture; it includes a digest and event-projected owner actions.
  `POST /api/v1/graph/crypto-readiness/actions` binds an existing core PQC campaign
  finding to the exact row digest and current attributed owner. Missing, foreign,
  unlocated/unowned, or later-changed topology is refused rather than guessed; stale
  actions stay visible but return `409` on mutation. `GET
  /api/v1/graph/crypto-readiness/export` returns the same ordered rows as bounded CSV
  and NDJSON plus an audit-key JWS/JWKS, and compliance evidence-pack v5 embeds the
  same dataset in its signed manifest. This still cannot discover dependencies no
  reporter observed; the coverage guidance travels in every format.
  CORRECTION (D2/D3, B2, R1, F1, H2 — 2026-08-05): FIVE agent-claimable job kinds
  dead-lettered before any agent could claim them. The control-plane dispatcher is
  the sole handler for every outbox sweep, and its default branch returns a hard
  error for an unrecognized destination — right for a genuinely unknown one, fatal
  for work an AGENT is meant to execute. A hard error burns the row's attempt budget
  and lands it in `status='failed'`, and `ClaimAgentJobs` only ever hands out rows in
  `pending`. So `endpoint.verify` (D2/D3), `endpoint.renew` (B2's host-generated
  renewal — the epic's central path), `revocation.probe` (R1), `adcs.inventory` (F1)
  and `trust.distribute` (H2) each enqueued rows that died on arrival, while the API
  had already told the operator the work was queued.
  This was already understood for two of the nine claimable kinds:
  `connector.rollback` and `connector.test` carry explicit deferral cases whose
  comment spells out this exact failure. Nobody applied it to the other five. The
  dispatcher now derives the answer from `agentJobKindAllowlist` — the one place that
  decides what an agent may execute — so a kind added there cannot be forgotten here,
  because there is nothing here to forget. A genuinely unknown destination still
  fails closed: the dispatcher must not become a global silent ACK, which loses a row
  quietly instead of dead-lettering it loudly.
  Related and separate: `RunEndpointVerificationScheduler` was also never registered
  as a runtime worker, so nothing produced `endpoint.verify` rows at all. Registering
  it is what made the dead-lettering visible — the scheduler began producing work
  that immediately died. Both halves are fixed; either alone would have left the
  capability dark.
  That makes SIX instances of one defect in this program: D2's VerifyAddress with
  no producer, B2's `endpoint.renew` with no enqueue, B5's custody projection never
  written, J2's restore drill with no production caller, the unregistered
  verification scheduler, and this dead-letter path. The shape never varies — the
  capability is complete, its unit tests drive it directly, and the composition root
  does not reach it — and unit tests cannot catch it by construction, because they
  stand in for the caller that does not exist. Two guards now do:
  `TestEveryDeclaredRuntimeWorkerIsActuallyStarted` fails on any declared `Run*(ctx)`
  scheduler that is not started, and `TestNoAgentClaimableKindIsEverDeadLettered`
  walks the claimable allowlist and fails on any kind the dispatcher would refuse.
  Both mutation-verified; the second names all five kinds when the fix is removed.
  Offline renewal resilience (A5, PARTIAL): a host agent now schedules its next
  rotation from the credential's REMAINING LIFE on its own clock, not from
  `--rotate-every` alone. The old timer was the configured interval and nothing
  else, which let three ordinary situations end with an agent asleep past its own
  expiry: an interval set longer than the certificate lifetime, a control-plane
  outage spanning a whole interval so the single attempt inside it failed and the
  next was a full interval away, and an agent restarting while holding a credential
  already most of the way through its life. All three end identically — the agent
  wakes with an expired certificate and can no longer authenticate to renew it,
  which needs a person on the box, for a fleet whose value is not needing one.
  The next attempt is therefore `min(two-thirds of remaining life, --rotate-every)`,
  jittered ±10%. The min() is the guarantee and only one half of it carries any
  weight: two-thirds-of-remaining is strictly below remaining, so no configured
  cadence can push an attempt past expiry. A first draft also clamped to
  `remaining - remaining/10` with a comment calling that the load-bearing line;
  mutation-testing showed deleting it changed no outcome, and it was removed rather
  than left as dead code under a false claim. The jitter is not cosmetic: agents
  installed by the same automation hold near-identical expiries, and without spread
  a fleet renews in one second — arriving during recovery from the very outage that
  synchronized it.
  Local clock, deliberately: the agent that cannot reach the control plane is exactly
  the agent that most needs to renew early, and it has no other clock to consult. A
  host with a badly wrong clock renews at the wrong time, which is a real limitation
  and is stated here rather than defended against with machinery that would need the
  network the agent does not have.
  A5's other items have since landed and their honest scope lives with the
  staged-upgrade entry below: rings run as dispatched, per-agent-targeted jobs
  when a campaign publishes artifacts; the agent's `-self-upgrade` executor
  verifies the pinned sha256, keeps the previous binary as `.old`, reports a
  signed receipt and restarts; and `--demo` exists. Agent/control-plane version
  skew IS enforced — `agentProtocolInterceptor` refuses a handshake outside
  `MinSupportedVersion..MaxSupportedVersion` — and was met before this
  program, so it is not claimed as new work.
  Constrained edge sub-CA (B6, THE one deliberate exception to AN-3/AN-4): a
  host with no path to the brain issues leaves locally under a delegated CA,
  and every bound that makes that defensible is enforced, not documented.
  Minted BY the central isolated signer over a CSR (the edge key never
  travels), with name constraints taken from the SEGMENT'S POLICY — never the
  request — in the certificate itself (permitted and excluded subtrees,
  exclusion beating permission), path length pinned to zero, and a 30-day
  ceiling on life that is refused rather than clamped. Default OFF: minting
  requires a declared segment's explicit opt-in, and the opt-in is one
  declaration carrying the pinned TPM attestation roots, the segment's
  identifiers, and a closed allowed-key-provider list. That list defaults to
  `tpm2` only. An un-attested host is refused. In the default TPM2 lane, an
  attestation over a different key than the CSR's is refused (a TPM vouching
  for one key must not license delegating another). The delegation is revocable from the brain and its
  serial lives in the parent CA's issued ledger, so OCSP and the CRL answer
  for it with no new machinery; expiry is the certificate's own clock. Local
  issuance (agent `-edge-issue`) enforces the constraints read FROM THE
  DELEGATION CERTIFICATE and fails closed on an out-of-constraint name; every
  issuance lands in a journal in exactly the reconcile request's shape, and
  `trstctl edge delegations reconcile -f <journal>` posts it when a path or a
  courier exists. Reconciliation re-verifies each leaf (signature chains to
  the delegated CA; names re-checked) and records an out-of-constraint leaf AS
  A VIOLATION — visible, never silently dropped and never silently accepted —
  while reconciled leaves enter the certificate inventory so there is no
  shadow estate. Key custody, stated exactly: `trstctl-agent --edge-csr`
  defaults to a persistent TPM2 signing object and writes only an opaque public
  handle; `--edge-issue` reopens that handle and asks the TPM to sign. PKCS#11
  is a configured alternative whose shipping module creates a token object
  with `CKA_SENSITIVE=true` and `CKA_EXTRACTABLE=false`. It must be explicitly
  allowed in the segment policy because the host's WebAuthn TPM attestation
  authenticates the host and CSR request, not the separate token object; the
  evidence therefore says `host_attested_operator_claim`, not hardware-key
  attested. Exportable software PEM custody exists only behind BOTH
  `--edge-key-provider software --edge-allow-software-key` and an explicit
  segment-policy allowlist entry. Its durable evidence says `file`,
  `key_exportable=true`, and `host_attested_software_exception`; the console
  renders that exception rather than borrowing the host TPM's stronger label.
  Neither hardware path silently falls back when its device/session is absent.
  Issuances made while the host is
  unreachable are invisible until its journal reconciles, and the console
  panel says so rather than rendering silence as inactivity; there is no
  automatic renewal of a delegation — expiry is the design, and a host that
  needs longer asks again through the same attested flow. The exact TPM2,
  PKCS#11, and software-exception command/configuration lanes are documented in
  [Disconnected edge CA key custody](edge-ca-custody.md).
  Authority agreement (C4): the pipeline now has a PRODUCER. A scheduled round
  observes the store-backed authorities, and when two signed digests commit to
  different state the scheduler hands every disagreeing pair to a sink that
  builds the witness, signs it in the isolated signer, records it in the event
  ledger (with both signed digests on the event, so offline verification needs
  nothing else) and passes it to quarantine admission. An earlier audit found
  the opposite: rounds were never scheduled, `witness.Recorder.RecordWitness`
  had no production caller, and every ingredient of "we checked and your
  authorities agree" shipped except anything doing the checking — the
  `collecting=false` state and its wording exist because of that finding, and
  they still guard the zero-schedule deployment today.
  Authority agreement (C4, core reconciliation): `GET /api/v1/reconcile/agreement`
  and a Posture console panel report whether the configured authorities agree about
  what was issued, and where they do not. XREC already built the hard part — canonical
  records per authority, signed Merkle digests over them, and witnesses naming the
  exact differing subset — and had nowhere to say so: the drift projection accumulated
  every witness class per authority and was never exposed on the runtime, so no route
  could read it. The system could detect that two authorities disagreed and could not
  tell anybody.
  The design constraint is that SILENCE RENDERS AS AGREEMENT. "0 open witnesses" looks
  identical whether reconciliation found nothing, is unconfigured, or
  has consumed no events yet, so the surface refuses to show a reassuring zero it
  cannot stand behind. A deployment with no reconciliation runtime reports that fact
  and states plainly that it is NOT a report that the authorities agree; a configured
  but cold projection says its counts are not yet evidence; and every response carries
  the replay watermark beside the count, because a projection lagging the event log
  reports an old world confidently. Resolution time is a MEDIAN over a stated sample
  size — one witness left open over a weekend drags a mean into fiction, and a median
  over a single sample is not a trend.
  Scope, stated exactly: this surface is READ-ONLY. Remediation is deliberately not
  reachable through it, because a corrective operation runs only through a plan
  verified inside the signer, and a REST route that could start one would be a way
  around that verification wearing the same URL prefix as a status page. Authorities
  are ranked worst-first; an authority that has never been collected from does not
  appear in the table at all, which is why `configured` is a field rather than
  something a reader is left to infer from an empty list.
  Relay migration parity (E1, OPEN — four migrated, three architecture exceptions,
  six unimplemented): the connector catalog and Connectors console publish the
  thirteen-family source-plan denominator, not the smaller list the current relay
  binary happens to execute. The exact families are a10, AWS ACM, Azure Key Vault,
  Cisco, Envoy, F5, FortiGate, GCP Certificate Manager, Kemp, MySQL, NetScaler,
  Palo Alto, and PostgreSQL; PostgreSQL and MySQL make the plan's formerly vague
  "+ DB/API variants" phrase executable. Every row carries a closed `disposition`:
  four are `migrated`, three are open `architecture_exception` rows, and six are
  `unimplemented`. The control plane REFUSES a migrated family's deploy
  when the tenant has a network relay enrolled. Before this, the A3 role stamp
  reserved an appliance deploy for a relay by writing `required_agent_role` on the
  outbox row and nothing enforced it: the outbox claim query has no predicate on
  that column — it is read by `ClaimAgentJobs` when an agent asks for work, never
  by the dispatcher — while the dispatcher swept every `connector.*` row on a
  one-second ticker. The stamp was correct in the column and decided nothing.
  The refusal is CONDITIONAL on a relay actually being enrolled, and that condition
  is the design rather than a hedge. Refusing unconditionally would turn "this
  estate has not deployed a relay yet" into "this estate's appliance deploys
  stopped working", and would retire the only path with end-to-end proof through
  the served API — the DoD connector suite drives a10, cisco, kemp and netscaler
  through the control plane to their device doubles and enrolls no relay. So what is
  promised is narrower and keepable: if you run a relay, the control plane will not
  do its work behind its back. An estate with no relay deploys exactly as it did
  before. A failed relay-presence lookup DEFERS rather than falling through, because
  falling through is the direction that silently removes the guarantee.
  Migrated today: a10, kemp, netscaler, f5 — device proof, rollback, readback, a
  published support row, a relay deploy proven byte-for-byte against the device
  double, and the refusal above. F5 closes the last gate it needed: an F5 HA pair
  keeps its certificate objects in separate stores, so a deploy that reached only
  the active node reported success while the standby served the old certificate
  until a failover surfaced it as expired. The relay now drives an `HAPair` over
  both peers when a peer endpoint is configured — a deploy must reach BOTH or it
  fails, a rollback re-binds both, and a readback reports the pair serving only
  when both peers are bound to the deployed certificate; the two-peer deploy is
  proven end-to-end through `relay.Execute` against two device doubles.
  Three open architecture exceptions retain control-plane execution for cisco,
  fortigate and paloalto: their management APIs
  import a certificate by name with no separately-addressable installed object to
  re-bind or query, so the rollback and readback gates are not expressible and
  migrating them would remove the control plane's proven fallback without the
  recovery path that justifies removing it. The parity surface and console now
  say this explicitly (`cp_retained` + a scope note) so "not migrated" cannot be
  read as completion; each family's support-matrix known limits state the same
  constraint. These rows KEEP E1 OPEN. Re-check on new PAN-OS / FortiOS /
  IOS-XE majors: a vendor API that grows an addressable installed object re-opens
  that family's migration through the same gates, not around them.
  Six accepted families have no network-relay migration: Envoy, PostgreSQL, and
  MySQL execute on co-resident host agents, while AWS ACM, Azure Key Vault, and GCP
  Certificate Manager execute in the control plane. None has a network-relay
  constructor, relay execution proof, and E1 refusal. Their `unimplemented` rows
  name those missing gates and current vantage instead of disappearing from the
  denominator. The executor census remains a separate fail-closed list: publishing
  an E1 row does not let an agent claim work it cannot construct.
  Device-generated CSR is reported as outstanding on the five families whose
  device APIs support it — a separate custody enhancement, not a migration gate:
  the current mode — the relay generates the key inside the segment and installs
  it — is correct as it stands, and holding families back to avoid an improvement
  was the worse trade.
  Served DR posture (J2): `GET /api/v1/platform/dr-posture` and
  `trstctl platform dr-posture` report when this deployment's backup was last
  VERIFIED — meaning its artifacts were re-hashed and matched — rather than when one
  was last taken. The distinction is the point: a nightly job that writes a corrupt
  file runs perfectly, and reading a manifest's recorded checksums back only proves
  the manifest agrees with itself, since one process wrote both in one pass. The
  failures this catches are silent — bit rot, a truncated copy, an artifact restored
  from the wrong directory — none of which change the manifest, and all of which are
  otherwise discovered during the restore that was supposed to save you.
  Three states are kept apart because only two are actionable: no backup directory
  configured (not a fault — many deployments back up through infrastructure this
  product does not see), a configured directory that cannot be read (a real finding,
  and the state that goes unnoticed until a restore), and one read that did not
  verify. A green verdict reports how many artifacts it covers and how many carried
  no recorded checksum at all, because "verified" over two of eleven artifacts is not
  the same claim as over all eleven. An artifact with no checksum is reported
  unverifiable rather than verified, and an EMPTY backup is never verified — green on
  an empty set is the most misleading answer available.
  Restore drills (J2): a drill restores the COMPLETE manifest into an isolated
  target through the same full-restore function production recovery uses. It creates
  and later drops a real ephemeral PostgreSQL database, starts a private file-backed
  JetStream beneath a temporary directory, copies the separately-custodied KEK and
  backup-decryption key into that directory, and redirects every restored signer,
  certificate, audit, socket, and archive path there. The production deployment is
  read only. A drill with its own simplified restore would prove the simplified one
  works, which is the one nobody runs at 3am; a drill aimed at live targets could
  cause the outage it is meant to rehearse.
  After event replay and both projection rebuilds, the drill imports and re-exports
  every `RecoveredFromPostgresBackup` table and compares exact table counts. It then
  starts the shipped signer over the recovered sealed key store, assembles a recovered
  control plane, and requires its real `/readyz` PostgreSQL, JetStream, and signer
  probes to pass. The attestation carries event count, independent-row/table counts,
  restored artifact names, and each health result. `restored` is impossible unless
  the full set and every runtime predicate pass; a missing required artifact or an
  event-only replay is `failed`.
  The attestation records FAILURES as readily as successes, because without one "no
  attestation" is ambiguous between "nobody ran a drill" and "the drill failed". A
  restore that completes having replayed ZERO events is recorded as a failed drill,
  not a fast one — it proved nothing and is the result most likely to be mistaken for
  reassurance. A backup that does not verify is not restored at all, so the cause
  reads as a sentence rather than being buried in a restore error.
  RPO is measured from the backup's own manifest, so it is what was achievable with
  the artifacts on disk rather than what was configured — the two diverge precisely
  when a backup job has been quietly failing. RTO is a FLOOR and the attestation says
  so in its own signed bytes: real recovery also includes provisioning, networking
  and people, and that caveat is signed alongside the number so it cannot be edited
  off a document whose signature still verifies. A deployment that has never drilled
  serves no drill rather than a zero-valued one, since zeros render as an instant,
  complete recovery.
  Each scheduled result now becomes a versioned
  `backup.restore_drill.recorded` event per live tenant. The deployment-wide
  attestation is signed through the isolated signer's purpose-constrained
  `audit-export` handle with the exact `restore-drill/v1` evidence domain; the
  signed body includes the complete attestation, recovery-objective thresholds,
  derived alert reason, signer key id, algorithm, and public JWKS. The projector
  verifies against the deployment-trusted key before
  writing an immutable `backup.restore_drill` evidence row, so changing an
  outcome, detail, limitation, metric, threshold, required alert, signer, or
  verification key is rejected.
  `last_drill` is derived from the newest durable row and `drill_history` exposes
  the newest 50 through the authenticated tenant API, generated SDKs,
  `trstctl platform dr-posture`, and the Platform console. A cold projection
  rebuild reproduces the history; it is no longer a process-memory pointer.
  The console shows signature status and signer identity and downloads the whole
  portable signed JSON evidence object.
  The drill RUNS: `RunRestoreDrillScheduler` is registered as a runtime worker and
  fires on `backup.drill_interval` (daily by default, `"0"` to disable, and an
  unparseable value fails startup rather than silently defaulting; the default is
  resolved at config-parse time so a zero reaching the scheduler can only mean the
  operator asked for none — an earlier cut applied the default in the scheduler too,
  which made the documented `"0"` run the drill daily instead of disabling it). It is worth
  recording that the first cut of this work did not have that. The drill, the
  attestation, the ephemeral target and the endpoint were all built and all tested,
  and nothing in the running binary ever called any of it — the fourth instance in
  this backlog of a capability that is complete, tested, documented and unreachable,
  after D2's VerifyAddress with no producer, B2's `endpoint.renew` with no enqueue,
  and B5's custody projection that was never written. Unit tests cannot catch it by
  construction: they are the caller that production lacks. Two tests now assert the
  wiring itself, and the DR panel on the Platform page reads the attestation the
  scheduler writes rather than a second source that could agree with nothing.
  A deployment that CANNOT drill — no external PostgreSQL to build a throwaway
  database in — records a skipped attestation saying so, rather than reporting that
  it has never drilled. Those are different facts, and the second is the one an
  operator would read as an oversight worth chasing.
  Failed and skipped outcomes create critical/warning alerts respectively.
  A successful restore whose measured backup age exceeds `backup.drill_rpo`
  (default 24 hours), whose isolated restore time exceeds `backup.drill_rto`
  (default one hour), or both, creates an objective-breach warning. The signed
  evidence row and its idempotent `notification.restore_drill` outbox intent are
  projected in one tenant transaction, so a crash cannot commit a red drill while
  silently dropping its alert. The scheduler logs structural/signing failures
  instead of discarding its returned error.
  Enrollment diagnostics (I4): refused ACME, EST, SCEP, and AD CS enrollments now
  produce a diagnosis naming the protocol, the step that failed, a cause from a
  CLOSED set, and a remediation. Each protocol emits at its shared refusal choke
  point, so a new refusal cannot silently bypass the recorder. AD CS keeps only an
  allow-listed stable HRESULT (`0x80094800` or `0x80094801`); its free-form upstream
  status is never retained because IIS or a proxy can echo submitted credentials.
  The design constraint is that it must DECLINE rather than guess. A tool that says
  "your DNS record is missing" when the responder was unreachable sends an operator
  to the zone file for an hour, and they will doubt it afterward on the occasions it
  was right. So the classifier matches only unambiguous evidence — RFC 8555 problem
  types, EST status codes, the two stable AD CS error phrases — and returns `unknown`
  for everything else, which is a first-class answer carrying NO remediation rather
  than a fallback. SCEP's `badRequest` is deliberately unclassified: it is the value
  a SCEP server returns for most refusals, so mapping it to any single cause would
  invent a diagnosis from a value that carries none. "Unreachable" is detected from
  typed network errors, never from error wording, so an error that merely mentions a
  connection is not reported as one failing. All three properties are
  mutation-verified.
  Diagnoses are served at `GET /api/v1/enrollment/diagnostics`, available as
  `trstctl enrollment diagnostics`, and shown on the Protocols console — where an
  unclassified failure renders "cause could not be established" rather than an empty
  remediation cell, because a blank reads as a rendering bug and the honest answer is
  a real one. Repeats collapse only when the stable diagnostic id names the same
  protocol, operation, identity, and endpoint. Two devices refused at the same step
  remain two rows; a retry storm for one exact operation remains one counted row.
  Each observation is a versioned immutable `enrollment.diagnostic.observed` event
  whose envelope carries the request tenant. PostgreSQL projects the exact refs into
  a FORCE-RLS table and retains the newest 200 operations per tenant. Version-1
  history replays under a deterministic `legacy:` id; version 2 carries the exact id
  and refs. Restart, snapshot restore, and full replay therefore reproduce both the
  refusal and its verification link instead of clearing a process-global map.

  `POST /api/v1/enrollment/diagnostics/{id}/prove-fixed` requires `certs:issue` and
  an `Idempotency-Key`. It appends an immutable queued receipt, then projects the
  link and writes one network-role `endpoint.verify` intent in the same PostgreSQL
  tenant transaction. If the event append wins but that transaction rolls back,
  startup reconciliation recreates the exact intent from the event. The intent
  contains one explicit deployment-target address and server name; it never
  guesses `SAN:443` and never treats the enrollment server as the workload endpoint.
  The operator must first retry enrollment successfully. A newer active certificate
  issued after the refusal supplies the expected fingerprint; without that evidence
  the action returns `409` and queues nothing. A real
  relay performs the TLS handshake; `verified` means the signed transcript reached
  that endpoint and matched the expected certificate. `diverged` and `unreachable`
  remain red, and a queued row never reads as success. The result is available
  through `GET /api/v1/endpoints/verifications/{id}`, its matching CLI command, and
  the Protocols console's signed-evidence link. While a row is queued, the console
  performs at most 30 bounded read-only refreshes and stops immediately when a
  terminal signed result appears.

  The ordinary offline support bundle remains tenant-data-free by default. An
  operator can explicitly add authorized, redacted aggregates with
  `trstctl support-bundle --include-enrollment-diagnostics` plus `TRSTCTL_URL` and
  `TRSTCTL_TOKEN`. The fetched shape can contain only protocol/cause/actionable/count
  aggregates and an unknown count; tenant ids, times, diagnostic ids, and exact
  operation/identity/endpoint refs cannot fit in its type. The fetch rejects
  redirects, bounds the body to 64 KiB, and never copies an upstream error body or
  bearer token into its error.
  Relay revocation cache (R3): a network-role relay started with
  `--revocation-cache-config` serves issuer-specific CRL and OCSP paths to relying
  parties in one named segment. The JSON file declares a bounded listener, the
  segment, and multiple issuers; each issuer points at a public certificate file and
  may declare a CRL GET path, an OCSP POST path, or both. The old
  `--crl-cache-listen` flags remain a single-issuer CRL compatibility path and now
  require `--revocation-cache-segment`. Revocation checking is the
  part of PKI that fails quietly — a client that cannot reach a distribution point
  usually proceeds rather than refusing — so a segment with no route silently stops
  checking, and nobody finds out until a compromised certificate is used.
  The relay SIGNS NO REVOCATION OBJECT: it holds the CA's signed bytes and hands them over, so a
  compromised relay can withhold a CRL (visible: the fetch fails) but cannot forge
  one (which would not be). It verifies a fetched CRL against the configured issuer
  before caching, which is not the relay adding trust — a relying party checks the
  signature regardless — but the relay declining to store what no client would
  accept, such as a captive portal's login page.
  The OCSP path accepts only bounded `application/ocsp-request` POST bodies. It
  proves that the request's issuer hashes match the configured issuer, forwards the
  exact request, and accepts a response only after the issuer/responder signature,
  requested serial, nonce equality, `thisUpdate`, and `nextUpdate` all validate.
  Nonce-free responses are cached in a 4,096-entry per-issuer bound; nonce-bearing
  responses are never reused because a nonce binds one response to one request.
  Expired entries are evicted first. The relay returns 503 with no OCSP response
  bytes when the upstream is unreachable or its answer is stale, malformed, for a
  different issuer/serial, or incorrectly signed.

  IT FAILS CLOSED ON STALENESS, and that is the property the feature exists for. A
  stale CRL is dangerous precisely BECAUSE it still verifies: nextUpdate has passed
  and the signature is good, so a relying party accepts it and trusts a certificate
  revoked yesterday. Past nextUpdate the relay serves 503 and no bytes — not the
  stale list with a warning header, because a client that receives bytes will use
  them. `--crl-cache-grace` can extend the window, defaults to zero, and is
  deliberately an operator decision: serving a list the CA declared expired is a risk
  only they can weigh. A CRL whose number went BACKWARD is refused, since replaying
  an older list is how a revoked certificate comes back to life. A failed refresh
  keeps a still-valid cached list rather than discarding it. Both fail-closed
  properties are mutation-verified. Before opening its steady-state channel, the
  relay signs a normalized metadata-only row per segment, issuer, and protocol with
  the same certificate key used by mTLS. The server verifies the certificate
  signature, tenant/agent binding, timestamp, network role, and monotonic order,
  then event-projects it. `GET /api/v1/revocation/caches` and Protocols → Revocation
  cache by segment show fresh, stale, empty, and error separately. Upstream URLs,
  issuer bytes, OCSP requests/responses, CRL bytes, and credentials never enter the
  heartbeat, event, API, or console. A missing report remains unobserved rather than
  green. The repository proves multiple issuers, signature-valid local CRL/OCSP
  clients, nonce policy, stale refusal, signed assembled-agent heartbeat, tenant
  isolation, replay, snapshot, and cold rebuild against controlled responders. A
  domain-joined Windows AD CS deployment using its real CDP/OCSP endpoints remains
  external lab evidence rather than a repository claim.
  Enrollment proxy for dark segments (A4): a network-role relay started with
  `--enroll-proxy-listen`, `--enroll-proxy-segment`,
  `--enroll-proxy-public-url`, and `--enroll-proxy-upstream` serves ACME, EST and
  SCEP on the LAN so hosts and devices with no route to the control plane can enroll
  through the one outbound pipe the relay already has. Stock clients (certbot,
  sscep, estclient) point at the stable public URL unmodified. The agent listener is
  HTTP; the public URL is HTTPS, so the segment's TLS-terminating load balancer
  terminates that public TLS connection before selecting a relay. Every redundant
  relay for one segment uses the SAME public URL. That detail is load-bearing for
  ACME: directory, account, order, authorization, challenge, finalize, and
  certificate resources are absolute URLs, and a different authority would send
  the stock client outside the relay path or strand it on the process that died.
  IT MAKES NO TRUST DECISION, and that is the design rather than a caveat. The relay
  sits inside the customer's network, which is where an attacker with a foothold
  already is, so a proxy that interpreted a challenge, cached an authorization, or
  spoke with its own agent identity would hand that attacker the ability to mint
  certificates. Requests are forwarded byte-identical — an ACME JWS is signed, so a
  proxy that reformatted it would invalidate every request — and the proxy attaches
  NO credential of its own: the client authenticates as itself through EST's TLS
  client certificate, SCEP's challenge password or ACME's account key, exactly as it
  would reaching the control plane directly. Both properties are mutation-verified.
  The control plane independently requires every ordinary ACME outer JWS protected
  `url` to equal that stable public request URL byte-for-byte before consuming its
  nonce. Missing URL, path, authority, and scheme differences fail unauthorized;
  the assembled two-process relay journey proves the relay preserves the same URL a
  stock client signed through failover.
  The forwarded paths are an allowlist, not a catch-all: a segment able to reach
  /api/v1 through a relay would hold the control plane's entire administrative
  surface, which is a far larger grant than "devices here can enroll".
  Two kinds of failover stay separate. Several `--enroll-proxy-upstream` values let
  ONE relay choose another control-plane endpoint after a transport failure. Several
  relay processes behind the SAME public URL let the segment frontend select a
  secondary relay after the primary process dies. Both work because the proxy is
  stateless — an ACME order lives in the control plane, not in a relay — so the
  client retries through another path and its order is still there. A 5xx FROM the
  control plane is NOT a failover trigger: it is an answer, and retrying elsewhere
  would ask a second endpoint the same question while hiding the real error.
  Every heartbeat preserves the relay's segment, public URL, verified,
  unavailable, and not-yet-verified upstream counts,
  forwarded/refused/failure counters, and last-forward/last-upstream-failover times
  in the immutable event stream. The authenticated agents API and Protocols console
  group those certificate-bound rows by segment AND public URL. That lets an
  operator distinguish no report, proxy off, no verified upstream, degraded
  upstreams, one relay, and actual relay redundancy. Counters reset when the relay
  process restarts; the projected timestamps remain durable evidence of the last
  observed activity.
  Third-party connectors in the relay (E4): a relay started with
  `--connector-plugin-dir` executes signature-verified WASM connectors inside the
  customer's network, under a capability grant its own operator sets. The control
  plane never loads partner code. Every guarantee is re-proven in the new location
  rather than assumed to have traveled with the code: an unsigned, tampered, or
  untrusted-key module is refused AT LOAD and fails the whole runtime rather than
  being skipped — a relay serving a subset of its configured connectors would be
  missing precisely the one somebody tampered with. An out-of-grant operation is
  denied at runtime and FAILS the deploy, so a module reaching outside its grant
  cannot report success. Both properties are mutation-verified.
  Everything is operator-owned: the modules, the publisher keys, the pinned build
  digests and the capability grant. None is read from the module or pushed from the
  control plane, because a publisher who could widen their own grant by editing a
  file they ship would make the sandbox a formality. A directory with no trust keys
  is refused, and an unset grant is refused rather than defaulted — a grant nobody
  set and a grant that permits nothing are indistinguishable at that point, so the
  reading that cannot surprise anyone is the one that refuses.
  AUD-34 adds a signed, metadata-only census to that boundary. The census comes
  from the exact verifier-and-loader that instantiated the module; it names the
  stable plugin name, verified module and publisher fingerprints, the fixed
  `network_relay_wasm` execution context, and the effective grants plus normalized
  constraints. The relay signs the tenant ID, its certificate common name, that
  normalized list, and the issued-at time with the same key used by its mTLS
  certificate. The server rebuilds both identities from the authenticated
  certificate, verifies the signature, and refuses a tampered, stale, or
  cross-tenant report. A host-role certificate cannot report relay plugins.
  Accepted reports enter the immutable event stream and rebuild the newest
  tenant-isolated projection after restart. The connector catalog API and the
  Connectors console show each reporting relay separately. A signed empty census
  means “this relay loaded no third-party modules”; no report means an older agent
  cannot make the claim. The report contains no module bytes, publisher keys,
  credentials, or secrets. The control plane still does not distribute modules or
  operator trust keys. Third-party connectors also never receive redeemed
  credential material; a module that could read an appliance password would make
  the sandbox decorative.
  Live appliance readback (E2): after every appliance mutation the relay now asks
  the device what it actually has, alongside D2's TLS handshake against the served
  listener. The two are not redundant and only together locate a fault: a handshake
  showing the old certificate with a readback showing ours-and-bound means the VIP
  is fronted by something else; with a readback showing theirs it means the binding
  never moved (the deploy patched the wrong profile); with a readback showing
  nothing it means the deploy did not take. A handshake failure alone reads as "the
  deploy failed", and the most common cause is the middle case — a binding the
  deploy never touched, on a device that reported success at every step. A readback
  that contradicts a passing handshake DOWNGRADES the outcome to verify_failed,
  because a handshake can pass against a second listener while the object this
  deploy installed is not the one bound. Verdicts are a closed set: serving,
  installed_not_bound, diverged, absent, unknown — and `unknown` (the device named
  an object but not which certificate it is) is NOT a pass. Readback is available
  only where the API can address an installed object separately from uploading one:
  f5, kemp, netscaler, a10. cisco, fortigate and paloalto cannot be asked, which is
  reported as no readback rather than as a clean one.
  Capability disclosures (K3): the connector support matrix and the per-issuer
  capability matrix are both generated by one tool from the censuses the API serves,
  with a Go test failing on drift in either. The issuer matrix gained an
  `issue_proven` column that is deliberately SEPARATE from `issue`, because
  "we implement this authority's API" and "we have run an issuance against it" are
  different claims and a table showing only the first states the stronger one
  everywhere. All thirteen advertised authorities now have high-fidelity protocol
  issuance proof in `TestDODExternalCAUniversalProductionAssembly`: each driver is
  constructed by the production server assembly, talks to its own nonce-bound
  authority-protocol substrate in the expected wire order, and returns a chain that
  is independently verified. That proves the adapter and custody path. It is **not live
  vendor-account certification** and does not prove a customer's policy,
  entitlement, network, appliance, or service version; operators must still run one
  scoped issuance against their configured account before depending on it. The
  revoke and unattended-DV columns remain separately census-checked against the
  implementations. Every row names the tests backing it, and a manifest-derived
  guard fails both when a row outruns its proof and when new executable proof remains
  incorrectly labeled "not tested."
  Support matrix (E3): docs/features/connector-support-matrix.md is GENERATED from
  the same census the API serves, and a Go test fails if the two diverge — so a
  capability cannot be removed while its published row survives. It deliberately
  publishes no firmware compatibility range: nothing in this repository runs against
  a physical or vendor-hosted device, so a version claim would be unbacked, and it
  is precisely the line an operator would plan a migration around. What it publishes
  instead is the API or local execution contract each connector speaks, the
  operations exercised by repository tests, and the family's known limits. The
  seven appliance rows distinguish faithful management-API doubles from the six
  rows that have only ordinary connector tests. A guard fails if a version claim
  appears, and all thirteen rows explicitly say no external target was tested.
  Rollback, restated honestly after that work: cisco, fortigate and paloalto CANNOT
  re-bind, and it is a property of their APIs rather than an unfinished feature.
  Each exposes a single call that both uploads and installs the credential, with no
  way to address an already-installed object, so the only available "rollback" would
  be re-uploading the predecessor key — which the control plane no longer holds after
  B1. They are correctly absent from the rollback census and their tests pin that
  absence in both directions.
  `buildRunDeps` constructs the operator-selected production registry; strict
  target schemas bind endpoint/filesystem/process and same-tenant secret
  references before a served issue/deploy route can enqueue work.
  Credential-bearing `connector.deploy` payloads exist only while needed, travel
  through the durable outbox, and are wiped after delivery. The acceptance proof requires
  provider-specific mutation plus independent external readback before a connector
  counts as served. Inventory: nginx, Apache, Caddy, Envoy, IIS, HAProxy, F5,
  NetScaler, A10, Kemp, Cisco, FortiGate, Palo Alto, Postfix, Traefik, AWS ACM,
  Azure Key Vault, GCP Certificate Manager, Java keystore, PostgreSQL, MySQL,
  RabbitMQ, Elasticsearch, and Tomcat.
- Discovery control plane + relay-owned network/SSH, cloud-certificate, CT-log,
  and drift execution: the running binary serves discovery sources,
  schedules, and runs under `/api/v1/discovery/*` — create/list a source,
  create/list a schedule, queue a run (idempotent, deduplicated by
  `Idempotency-Key`), read runs and findings (keyset-paginated), and read
  `GET /api/v1/discovery/monitoring` for the centralized continuous-monitoring view
  across sources, schedules, last runs, findings, and inventory counts.
  `GET /api/v1/certificates/health` and `trstctl certificates health` serve the
  estate-wide expiry/source dashboard over the same inventory projection,
  including certificates issued elsewhere and later imported or discovered.
  Queuing a run is an immutable `discovery.run.queued` event. For **network** and
  **SSH** sources the same transaction resolves the bounded target list and stamps
  the declared segment, required `network` role, and optional exact relay ID into
  both the event and outbox command. The control-plane dispatcher refuses to dial
  those targets and leaves the row claimable. An enrolled relay executes the sweep
  on its bounded worker lane, signs the result receipt, and the control plane
  validates the command/report binding before projecting metadata-only findings,
  counts, segment freshness, and the executing agent ID. For a
  **cloud_certificate** source the worker executes AWS ACM, Azure Key Vault, and
  GCP Certificate Manager enumeration through credential references — served
  cloud-certificate discovery execution. For a **ct_log** source the worker polls
  configured RFC 6962 log fixtures or public logs, checkpoints each log, and
  records unexpected issuance as `ct_unexpected_issuance` findings — this is
  served through the served discovery worker, queuing notification alerts the
  same way expiry alerts do. CT monitoring is a **headline capability on the
  Discovery workspace**, not a footnote: one surface carries the watched-domain
  and log watchlist, per-log checkpoint/health state (so you can see whether a log
  succeeded, failed, or has never been reached), retired audit history that is no
  longer polled, unexpected-issuance findings
  with certificate detail, and a one-click hand-off to the rogue-certificate
  remediation path. It previously appeared there only as a single count shared
  with drift detection, so the capability was effectively unfindable. It covers
  **only the domains and logs configured** — a domain you have not listed, or a
  log you do not poll, produces no finding, and the surface says so beside the
  counts so an empty list is not read as an all-clear. Replacing a named watchlist
  retires URLs absent from the new source configuration in the source event's same
  tenant transaction; one failed active log does not discard a peer's successful
  checkpoint or finding. The console polls queued/running CT runs to completion,
  refreshes per-log checkpoints in place, follows the parent Discovery refresh, and
  shows a bounded credential-redacted diagnostic for a failed discovery run. It also
  only sees what a
  CA chose to log, which in practice means public issuance.
  For a **drift** source the worker compares configured
  credential paths against expected fingerprints/permissions and records
  `credential_drift` findings through the same served discovery worker. For an
  **ssh** source the worker runs a non-invasive SSH host-key scan through the
  discovery outbox worker, applying the same reserved-address guard as network
  scans, recording metadata-only `ssh_key` findings (fingerprint/key-type/
  location) and never authenticating or storing private key material. A
  **manual** source records its supplied findings.
- CBOM scan and migration inventory: `POST /api/v1/cbom/scans` runs the
  cryptographic bill of materials scanner against TLS endpoints and host config
  files, records `cbom.asset.observed` events, and projects tenant-scoped
  `crypto_assets`. `GET /api/v1/cbom/assets` returns the inventory plus
  migration targets and `migration_progress`. With PQC in the core, the targets are the concrete FIPS 203/204/205 algorithms and
  `migration_progress` counts which assets are already post-quantum-ready.
- Credential-compromise incident execution is part of Core: the old `POST /api/v1/incidents/executions` single-identity
  mutation refuses with conflict and points to the H2 fleet route; it cannot prove
  exact trust scope, trust-before-leaf ordering, or signed live health before
  revocation. Historical evidence remains readable via
  `GET /api/v1/incidents/executions{,/{id}}`. Automated remediation playbooks are
  also served without a commercial license: `GET /api/v1/remediation/playbooks`,
  `POST /api/v1/remediation/playbooks/{id}/runs`, and
  `GET /api/v1/remediation/playbook-runs{,/{id}}` cover revoke, rotate, and NHI
  right-size. Owner-driven self-remediation is served through
  `GET /api/v1/remediation/owner-actions` and
  `POST /api/v1/remediation/owner-actions/{id}/accept`: a bound owner can accept the
  CAP-POST-01 least-privilege recommendation, and trstctl records the same
  `remediation.playbook_run.recorded` evidence plus a `connector.right_size` outbox
  intent. When the operator configures the matching tenant/connector binding, the
  shipped dispatcher authenticates to the entitlement service with a tenant-secret
  reference, sends the stable outbox idempotency key, applies the requested scope
  removal, reads the effective scopes back independently, and advances the queued
  connector receipt to delivered or failed. An absent binding and every unknown
  `connector.*` outbox kind fail closed. The rule is simple: a queued receipt is not
  external-effect evidence. Only the verified delivered receipt is.
  SIEM/SOAR/chat/ITSM response dispatch is served through
  `POST /api/v1/incidents/response-integrations/dispatch`, which records
  `response.integration.dispatched` and queues Splunk HEC, Jira issue, configured Slack
  notification, and ServiceNow Table API outbox rows in the same event-backed workflow.
  The served boundary is dispatch plus evidence: Splunk correlation searches, Jira
  automation rules, Slack app/channel installation, arbitrary third-party SOAR
  playbook execution, and bidirectional ServiceNow ticket-status sync remain
  customer/operator configuration outside trstctl. Fleet-wide re-issuance is served
  separately at `POST /api/v1/incidents/fleet-reissuance-runs`: it freezes exact
  certificate/SPKI H1 trust consumers and ordered H2 member bindings before work,
  installs replacement trust before host-CSR issuance, waits for lease-bound signed
  trust/live receipts, revokes each exact predecessor only after verification, and
  seals terminal success/rollback as a compact JWS. The separately authorized
  `game_day` mode structurally refuses production owner/target environments. It has
  pause/resume/current-cohort rollback and evidence export routes under
  `/api/v1/incidents/fleet-reissuance-runs/{id}`, matching
  `trstctl incidents fleet-reissuance *` CLI commands, and the `/incidents` console.
  Online break-glass at `POST /api/v1/breakglass/issue` is conditionally served when
  `breakglass.online_enabled=true`: production `buildRunDeps` binds the configured CA
  and public key to one persisted, purpose-constrained dual-control signer handle.
  The caller first opens an exact-request-bound ceremony, and distinct approvers use
  their own authenticated tokens at `/api/v1/ca/ceremonies/{id}/approvals`; the issue
  request carries no approver names. Only authenticated immutable
  `ca.ceremony.approved` event actors in the configured roster count toward quorum,
  and the ceremony is consumed once with `breakglass.issued`. Break-glass recovery
  reconciliation remains served at `POST /api/v1/breakglass/reconcile`, where signed
  offline bundles are verified and recorded as `breakglass.issued` audit events.
- Real X.509 issuance: transitioning an identity to *issued* mints a leaf
  certificate from the assembled CA (its key held in the out-of-process signer) and
  records it in inventory. Exercised end to end in CI.
- Attested X.509-SVID issuance: workload owners with `certs:issue` can self-serve
  attester trust sources at `/api/v1/workloads/attester-trust-sources` (create,
  list, get, replace, rotate, revoke, delete) before calling
  `POST /api/v1/workloads/attested-issuance`. The route verifies a workload proof
  (`aws_iid`, `azure_imds`, `gcp_iit`, `github_oidc`, `k8s_sat`, or `tpm`) against
  tenant trust material or configured process defaults, signs a short-lived
  X.509-SVID in the isolated signer, records `certificate.recorded`, binds
  `attestation.bound`, and returns the certificate plus verified subject metadata.
  Mutations require `Idempotency-Key`, reads and issue are tenant-scoped, forged
  proofs fail closed, and offboarded trust sources mint nothing.
- Authentication and RBAC via scoped API tokens (`Authorization: Bearer`),
  multi-tenancy with PostgreSQL row-level security, and a tamper-evident audit
  chain. A fresh boot fails closed (every route `401`s until a credential exists);
  mint the first tenant-scoped token with `trstctl token create --tenant <uuid>`
  (writes through the store, prints the token once). OIDC, SAML, and LDAP / Active
  Directory login are served by the binary when their respective `auth.*.enabled`
  flags are set — see "Single sign-on" below — under the same RBAC and per-tenant
  scoping as an API token, with each user mapped to its real tenant. API-token
  auth remains the default when SSO is disabled. OIDC stays core; tenant SAML
  and LDAP require Enterprise SSO, inherited by Provider.
- SCIM 2.0 provisioning requires Enterprise SSO and `auth.scim.enabled` — see
  "SCIM 2.0 provisioning" below for the route and event detail.
- Transport security (TLS), idempotency and the outbox, observability
  (`/metrics`, `/readyz`, W3C trace headers), bulkheads plus per-tenant rate
  limiting, backup/restore plus disaster recovery, and safe schema migrations.
- Protocol parity hardening: served ACME supports the explicit
  ACME trust_authenticated profile mode for authenticated internal issuance, plus
  account-keyed order/hour and concurrent-order limits. Served EST includes
  `/serverkeygen`, RFC 9266 `tls-server-end-point` binding, profile PathID dispatch,
  and an mTLS sibling route when configured. Served SCEP includes the
  SCEP Intune challenge gate with tenant/CSR binding, single-use replay rejection,
  per-profile RA material, and per-device rate limiting. The MDM SCEP control
  surface serves `/api/v1/mdm/scep/status`, policy CRUD, challenge-rotation
  evidence, CLI commands, and Protocols UI telemetry; live SCEP validator trust
  anchors are still supplied by `protocols.scep.intune_challenge` configuration
  rather than hot-swapped from policy CRUD.
- Revocation hardening: RFC 5280 named revocation reasons, bulk revoke routes,
  delegated OCSP responders, OCSP nonce echo, nonce-free OCSP response caching,
  and CRL ETag / `If-None-Match` caching. CT precertificate/final-certificate
  submission is served through `POST /api/v1/revocation/ct-submissions` and the
  `ct.submit` outbox worker.
- NHI decommissioning: `POST /api/v1/nhi/decommission` and
  `trstctl-cli nhi decommission` resolve departure, vendor-term, and inactivity
  signals to tenant-local managed NHIs, then drive event-sourced lifecycle
  revoke/retire transitions with per-item evidence.
- NHI posture — metadata-only, drawn from the unified NHI inventory; every route
  below returns recommendations, not automatic action, and each has a matching
  `trstctl-cli nhi posture <name>` command:
  - Shadow (`GET /api/v1/nhi/posture/shadow`): unmanaged, unregistered, and
    ownerless external NHIs from discovery findings; the Discovery findings table
    lets an operator claim a finding and run rotate/revoke/decommission/
    remediation against the prefilled identity.
  - Over-privilege (`GET /api/v1/nhi/posture/overprivilege`): granted
    scopes/permissions/roles compared with observed usage; rows without usage
    evidence are not classified as excessive scope.
  - Stale (`GET /api/v1/nhi/posture/stale`): stale/dormant activity, unused
    credentials, and orphaned records; finding-backed rows hand off to
    revocation/decommission/remediation, but owner reassignment stays an
    operator workflow.
  - Static credentials (`GET /api/v1/nhi/posture/static-credentials`):
    long-lived credentials, static lifecycle markers, no-expiry credentials,
    and overdue rotation age; managed rows can start the served
    rotate/revoke/remediation workflow prefilled.
  - Exposure (`GET /api/v1/nhi/posture/exposure`): internet-exposed NHIs, public
    endpoints/callbacks, plaintext transport, weak authentication, missing
    network policy, wildcard reachability, and insecure-deployment markers; URL
    query strings are sanitized and no credential values are returned. Live
    reachability probing and provider-native attack-path validation remain
    deeper connector work.
- Rogue and non-compliant certificate posture:
  `GET /api/v1/revocation/rogue-certificates` and
  `trstctl-cli revocation rogue-certificates` combine unexpected CT findings with
  active certificate inventory policy checks (weak keys, expired active state,
  over-long public-TLS lifetimes, missing owners/issuers) — metadata-only,
  returning projection evidence refs rather than PEM or key material. CT coverage
  depends on configured monitored domains/logs; provider-native revocation,
  connector-side takedown, and arbitrary customer policy evaluation remain
  separate remediation work.
- Compliance and inventory reporting: `GET /api/v1/compliance/inventory-report`
  and `trstctl-cli compliance inventory-report` return the CAP-OBS-02 reporting
  view (frameworks, report types, routes, evidence refs, inventory counts, tenant
  schedules). `GET /api/v1/compliance/evidence-packs/{framework}` and
  `trstctl-cli compliance evidence-pack` serve signed CAP-CMP-04 framework packs
  for eIDAS, NIST SP 800-53/CSF, CMMC 2.0, FedRAMP, NIS2, and the existing
  PCI/HIPAA/CNSA/FIPS/Common Criteria/CA-audit frameworks. The `soc2` pack serves
  CAP-CMP-05 only when each CC6/CC7/CC8 prerequisite has exact tenant-scoped
  event/object evidence in the signed 90-day window; absent, stale, malformed, or
  wrong-tenant prerequisites are explicit gaps. The signed v2 manifest includes
  the tenant, window, event IDs/sequences/audit-chain digests, object refs, and
  missing prerequisites. CPA examination and trust-services scope remain
  residuals, and signature validity is not certification. `GET
  /api/v1/compliance/nhi-report` and `trstctl-cli compliance nhi-report` return
  CAP-CMP-06 NHI compliance mappings for NIST SP 800-53, NIST CSF 2.0, PCI DSS
  4.0, DORA, ISO/IEC 27001:2022 Annex A, FedRAMP, CMMC 2.0, eIDAS, and NIS2. These
  are evidence mappings, not legal certification — operator scope, policy,
  authorization packages, qualified status, national transposition duties, and
  auditor sampling remain explicit residual attestations. `POST
  /api/v1/compliance/report-schedules` and `trstctl-cli compliance
  report-schedules create` record idempotent, event-sourced audit-export
  schedule definitions; `GET /api/v1/compliance/report-schedules` and
  `trstctl-cli compliance report-schedules list` read them back. Delivery is
  `audit_export` only; email/webhook/ticket dispatch is not served or implied.
- Audit chain anchoring (J1): `GET /api/v1/audit/export?format=` serves the signed
  JWS bundle (default) plus NDJSON, CSV, Splunk HEC and Microsoft Sentinel record
  streams. The JWS response and browser download are one versioned JSON envelope
  containing the compact JWS, chain head, and complete anchor. NDJSON, Splunk HEC,
  and Sentinel end with a JSON `chain_trailer`; CSV adds the compatible
  `trstctl_record` and `integrity` columns and ends with an RFC-safe trailer row.
  Every saved form therefore retains the record count, archived-prefix predecessor
  hash, chain head, and complete anchor without depending on HTTP headers. When
  operators need continuous delivery rather than a download, tenant-scoped
  `GET|PUT /api/v1/audit/feeds[/{id}]` schedules bounded Splunk HEC or Sentinel
  batches through the durable outbox. It persists exact record lag, cursor,
  retries, safe terminal error codes, and collector request IDs; it does not store
  credential values or remote response bodies. This native feed is separate from
  the metadata-only OTLP log exporter and from incident-response SIEM dispatch.
  When
  `protocols.tsa` is enabled the chain
  head is countersigned with an RFC 3161 timestamp over a domain-separated
  imprint; the artifact carries the timestamp info, signature, TSA certificate,
  and CMS DER token. The shipped `trstctl-cli audit verify` command checks all
  five saved formats offline. An auditor first downloads the public-only JWK set
  through authenticated `GET /api/v1/audit/verification-keys`. The command
  `trstctl-cli audit verification-keys` downloads it for separate `--audit-jwks`
  pinning. The TSA issuer
  root is separately pinned and supplied as PEM or DER with `--tsa-root`; the
  verifier never promotes the TSA leaf embedded in evidence into a root. It
  reconstructs the archived-prefix-aware chain, verifies the domain-separated
  RFC 3161 imprint, and can enforce a maximum anchor delay with
  `--max-anchor-delay`. This independently pinned trust is what makes a
  BACK-DATED head detectable: a chain rebuilt to
  remove a record hashes differently, so no earlier token exists for it, and a
  freshly-taken token is dated long after the events the bundle describes.
  Scope, stated exactly: an anchor proves the head is no NEWER than the timestamp.
  It does NOT prove the chain was complete when anchored — a record withheld
  before anchoring was never in the chain — and detecting that needs continuous
  anchoring at a known cadence, which is not served. A deployment without a TSA
  exports successfully and says in the payload that it is unanchored; that is a
  weaker claim, not an invalid one, and the export states which it is. The CLI
  verifies a plain signed JWS using separately pinned `--audit-jwks`, reporting
  `audit_signature_verified: true` and `anchor_verified: false`. It checks the
  signed slice's tenant, count, archived-prefix chain and head, without claiming
  an independent time or complete tenant history. `--require-anchor`, a supplied
  TSA root, or a positive maximum anchor delay refuses unanchored evidence.
  Timestamp failures never fall back to plain verification, and unsigned record
  streams still require TSA trust. Translog
  inclusion proofs (`internal/translog`) are not wired into this path.
- Signed invoice evidence (L2): `GET /api/v1/provider/usage-evidence` (`trstctl
  usage evidence`, Platform console panel) serves a per-customer, per-period
  document that states its own completeness and carries THREE attestation
  layers, each of which can refuse: coverage (the durable metering store must
  vouch for the whole closed period), reconciliation (the certificates_issued
  meter is recounted from the identity_transitions projection of the event log,
  and a divergence names BOTH numbers and blocks signing — a counter that
  disagrees with the log must not be invoiced from), and the detached RS256
  signature over the canonical bytes, made with the SAME audit-export key every
  other auditor-facing export uses. An unsignable document still returns 200
  with its reason — "your usage is incomplete and here is how" is actionable
  where an error is not — and NEVER carries a signature; the absence is the
  point. `?format=csv` exports the table with the verdict and digest on EVERY
  ROW, because a spreadsheet slice detaches headers, and the JWS stays in the
  JSON document where a verifier can use it. Per-customer quotas are durable
  (`provider_tenant_quotas`), administered only through the provider plane
  behind the per-customer delegation gate (`PUT/GET
  /provider/v1/tenants/{id}/quota`), counted against the live read model, and
  ENFORCED at the served issuance transition with a structured 429 before the
  orchestrator accepts anything. Scope, stated exactly: only
  certificates_issued has an independent event source today — other meters say
  in the document that the metered value stands alone; only the
  certificates_stored cap is enforced at a served create path (agents, tenants
  and secrets caps are stored and reported but no create site consults them
  yet). The tenant-self-service route still serves only the caller's own
  tenancy and refuses a foreign `customer_id`. Provider staff use authenticated
  `GET /provider/v1/tenants/{id}/usage-evidence` instead: the handler requires
  that exact customer's `read` delegation before billing opens the customer's
  forced-RLS transaction, then returns the same signed JSON document or
  `?format=csv` finance CSV. `GET
  /provider/v1/evidence/verification-keys` supplies the separately fetched
  public-only JWK set; the Provider console reconstructs the exact displayed
  canonical bytes and shows **Signature verified** only after checking the
  RS256 signature, protected billing-invoice domain, key id, and digest. An
  undelegated customer or wrong-operation grant is refused before metering is
  touched. Reconciliation compares against the
  transitions projection, so a rebuild-in-progress can transiently refuse to
  sign — the refusal names the numbers, which is the correct behavior while
  the projection catches up.
- notification routing matrix and inbox: expiry, CT, drift, and workflow alerts
  resolve through the configured severity-to-channel matrix, dedup by
  per-subject/threshold/channel, and are inspectable through the served
  notification inbox with owner/approver escalation fields and dead-letter requeue.
- MCP-vs-REST parity guard: the served MCP automation surface includes broad
  route-backed REST tools in addition to the named investigation tools, and CI
  fails when a served REST route is missing both an MCP mapping and an explicit
  allowlist.
- Cert-ops console parity: issuer catalog and Test connection, operations queue,
  Alerts and delivery, richer certificate filters, dashboard charts, CTA empty
  states, onboarding carousel, and server-side command-palette search are in the
  served console.

The `trstctl-cli` drives this same served surface, including OIDC/SAML/LDAP
browser login, the React web console, and the AI/RCA/MCP surface covered in
their own sections below.

### Tenant offboarding boundary

Tenant offboarding erases **PostgreSQL read state** for the target tenant: it
deletes every tenant-scoped table under that tenant's row-level-isolation
context, verifies zero residue, and returns a deletion attestation. The
`tenant.offboarded` event is replayed by projections, so a read-model rebuild
does not resurrect the tenant's PostgreSQL rows.

That is the limit of what tenant offboarding deletes — it is not a promise that
the append-only event log or a signed audit archive disappears when a tenant is
offboarded. Those records are governed by audit/privacy retention policy:
configure `TRSTCTL_AUDIT_RETENTION` plus `TRSTCTL_AUDIT_ARCHIVE_DIR` for
archive-backed retirement from the served audit view, and use **Privacy Retention**
for non-audit personal data pseudonymization. The underlying AN-2 event envelopes
stay retained for rebuild and disaster recovery. WORM/object-store archive cleanup and legal
hold decisions remain operator privacy/compliance work, but the product gives
that work a queryable evidence ledger: record deletion, legal-hold exemption, or
cryptographic shredding with `POST /api/v1/privacy/archive-erasure-attestations`,
inspect it with `GET /api/v1/privacy/archive-erasure-attestations`, or use
`trstctl privacy archives attest/list`. The attestation stores `subject_ref` and
redacted evidence refs rather than the raw subject.

## Built and tested, but not yet served by the binary

No current feature-map row is in this bucket. The empty section is deliberate:
future library code that is built and tested but not yet wired into the served
API must be listed here as library-only until its required wiring-census proof
passes — Phase 2 residual breadth stays under Partial or Roadmap instead of
being quietly promoted.

## Conditional, partial, and residual boundaries

These notes explain the matrix's conditional and partial rows: some are served
only when an operator enables or configures a backend, and some have a served
spine with explicit residual work. The matrix above is the authority for whether
the running binary serves a capability; this section records the operator-facing
edges and follow-up integration work.

### The CA calendar: year-scale hierarchy expiry

Leaf expiry alerting runs on 7/30/90-day windows. That is the right clock for a
leaf and useless for a certificate authority: replacing a trust anchor means
getting the new one into every relying party first, which is a quarters-long
program, so a 90-day warning arrives long after it could have helped. Nothing
evaluated `ca_authorities.not_after` at all before this, and the CA console
printed the raw date and called anything past 90 days healthy.

CA authorities now run on their own clock. The leader lifecycle sweep walks every
active authority against year-scale bands — **36, 24, 12, 6 and 3 months** — and
alerts once per band an authority crosses into, with severity scaled to runway:
a planning signal beyond a year, a warning inside one, critical inside three
months or already expired. The band already notified is recorded on the authority
and only ever tightens, so a repeated sweep is silent, each tightening re-fires,
and a clock skew cannot replay an alert the operator already saw.

The second check is the one that hides. A CA cannot issue a leaf that outlives
it, so once an authority has less life left than the validity its leaves are
issued with, every new leaf is silently truncated to the parent's expiry.
Issuance keeps succeeding; certificate lifetimes become shorter until something
downstream rejects one. That case raises `ca.validity_compression` rather than a
plain horizon alert, because the fix is different: renew or re-key the authority.

Exact contract. Alerts land on the `notification.ca_horizon` outbox destination
as `ca.horizon` or `ca.validity_compression`, carrying the authority, its band,
how many active certificates chain to it, and the renew-by date; they fan out
through the same operator-configured channels as expiry alerts. The alert intent
and the band stamp commit in one transaction. The reference leaf validity is
`lifecycle.leaf_validity` (`TRSTCTL_LIFECYCLE_LEAF_VALIDITY`, default `2160h` /
90 days) — a yardstick for horizon reporting that caps nothing.
`GET /api/v1/ca/authorities` carries a `horizon` object per authority, and the CA
Hierarchy console shows the band, the renew/re-key-by date, and the truncation
warning. `GET /api/v1/certificates/health` resolves beyond 90 days into 180-day,
1-year, 2-year and 3-year bands; `later` now means beyond three years.

What is **not** served: an authority with no recorded `not_after` raises nothing
and is shown as "no recorded expiry" rather than healthy — an unknown expiry is a
real state, not a passing one. Authorities beyond 36 months raise nothing. The
compression check is forward-looking (it says new leaves are being truncated); it
does not retrospectively scan already-issued leaves to report which ones were
shortened. Nothing here schedules or performs the renewal — it tells you when to
start, and the re-key and rotation routes remain the operator's action.

### Agent roles: a vantage in the certificate

An agent runs in one of two places, and where it runs decides what it can be asked
to do. On a host, it acts on the machine it lives on. In a network segment, it
acts for things that cannot run an agent at all — load balancers, appliances,
cloud certificate stores — and probes endpoints the way a client would. The second
kind holds the credentials that drive those devices, which is exactly why it is a
grant and not a startup flag.

An operator picks the roles when they mint the enrollment token. The grant is
recorded with the token, and at redemption the **CA** stamps it into the issued
certificate as an additional SPIFFE URI SAN
(`spiffe://trstctl.example/tenant/<id>/agent/<cn>/role/<role>`). It is never read
from the CSR: an agent that could put a role in its own certificate request would
be choosing its own capability, and the whole control is that it cannot. A CSR
that tries gets a certificate carrying only what the operator granted.

At claim time the served channel reads the roles off the certificate the agent
authenticated with — the same certificate the tenant is derived from — and
intersects them with the vantage each job kind needs. `trust.distribute` acts on
the agent's own machine and is host work. `discovery.run`, `endpoint.verify`, and
`revocation.probe` are observations from a segment vantage and are relay work. A
host agent reaching for relay work is handed nothing and the reach is recorded as
`agent.jobs.role_refused`, because it is either a misconfiguration or the thing
the gate exists to catch.

Granting the network role additionally requires the `agents:relay.grant`
permission, separately from `agents:write`. Enrolling a host agent is routine
fleet work; placing a relay puts appliance credentials on a machine of the
operator's choosing, and those are different decisions.

The agent binary itself is now held to the boundary the roles imply: a CI guard
(`docs/agent_binary_import_boundary_test.go`) fails the build if `trstctl-agent`
links the database driver, the store, the event spine, or any served
control-plane package — before the guard existed, two dead store-backed sinks
had already pulled all of those into the binary. A companion guard pins the
connector core (`internal/connector/...`) to a host-neutral dependency set, which
is what will let the same connector implementations execute on a relay.

An agent enrolled before roles existed carries no role SAN, and is read as
**host-only** rather than as capability-less. That is what those agents already
were, and reading them any other way would strand a live fleet mid-upgrade. A
renewal carries the roles across unchanged — it cannot gain a capability, and it
cannot silently lose one either. Changing an agent's role is a re-enrollment,
because the role lives in a signed SAN.

**Per-row locality is now gated at the kind the roles share.** `connector.deploy`
and `connector.rollback` remain both roles' work at the kind level, and the row
decides: at enqueue, the control plane reads the connector name out of the raw
payload — the one moment it is not yet sealed — consults the shipped vantage
census (`nativeConnectorVantage`), and stamps `required_agent_role` onto the
outbox row. The claim SQL filters on that plain column, so a host agent asking
for `connector.deploy` receives the nginx deploy and never the F5 deploy, and a
cloud-store deploy (ACM, Azure Key Vault, GCP Certificate Manager) is stamped
`control_plane` and handed to no agent ever. The stamp is durable in the
lifecycle event's side-effect record, so reconcile-replay reproduces it rather
than re-deriving it against a possibly-changed census; rows enqueued before the
census existed carry the empty demand. The dispatcher reclassifies those legacy
rows by connector family before native lookup, so an old nginx row cannot use an
upgrade as a path back into control-plane execution.

The census is per connector KIND, written by hand in the composition root, and
deliberately not derived from transport: Envoy is HTTP-driven yet classified
host-agent, because its admin surface binds loopback in the deployments we ship
for. The agent has constructors for the same 14 host families, including Envoy,
and a generated parity test compares the two closed sets. A host stamp is carried
through the control-plane outbox claim rather than discarded; the dispatcher
defers it before unsealing, and its direct handler repeats the family check before
registry lookup. Classification failure is therefore a refusal, never permission
to touch the control-plane host.

**What is still not served: per-target vantage overrides** (declaring that one
particular Envoy is remote and needs a relay). The `roles` column on the agents
read model is a **projection** for the console only: writing `network` into it
grants nothing, because the certificate still says host and the claim path still
refuses. Host availability also never re-enables the old path: with no eligible
host agent the deploy stays pending for Operations to surface.

### AD CS template posture, read from inside the domain

A Windows PKI's real attack surface is not its CA — it is the template list. A
template that lets the enrollee supply their own subject, grants enrollment to a
broad group, and carries a client-authentication EKU is a domain escalation path
that looks, in every console the organization owns, like an ordinary certificate
template. Nobody has an inventory of these, because the information lives in the
directory rather than anywhere a PKI product looked.

An operator creates an `adcs` discovery source and schedule with an LDAP/LDAPS
authority, configuration naming context, read-only bind DN, `secret://`
credential reference, and optional exact relay UUID. The mutation emits the
immutable discovery source/run events and writes one `adcs.inventory` outbox
intent in the same transaction. Only a network-role relay can claim it; an
exact UUID pins it further. The control-plane worker recognizes the job as
estate-owned and performs no directory I/O. Concurrent schedule leaders use a
database transaction lock and database-clock due check, so one due interval
produces one run rather than two.

`adcs.inventory` reads `pKICertificateTemplate` and `pKIEnrollmentService`
objects under `CN=Public Key Services`, capturing schema version,
`msPKI-Certificate-Name-Flag`, the enrollment and private-key flags, EKUs,
which CAs publish each template, and the template DACL. It runs in-domain
because a domain controller's LDAP is not reachable from a hosted control plane
and should not be — an in-domain relay is the only vantage from which this
inventory exists.

The source may also name at most 24 enrollment endpoints, each bound to the
exact LDAP enrollment-service name and one closed kind: `web_enrollment`,
`ndes`, or `ndes_admin`. The relay performs one bounded GET from inside the
domain, requests at most one response byte from cooperative servers, never
follows a redirect, and closes the body without reading or retaining it. Only
the configured URL, closed reachability/authentication state, HTTP status,
authentication scheme names, verified-HTTPS fact, and Extended Protection
state cross the relay boundary. Cookies, redirect targets, authentication
challenge bytes, and response bodies do not. An endpoint not named in source
configuration is not scanned and cannot be reported by the signed result.
Public addresses are accepted through the shared resolved-address SSRF guard.
Private endpoints require the source's explicit `allow_private_endpoint` opt-in
and a bounded `private_egress_cidrs` list limited to RFC1918 or IPv6 ULA
sub-prefixes. The resolved address must fall inside that list; link-local/cloud
metadata, loopback, multicast, unspecified, and CGNAT addresses remain blocked.

**The combinations are named, not the flags.** Nobody spots an escalation path
by scanning four boolean columns across ninety templates, so the analysis reports
consequences: `ADCS-ESC1` fires only when supplies-subject, an authenticating
EKU, the absence of manager approval, and an observed broad/low-privilege
enrollment trustee are all present, because removing any one of them changes
the answer. Everyone, Authenticated Users, Builtin Users, Domain Users, and
Domain Computers are recognized by canonical SID; an unknown custom SID is
never guessed broad. Enrollment-agent templates get their own rule
(`ADCS-ESC3-AGENT`) rather than being folded into the client-auth checks,
because the primitive is different — an agent certificate requests on behalf of
*any* principal, so one of them is a master key rather than an impersonation of
one account — and so is the remediation: restricting who may enroll is not
enough, the CA must also bound which templates accept agent-signed requests.

The same sweep checks the surfaces outside template LDAP. Plaintext published
CES URIs, reachable plaintext Web Enrollment/NDES, anonymous `mscep_admin`, and
Windows-authenticated Web Enrollment whose Extended Protection is disabled or
unobserved produce separate findings with the exact endpoint/status/header
facts. `msPKI-Enrollment-Servers` is treated only as the CES metadata it is; it
is never mislabeled as proof that legacy `/certsrv` or NDES exists or is absent.
On Windows relays, `certutil.exe` queries each publishing CA's
`CA\\EnrollmentAgentRights`: a present policy is `enabled`, Microsoft's stable
missing-value result is `disabled`, and access/transport/tool failures are
`unobserved`. A non-Windows relay reports `requires_windows_relay`. Missing
evidence therefore produces an explicit visibility finding instead of becoming
either a vulnerable or hardened guess.

**Every finding carries the attributes and values it was derived from.** A
posture finding an operator cannot check against the template's own property
page is one they have to take on faith, and the first false positive they cannot
check costs the credibility of every true finding after it. A test asserts a
deliberately hardened template set produces *no* findings at all, which is the
harder half of getting this right: firing a rule is only half the problem; keeping it
quiet is what makes the output worth reading. The SAN variant is reported separately and is the
more urgent of the two, since SAN-based mapping is what Windows authentication
actually reads. An empty EKU list counts as authenticating, because unrestricted
is not harmless. Every finding names the specific change that removes it, and
reports whether a CA actually publishes the template — a dangerous template
nobody publishes is a latent risk an operator can fix calmly.

**Read-only, structurally.** The directory interface has exactly one method and
it is `Search`; a test asserts that. An inventory tool pointed at a domain
controller must be incapable of modifying one, not merely careful. The queries
name the attributes they use rather than requesting a wildcard, are bounded to
2,048 templates and 512 enrollment services, and are scoped to the Public Key
Services container. The template query requests `nTSecurityDescriptor` with
Microsoft's critical `LDAP_SERVER_SD_FLAGS_OID` (`1.2.840.113556.1.4.801`) and
the DACL-only flag; owner, group, and SACL data are not requested. A plain
`ldap://` connection is upgraded with StartTLS or the read does not happen: a
template inventory is the map of a domain's escalation paths, and reading it in
the clear publishes that map to anyone on the segment. Anonymous binds are
refused rather than attempted — where they would succeed, the directory is
misconfigured in a way worth reporting rather than quietly relying on. The
redeemed bind credential is attempt-scoped and never enters the intent, event,
report, or posture row.

The Posture console shows it: configured directory readers with
pending/running/succeeded/failed lifecycle, templates worst-first, what each one
permits and the specific fix, whether a CA publishes it, canonical Windows SIDs
granted the enrollment extended right, and which relay observed it when.
It also shows each enrollment service, its published CES URIs, configured live
endpoint probes, CA restriction state/source, exact finding evidence, and the
same observation time/relay. The Discovery form exposes the bounded endpoint
targets; the control plane never probes them.
The empty state distinguishes "no relay has read a directory yet" from "no AD CS
estate", because those are opposite facts an empty table cannot tell apart. The
posture table is only an event projection. The immutable
`adcs.template.inventory.observed` v2 event is the authority, snapshot/restore
includes both template and enrollment-service projections, and a cold replay
rebuilds the same rows atomically. Historical v1 template-only events remain
replayable but cannot masquerade as complete service evidence. Observation
time and relay identity stay visible so restored evidence cannot masquerade as
a fresh directory read.

**Changes between sweeps are reported semantically.** A textual diff of two
directory dumps is useless — attribute values are bit fields, and
"msPKI-Certificate-Name-Flag changed from 0 to 1" tells nobody anything. Each
change says what it means and which way it moved: somebody turning on
enrollee-supplies-subject, or removing manager approval, or publishing a
template that carries findings so a latent risk became an offered one. Only a
change for the WORSE emits an alerting event. An operator who has hardened
a template does not need waking, and a tool that alerts on improvement teaches
people to mute it — after which it will not reach them on the day it matters.
Better and neutral changes are still recorded, because an incident timeline
needs them.

Those records are now first-class, tenant-scoped `adcs_template_drift`
discovery findings rather than event-log-only notes. Each one is bound to the
real source, run, relay UUID/name, domain, and observation time, and preserves
the semantic change plus exact normalized before/after facts. Trustee changes
carry canonical SIDs (who gained or lost enrollment access), never raw security
descriptor bytes. `GET /api/v1/posture/adcs/drift`, the generated SDKs, and the
Posture console expose the same bounded history. A worsening v2 drift event
projects the immutable finding and one `notification.drift` outbox intent in the
same PostgreSQL transaction, so it appears in the notification inbox after one
sweep; first, unchanged, neutral, and improved sweeps do not page. Event ID and
outbox-key replay guards keep a retried signed receipt from duplicating either.
Pre-v2 drift events lacked run/source authority and therefore replay as audit
history only rather than being attached to a guessed source.

Licensed compliance evidence packs copy the latest complete v2 observation for
each domain in the bounded window plus every authoritative v2 drift record into
the signed manifest. Each carries tenant-local event ID, type, sequence, chain
digest, source, run, relay, and observation time. The outer API copy is the same
semantic object for the console; offline verification still treats the signed
manifest as authority. Template/service findings are recomputed from normalized
event facts before export, so an agent cannot omit an uncomfortable verdict
while keeping the facts that require it.

A first sweep is deliberately not drift. Reporting an entire estate as "added"
the first time anyone looks would bury the real change that comes next under
ninety notifications. The template is stored exactly as the directory reported
it so the next sweep diffs against what was really there; a row written before
that column existed is skipped and re-baselines on one quiet sweep, rather than
being reconstructed into a template whose flags all read false and reported as
becoming dangerous.

**What is not inferred:** effective user access. The descriptor parser handles
self-relative DACLs, standard and object allow/deny ACEs, Generic All, the
certificate-enrollment extended-right GUID, SID byte order, exact-trustee deny,
null DACLs, and malformed-value refusal. It reports stable ACL trustees as
canonical SIDs. It does not expand nested groups, evaluate conditional ACEs, or
invent a user's effective token; those are directory-side authorization
decisions and the console says so.

**External Windows-lab boundary.** The repository fixture runs the real LDAP
client over a BER wire, accepts exactly the two bounded SearchRequest operations,
checks the critical DACL-only control and named attributes, returns a binary
self-relative descriptor, and proves the normalized enrollment SID reaches the
inventory. The served journey separately proves real PostgreSQL, JetStream,
out-of-process signer, mTLS relay claim, single-use credential redemption,
signed result, event projection, cold replay, and console/API readback. This
development environment does not contain a licensed Windows Server forest with
AD DS and AD CS, so forest policy, domain-controller authorization, and Microsoft
implementation interoperability still require the release lab. A release must
run the same read-only account against that lab and retain the domain-controller
audit showing Bind/Search only, certutil read evidence, and IIS probe outcomes.
Repository tests use live-shaped HTTP/certutil outcomes and cross-compile the
Windows collector; they do not claim a real CA's registry encoding or IIS
Extended Protection configuration was observed here.

### Segment sweeps run from inside the segment

Network scanning ran from the control plane's worker, which meant it could only
ever see what the control plane could route to. For a hosted deployment that is
the public internet — so the scan inventoried the estate's least interesting
surface and reported it as the estate. The segments that actually hold unmanaged
certificates are the ones behind a firewall: a management VLAN, a DMZ, a lab
nobody admits owning.

`discovery.run` is now a relay job. A network-role agent already sits in those
segments, and the scanners needed no changes to allow it — they were already
dependency-light, and the one thing keeping them out of the agent binary was a
store-backed sink whose only caller was a control-plane test. Both modes travel:
TLS sweeps for served certificates, SSH sweeps for host keys.

The source must bind a declared `segment`; it may also bind one
`relay_agent_id`. Declare the denominator first with idempotent
`POST /api/v1/discovery/segments` (`name`, `ranges`, and the segment's
`staleness_hours` SLO). That mutation emits `discovery.segment.upserted`, so a
cold event replay reconstructs the declaration instead of relying on a seed-only
database row. Queueing then resolves CIDRs into at most 10,000 stable `host:port`
targets and persists that exact command with `required_agent_role=network` in the
same event/outbox transaction. The generic control-plane worker recognizes both
new commands and legacy network/SSH rows and defers them before receiver I/O, so
an upgrade cannot make an old pending scan dial from the control plane. A wrong
role or wrong exact agent cannot claim the row.

**The reserved-range guard travels with the scanner, not with the control
plane.** A relay does not escape it by being somewhere else: loopback,
link-local and multicast targets are refused inside the scanner, and the sweep
reports how many were `blocked` rather than presenting a refused range as an
empty segment. Attempted, discovered, failed, rejected and blocked are all
reported, because a sweep that reached nothing and a segment with nothing in it
must not read the same.

Findings come back over the channel the agent opened and the control plane writes
them, as with every other agent finding — a relay holds no database. The result is
accepted only while that exact lease generation is held and only after its receipt
signature, mode, assigned targets, counts, metadata bounds, and optional exact
agent selector validate. A projection error leaves the claim retryable; a replay
after completion is refused. The run API and Discovery console show the segment,
role/agent binding, blocked count, and the relay ID from the verified terminal
receipt.

**What changed in the vantage table:** `discovery.run` was host work when it
meant "enumerate this machine's filesystem". It is now a segment sweep, which is
a vantage question, so it demands the network role. A host agent's own
filesystem inventory still travels on the inventory path rather than as a
claimed job, so nothing was taken away from it.

### Revocation distribution points are monitored and recorded

Every inventoried certificate has carried its CDP and OCSP URLs since discovery
shipped — `internal/crypto/certinfo` parses them — and until now nothing fetched
one. That gap is quietly serious. A CRL whose `nextUpdate` has passed does not
announce itself: relying parties either fail closed and break the service, or
soft-fail and stop checking revocation at all. Neither appears on any dashboard
until an incident, while the CA's operator believes revocation works because
publishing succeeded once.

`revocation.probe` is now an hourly, database-clocked relay job. The leader
scheduler derives distinct CRL distribution points and OCSP responders from
inventory, matches every leaf to its real issuer key, and carries the exact
public leaf/issuer certificate context needed to verify the answer. It queues
at most 32 endpoints per bounded network-role command through the event/outbox
transaction. Concurrent leaders converge on the same command ID; if the
representative leaf changes, its OCSP serial changes the ID and creates new work
instead of colliding with an old command.

The relay performs a real fetch. For CRLs it parses the signed list, verifies the
issuer signature, and records `thisUpdate`/`nextUpdate`, latency, and revoked
count. For OCSP it builds a request for the exact leaf, POSTs the RFC 6960 media
type, verifies the signed response, checks the serial and response status, and
applies the same freshness window. Endpoints are deduplicated before probing:
one CA's endpoint is named by every certificate it issued, and walking the raw
list would be monitoring that causes the outage it watches for.

It is a RELAY job deliberately. The distribution points that matter most are
internal — an AD CS CRL on `http://pki.corp.internal/certenroll/` is unreachable
from a SaaS control plane by design — so monitoring only what is reachable from
outside would inventory exactly the endpoints least likely to break.

Five outcomes, kept distinct because they need different people. **fresh** and
**expiring** differ by a warning window, and expiring is the one worth alerting
on: after `nextUpdate` passes, relying parties are already failing. **stale**
means that has happened. **unreachable** is deliberately not the same as stale.
And **unparseable** catches the case that fools status-code checks: a proxy or
captive portal answering 200 with HTML. An LDAP CDP reports unparseable with its
scheme named, rather than unreachable, because sending someone to check a
network path that was never the problem wastes the hour that mattered. Whether
the signature was checked is reported explicitly — "we did not check" and "it
verified" must never read the same. The signed terminal receipt is accepted only
for the live lease and exact command. It emits immutable queue and observation
events, projects tenant-scoped endpoint health, and queues one warning/critical
notification per unhealthy endpoint. `GET /api/v1/revocation/health` and
Certificates → Revocation & CT show the endpoint, issuer/certificate context, relay,
evidence digest, status, latency and freshness window. Before a signed
observation exists, the API says `observed:false` and the console says unknown;
an empty projection never reads as healthy.

The view gives client-context guidance, not a universal recommendation. CRLs and
OCSP are different relying-party mechanisms. A fresh responder proves the relay
could validate that answer at that time; it does not prove every client is
configured to check it, nor whether a client fails closed or soft-fails when the
endpoint disappears. Operators must test those client policies separately.

**External lab boundary:** the repository acceptance test uses a real embedded
PostgreSQL/JetStream/signer stack, an enrolled network relay, and controlled
cryptographically valid CRL and OCSP responders. It does **not** claim a run
against a domain-joined Windows AD CS CDP/OCSP estate. That externally served AD
CS lab remains infrastructure evidence to collect when the Windows lab described
under F4 is available. LDAP CDP fetching is also not implemented; such an
endpoint is reported as an unsupported scheme instead of as fresh or merely
unreachable.

### Just-in-time credential leases: the brain ships references, not secrets

A relay executes against things that cannot run an agent — an F5, a NetScaler —
which means it needs the credentials that drive them. Handing a relay standing
credentials would put a copy of the estate's admin passwords on a machine in the
estate, permanently, whether or not any work was pending. So nothing standing is
shipped at all.

A claimed connector job carries a **reference-only intent**: what to deploy,
where, and the NAMES of the credentials it may redeem. Not the credential, and
not the sealed container holding it — the agent has no key for that seal, so
shipping it would be pointless, and would leave the tenant's credential
ciphertext sitting on a host waiting for a future key compromise. At execution
time the relay calls `RedeemJobCredential` over the same mTLS channel it claimed
on, and the control plane resolves the references — opening the sealed payload
and reading each `secret://` name out of the tenant secret store — into locked
buffers that are wiped as soon as the response is encoded.

**Redemption is once per attempt, ever.** It is a single statement: an
`INSERT ... ON CONFLICT DO NOTHING` keyed `(tenant, job, attempt)`, performed only
if the caller currently holds the job's claim lease. A replay inserts nothing. So
does a second agent that stole a lapsed lease, and so does a stale attempt
number. All three get the same coarse `PermissionDenied` with nothing to
distinguish them; the reason is classified afterward for the audit event only,
so probing the endpoint cannot map the claim table. Material is resolved BEFORE
the gate is taken, so a custody outage refuses the call without burning the
attempt's one redemption — the relay retries rather than failing the job. The
redemption's expiry is bound to the claim lease and never chosen independently:
a credential must not outlive the claim, or a second agent could take the job
while the first still holds live material.

**The agent's own words no longer become durable history when it held a
credential.** A1 already kept agent free-text out of `outbox.last_error` behind a
closed set; the event log took it raw, which was safe only while agents held no
secrets. An appliance password is short and word-shaped — no redactor recognizes
`hunter2-lab`, and no entropy floor fires on it — so any attempt that redeemed
material records a closed-set marker instead of the agent's text. The operator
still gets the failure reason, the redemption's audit reference, and the evidence
digest; the transcript stays on the relay, where an operator with access to that
host can read it. An attempt that redeemed nothing never held a secret to echo,
so its detail flows through redaction as before.

Operations shows credential custody directly: how many redeemed credentials are
held by relays right now, how many have ever been handed out, and how long the
oldest live one has been held — counts and one age, never a tenant, agent,
reference name or value. A live count that does not fall, or an age past the
maximum claim lease, is a stuck attempt holding material.

**The relay executor ships.** `internal/agent/relay` in the agent binary claims
`connector.deploy`, redeems the credential for that attempt, builds the same
connector implementation the control plane would have built — same constructors,
same sandbox, same capability grant — drives the appliance over its API from
inside its own segment, wipes, and reports. It is armed by `--relay-claim` and
only when the agent's certificate actually carries the network role; an agent
without the role says so at startup instead of polling forever and presenting as
a stalled queue.

The order inside an attempt is deliberate. Work this build cannot execute is
refused BEFORE redemption, because a credential redeemed for an attempt that was
never going to run is material outside the seal for nothing — and it burns the
attempt's one redemption, so no other agent can take the work either. Redeemed
values are moved straight into locked buffers and the wire copies wiped, so the
only surviving copy is the one destroyed on the way out, including on panic. What
a connector or an appliance says on failure is never forwarded: the relay reports
a closed phrase and keeps the target's words local, because an appliance can and
does echo the credential it received back in an error body. A sandbox
denial is reported as a failure, not as a deploy with a footnote.

Seven connectors are relay-executable — `f5`, `netscaler`, `a10`, `kemp`,
`cisco`, `fortigate`, `paloalto` — and the Agents console shows exactly that set
per relay, derived from the agent package's own census so the console cannot
advertise an executor the binary lacks.

**Host connector execution ships too.** The thirteen file/exec connectors —
nginx, Apache, Caddy, HAProxy, IIS, Postfix, Traefik, Java keystore, PostgreSQL,
MySQL, RabbitMQ, Elasticsearch, Tomcat — now execute on the host agent that
serves the machine, not against the control plane's own filesystem. The
connector implementations moved unchanged: they were always host-neutral, and
what changed is which filesystem they resolve against.

Envoy is the fourteenth host connector. It pushes SDS over HTTP instead of
writing files, but the shipped target is a co-resident loopback listener. The
agent therefore supplies its own HTTP client and the control plane refuses the
row exactly like every file/reload family; transport shape does not make a
loopback address reachable from the right machine.

The exec profile moved with them, and had to. An allowlist naming
`/usr/sbin/nginx` is a statement about a host; leaving it on the control plane
while the exec happened on an agent would mean an operator authorizing a binary
on one machine and a different binary running on another. It is now a file on
the host (`--host-exec-profile`), read and validated at agent startup so a
mistyped path surfaces when someone is watching rather than an hour later during
a renewal. Without it an agent claims no file/reload deploys at all: there is no
safe default for "which commands may run on this machine", so an absent profile
refuses rather than permits. `NewLocalOps` re-canonicalizes the roots and
re-`Lstat`s every command on the host that will run them, which is the point —
the check and the execution finally happen on the same machine.

One binary serves both vantages. A relay claims appliance work, a host agent
claims file/exec or co-resident Envoy work, an agent granted both roles claims
both, and the per-row role demand stamped at enqueue decides which agent may take a given job.
The two executor sets are disjoint by test.

**Rollback executes now through two custody-safe models (D4/G1).** After
CSR-first issuance the control plane holds no subject key, so it never rebuilds
a predecessor bundle and never sends one back down.

The executable form is a re-BIND. The predecessor is already installed on the
appliance; what a deploy changed was which installed object the listener points
at, and a rollback points it back. Nothing is uploaded, no key moves, and the
operation is possible precisely because the control plane holds nothing.

That required a change to deploys, in addition to a new operation. Every appliance
connector installed under a name derived from the target, so each deploy
**overwrote** the object before it — there was never a predecessor to bind back
to. Deployments now install under a name carrying the certificate's fingerprint,
which makes two deployments two objects (and keeps deploys idempotent for free,
since the same certificate computes the same name). The listener-facing object —
an F5 Client SSL profile, a NetScaler certkey, an A10 client-SSL template, a
Kemp virtual service — keeps its name, so existing bindings are untouched.

Four appliance families ship re-bind: **f5, kemp, netscaler, a10** — the ones whose API
addresses an installed object separately from uploading one, which is the
property a re-bind needs. The rest do not implement it and the census says so
rather than offering a rollback that would return success having changed
nothing. A rollback whose predecessor object is no longer on the appliance
**fails**, with a distinct error, because reporting success there tells an
operator that a bad certificate stopped serving traffic when it did not.

All 14 host connectors use a different model. After a successful host deploy,
the exact enrolled host agent stores active plus one predecessor bundle in a
machine-local AES-GCM ledger (`--host-rollback-dir`, default beside the agent
key). The key file and state files are `0600`; plaintext certificate/key bytes
exist only in locked memory while recording or restoring. A rollback is pinned
to that exact agent, reopens the ledger after restart, restores the predecessor,
runs the same connector reload, and repeats local listener verification. A
second predecessor is never retained, so this is a rollback buffer rather than
a key archive. Losing that directory means the host predecessor is gone and the
job is refused; the control plane cannot reconstruct it.

**Two things to know before relying on it.** First, an existing install has no
rollable target on day one: every certificate deployed before this change was
installed under the old target-derived name, which no rollback looks for. A
target becomes rollable once two deployments have landed under the new naming —
one to be the predecessor, one to be the current. Nothing warns about this; the
rollback reports that the predecessor object is not installed, which is
the truthful answer.

Second, objects now accumulate. Each deployment leaves its predecessor on the
appliance rather than overwriting it, which is the entire point, and nothing
prunes them — trstctl does not delete objects it did not create during the
customer's appliance. On a target renewed every 90 days that is a handful of
objects a year; on a short-lived-certificate target it is not, and operators
running those should expect to prune. Automatic pruning is deliberately not
served: deleting a crypto object that something else might be bound to is a
worse failure than leaving one behind.

Deploy and rollback now use the same `connector.bind:target:<id>` effect lane.
The agent claim query admits one unexpired holder per lane and returns at most
one row from that lane in a batch, so two agents cannot race a deploy and restore
against the same listener. Unrelated targets remain parallel.

Automatic rollback is served when a target explicitly sets
`auto_rollback_on_verify_failure`; manual console rollback queues the same
command. Unsupported connector families and targets with no predecessor are
refused at request time with no memo-only success receipt. Plugin-backed
connectors, `connector.right_size` and the TLS
posture path stay control-plane-only. No job kind is claimable by default:
`agent_channel.claimable_job_kinds` must name each kind before any of this
moves, which is deliberate rather than unfinished. `connector.rollback` is named
separately from `connector.deploy` on purpose — an operator should be able to
enable undoing a deployment without enabling deploying, and during an incident
that is the order they will want.

**Egress policy does not travel with the work.** The control plane validates a
target's endpoint at admission and drives it through an SSRF-blocking,
egress-guarded transport. A relay does neither: it exists to reach devices on
private, non-routable addresses inside its own segment, which is precisely what
those controls refuse. Keeping validation at admission and not re-running it on
the relay is the correct split, and it is a real reduction in what the control
plane can promise about where a relay connects. An operator granting the network
role is granting that.

### The agent job ledger: served executors and signed receipts

Work that touches your estate has to execute inside your estate. The control
plane has no route into a host and never gets one, so the agent comes and takes
the work over the connection it opened — the same mTLS channel it heartbeats on,
the same certificate-derived tenant, no inbound port anywhere.

The ledger is the outbox, unchanged. An entry is still committed in the same
transaction as the state change that caused it, still carries an idempotency key,
still at-least-once. What changed is the consumer: `ClaimJobs` and
`ReportJobResult` on the agent channel let an enrolled agent lease work, extend
while it is still going, and report executed or failed.

A claim is a **lease**, not an assignment. An agent that is killed, partitioned,
or stops calling home leaves work behind; because the claim expires rather
than sticking, that work returns to the queue without anyone noticing the machine
is gone. Claims use `SKIP LOCKED`, so a fleet polling in lockstep fans out across
the queue instead of serializing on its head. Extend, complete and release all
require the caller to hold the lease, so a stalled agent whose lease lapsed cannot
report on work another agent has since done. `GET /api/v1/operations/jobs`, `trstctl-cli operations jobs` and the
Operations console show per-kind waiting and held counts plus the oldest wait —
counts only, never a tenant identifier, payload or credential. The same posture
read publishes Prometheus series (queue depth and oldest wait per kind, live
credential redemptions and their oldest age, claims and refusals as counters),
so the metrics and the console cannot disagree about what the fabric is doing.
Three alert rules ship in `deploy/observability/alerts.yml`: a stalled queue
alerts on the oldest WAIT rather than depth, because depth alone cannot
distinguish a busy fabric from a stopped one; a credential held past the maximum
claim lease is critical, because that is live material on a machine whose claim
should already have lapsed; and refused redemptions alert at all, because each
one is an agent asking for material it did not hold a claim for. `trstctl doctor`
gains `FABRIC-1`, which sweeps agent-claimable work nobody has taken and names
the ROLE the waiting work demands — usually the answer, since work demanding a
role no enrolled agent holds waits forever and looks exactly like a busy queue.
It sits beside `DUR-2` rather than inside it because a control plane that is not
delivering and a fleet that is not claiming need different runbooks.

**Reports are signed, and the signature is what an auditor gets.** Every terminal
report — executed or failed — carries a detached signature the agent made with
the same key behind its channel certificate, over a canonical statement naming
the tenant, the agent, the job, the claim attempt, the outcome, the evidence
digest, a digest of the report's text and when it was signed. The tenant and the
agent name in that statement come from the certificate the caller authenticated
with, never from a request field, which is why a forged receipt and a
cross-tenant receipt are the same refusal: both were signed over different bytes
than the ones the server rebuilds.

This is worth being precise about, because mTLS already authenticates the
connection. What the signature adds is evidence at rest. Without it, "agent-7
executed this deploy" is a sentence the control plane wrote about itself, and
anyone who can write to the event store can write that sentence. With it, the
record is one the control plane could not have produced. The statement and the
signature are stored on the event and in a receipt ledger, so the check can be
repeated later by someone who does not trust that it happened the first time.

The production event log checks an explicit, closed payload schema for agent
claims, refusals, signing, credential redemption, workload issuance and terminal
reports. Unexpected fields or undeclared schema versions are refused. Privacy
erasure cannot rewrite a signed terminal report: it refuses that rewrite rather
than changing the bytes covered by the signature.

Agent audit publication is best-effort after the operation's state change. If the
event append fails, the server logs `agent job audit event could not be stored`
with the tenant and event type, without the payload. Investigate that error and
compare the job and retained receipt with the event history; a successful agent
response alone does not establish that its audit event was retained. Publication
does not automatically retry a missing event after the operation completes.

Anything that does not verify is refused fail-closed, with an
`agent.job.receipt.rejected` audit event and a counter on Operations: unsigned,
signed by a key that is not the connection's certificate, altered after signing,
or signed outside a ten-minute window against the server's clock. That last one
is what stops a captured receipt being replayed later — a signature does not
expire on its own. Lease extensions are deliberately NOT signed: an extend
claims nothing about the world, and signing every keepalive would put the
agent's key on the heartbeat path for no evidentiary gain.

Two honest limits. The signature attests what the agent SAID, not what the
appliance did — an agent that is lying, or that is wrong about its own outcome,
produces a perfectly valid receipt for a false statement; making the claim
checkable against the endpoint itself is the verification work (WS-D), not this.
And the transcript behind `evidence_digest` stays on the agent: the receipt
binds to a digest of something the control plane has never seen, which is a real
binding and not the same as holding the evidence.

**What is served, and what is not.** `connector.deploy` has both the network-relay
executor from A3 and the host executor for the 14 host-vantage families; a role-
eligible agent claims it, redeems its credential for one attempt, and performs the
effect from the required machine or segment. Connector test, rollback, endpoint
renewal and verification, discovery, revocation probing, AD CS inventory, trust
distribution, CMDB/MDM/ticket observation, and self-upgrade also have the executors
named in their own sections. The claimable set remains empty by default and
`agent_channel.claimable_job_kinds` is the only way to fill it. That is deliberate
rather than unfinished: handing out work nothing can perform fills a queue while the
control plane's own worker stops doing it. The kinds the allowlist recognizes
— `connector.deploy`, `connector.test`, `connector.rollback`, `endpoint.renew`,
`endpoint.verify`, `discovery.run`, `revocation.probe`, `adcs.inventory`,
`trust.distribute`, `cmdb.sync`, `mdm.sync`, `ticket.sync`, and `agent.upgrade` —
all have shipped executors. Enabling a kind exposes that already-built executor; it
does not turn a placeholder into work.
Anything outside that allowlist is dropped even if an operator names it in
configuration, so `ca.issue` and `notification.expiry` cannot be moved onto a host:
those are the control plane's own effects and CA-adjacent work does not belong in
the estate.

Agent-signed result receipts are served and verified against the same certificate
that authenticated the mTLS channel. Aggregate waiting and claimed counts are served
on Operations, together with verified/refused receipt totals. Per-agent claim quotas
beyond the shared agent bulkhead and attribution of each live claim on the Agents page
remain unserved; aggregate queue health must not be mistaken for that missing drill-down.

### Served status vocabulary: what each status claims

A status string is a claim you act on, so each one has to mean exactly what the
code did and nothing more. Three statuses on the deployment surface used to read
stronger than the work behind them. They are corrected below, and the correction
is enforced rather than remembered.

The enforcement has two closed layers. `internal/servedstatus` records, for the
action-bearing deployment and fleet surfaces, whether an attempt contacted the
target, changed it, independently re-read it, or computed a verdict from
evidence. The API builds those receipts from registry constants and CI rejects a
spelling stronger than its flags or a bare string that bypasses the registry.
Separately, `docs/status_vocabulary_test.go` derives an exhaustive census of
every `status`, `outcome`, `verdict`, `health_gate`, and `canary_state` field in
the generated OpenAPI contract. Each field must bind a closed evidence class to
an exact, AST-resolved production Go symbol; a planted future DTO proves the
census fails closed. The same gate declaration-checks the assembled negative
proofs and console renderers for fleet re-issuance, full-set restore drills, and
MDM lifecycle traces. Shared console labels cannot add a green status until its
evidence predicate is reviewed.

| Status | Surface | What it means | What it does **not** mean |
|---|---|---|---|
| `queued` | connector delivery | Intent committed to the outbox in the same transaction as the state change. | That any connector has run. |
| `delivered` | connector delivery | A connector reached the target and applied the credential. | That the endpoint is serving it. Live verification is a **separate state**, served since D2 — see `GET /api/v1/endpoints/verifications` and the endpoint verification vocabulary below. A delivery receipt says what this control plane did; only a handshake says what the listener answers with. |
| `failed` | connector delivery | The attempt ran and did not succeed. | — |
| `config_validated` | connector delivery | `POST /api/v1/connectors/targets/{id}/test` resolved target metadata, schema, and credential references **locally**, because an agent-owned target has no eligible `connector.test` path enabled. Cloud-store targets do not use this fallback. | That the target was contacted, reachable, or willing to accept the credential. Nothing was changed. |
| `verified` | connector delivery | A connector applied the credential AND a TLS handshake against the endpoint afterward observed it serving that exact identity. The only delivery state that says the certificate is **live** rather than that it was sent. | That it is still live now. A delivery receipt is historical — it records what was true when that delivery ran. Current state is the endpoint verification row beside it. |
| `verify_failed` | connector delivery | A connector applied the credential and a handshake found the endpoint serving something else. | That the delivery failed. It succeeded; the endpoint did not take it. This is a renewal that did not land, and it is what triggers rollback where a target has opted in. |
| `verified` | endpoint verification | A TLS handshake against the live listener observed it serving the expected identity. The record carries which comparisons ran — fingerprint always, name set and chain when an expectation supplied them. | That every vantage agrees. A `local` row means the serving host's own agent confirmed it; only a `relay` row means a client across the segment could get it. |
| `diverged` | endpoint verification | A handshake succeeded and the listener is **not** serving what was deployed. The mismatch class says which way: `fingerprint`, `sans`, `chain`, `expired`, `not_yet_valid`. | That the deploy failed. It usually succeeded — this is a renewal that did not land, which is exactly the failure inventory-based expiry alerting cannot see. |
| `unreachable` | endpoint verification | The handshake did not complete, so nothing was observed. | A divergence, and emphatically not a pass. An endpoint nobody could connect to is not verified. |
| `not_checked` | endpoint verification | No verification has run for this endpoint from this vantage. | That the endpoint is fine. An endpoint with no configured listener address stays here permanently — absence of a check is not absence of a problem. |
| `dry_run_queued` | connector delivery | An effect-free test was queued for the eligible host/network agent bound to this target or for the bounded control-plane outbox worker that owns its cloud connector. | That anything is yet known about the target. No executor has reported. |
| `dry_run_planned` | connector delivery | The correct execution vantage validated every prerequisite a real deploy needs and returned the mutation plan. A network relay proves its appliance credential with a read-only request. A host agent validates its operator-owned roots and logical commands and performs a read-only TLS handshake when `verify_address` is configured; without one, the plan explicitly says live verification is not configured. | That anything was deployed or, when no `verify_address` exists, that a certificate is serving. The test path never invokes a connector's `Deploy`, writes a file, or starts a reload command, so zero writes is structural rather than promised. |
| `dry_run_blocked` | connector delivery | The correct agent vantage ran the effect-free test and a real deploy would **not** proceed. The reason names the step that stopped it. Deterministic blocks are terminal test answers rather than endlessly retried jobs. | That the target is broken in every respect — one step failed, and the plan says which. |
| `rollback_recorded` | connector delivery | Legacy evidence from releases that recorded a memo instead of executing. New unsupported/no-predecessor requests are refused and do not create this status. | That a rollback executed. Nothing was restored. |
| `rollback_queued` | connector delivery | An executable rollback was queued for the required enrolled agent. Host rows also pin the exact agent that retained the predecessor. | That anything happened yet. No agent has reported. |
| `rolled_back` | connector delivery | An agent restored the predecessor and returned a signed receipt. `reason=rolled_back_and_reverified` additionally proves the same agent handshook the listener after reload; otherwise the detail explicitly says verification was not configured. | That an unverified restore is live when the reason does not say reverified. |
| `rollback_refused` | connector delivery | An agent declined the rollback **before contacting the target** — it cannot execute that connector, no supported inverse exists, the named predecessor is absent, the exact host ledger/profile is unavailable, or the sandbox blocked the operation. | That the target rejected anything. It was never reached and is unchanged. |
| `rollback_failed` | connector delivery | An agent **reached** the target and the family-specific re-bind or local restore/reload/reverification did not succeed. The reason names the failed stage. | That the target is broken in every respect, or that the predecessor is absent unless the reason says so. |
| `not_evaluated` | fleet re-issuance health gate | No evidence exists from which a verdict could be computed, so trstctl asserts none. | It is **not** a pass. |
| `passed` / `failed` | fleet re-issuance health gate | Either an operator attested the verdict, or the replacement-deployment gate was computed from signature-verified agent receipts. | That a plain delivery row or an unsigned report proved endpoint health. |
| `planned` | fleet re-issuance batch | A partition of the affected identity set that has not been published. | That anything in the batch was attempted. |
| `queued` | fleet re-issuance batch | Exactly one durable outbox command exists for the cursor batch. | That the worker or a target has run. |
| `waiting_verification` | fleet re-issuance batch | Replacement work was published and the cursor is waiting for accepted signed endpoint receipts. | That silence is success or that a later batch was published. |
| `executed` / `failed` | fleet re-issuance batch | The batch ran as a mutation unit and its signed verification gate passed or failed. | That a later batch necessarily ran. |
| `halted` | fleet re-issuance batch | The batch was never published because an earlier signed verification failed. | That this batch or its targets failed. |

Two spellings are retired and are no longer written: `test_succeeded` (now
`config_validated`) claimed a successful test on a route that opens no
connection, and a batch `completed` was stamped at planning time before anything
ran per batch. Both remain in the served OpenAPI enum and render in the console,
because receipts written before the correction still carry them and removing an
enum member would put stored rows outside the contract that describes them.

Making these statuses stronger is real work, not relabeling. The dry-run half
is now served from every execution vantage. With `connector.test` enabled,
`POST /api/v1/connectors/targets/{id}/test` queues a job for the bound host agent
or network relay. A network relay redeems the appliance-management credential
for one attempt and probes the endpoint with a read-only GET. A host agent
validates the target paths and logical commands against its local
`--host-exec-profile`, then performs a read-only TLS handshake against the exact
`verify_address` and optional `verify_server_name` when configured. If the
address is absent, preview explicitly marks listener verification skipped while
still planning the deploy; the later delivery can say `delivered` but cannot
say `verified`. It does not redeem a
certificate or private key: those do not exist in a target-only test and are
supplied only after a deploy is authorized. It redeems only a host-target secret
the preflight actually needs, such as a Java keystore password reference.
The three cloud-store connectors queue the same event-sourced job on the bounded
control-plane outbox worker. That worker resolves the exact saved target revision,
leases its provider credential for one attempt, and performs an authenticated
read-only list operation before returning the later import plan.

Both vantages return what a real deploy would change as `dry_run_planned`, or
name the first failed step as `dry_run_blocked`. Zero writes is structural rather
than promised: this path never calls a connector's `Deploy`, never writes a file,
and never executes a reload. A deterministic block is reported as a completed
test answer, so an unavailable listener or insufficient host profile does not
become a rapid retry and credential-redemption storm. Signed connector plugins
without an explicit zero-write test contract are blocked before the plugin is
invoked or any credential is redeemed. Without an eligible agent path enabled,
the route keeps the honest local answer, `config_validated`, rather than queueing
work nothing will claim.

Restoring a predecessor is served as a relay-executed re-**bind**, not a
re-upload. After CSR-first issuance (B1) the control plane never holds the
subject key, so the rollback command names the predecessor already installed on
the target by serial and fingerprint. A connector that supports re-binding can
switch to that object and report `rolled_back`; missing capability, credential,
predecessor, or sandbox permission reports `rollback_refused` before contact,
while a reached target that cannot re-bind reports `rollback_failed`. Where no
predecessor exists — a first deployment — the durable evidence says so rather
than sending an operator looking for a credential that was never there.

- Remaining private CA hierarchy operator flows beyond root/intermediate/leaf
  issuance. Root/intermediate CA creation, existing signer-backed CA chain
  import, offline-root import, offline-intermediate CSR generation/import,
  m-of-n approvals, signer-backed leaf issuance, and configured upstream CA
  issuance are served at `/api/v1/ca/ceremonies`, `/api/v1/ca/authorities`,
  `/api/v1/ca/authorities/offline-roots`, `/api/v1/ca/authorities/imported`,
  `/api/v1/ca/authorities/{id}/offline-intermediates/csr`,
  `/api/v1/ca/authorities/{id}/offline-intermediates`, and
  `/api/v1/external-cas`. Public/private direct-CA discovery is served at
  `/api/v1/ca/discovery` (returns configured public/private upstream CAs and
  imported hierarchy authorities, without PEM or key material). Zero-downtime CA
  rotation activation is served at `/api/v1/ca/authorities/{id}/rotate` (marks
  the predecessor superseded, records the successor's `replaces_id`, keeps the
  predecessor issue URL live while new certificates route to the successor).
  Signer-backed renewal/re-key is served at
  `/api/v1/ca/authorities/{id}/rekey` (consumes a `rotation:<ca-id>` ceremony,
  mints fresh CA key/certificate material, records `ca.authority.rekeyed`, keeps
  the stable issue URL live), and cross-signing at
  `/api/v1/ca/authorities/{id}/cross-sign`. Offline-root re-key
  (`/api/v1/ca/authorities/{id}/offline-rekey`) and cross-certificate
  verify/import (`/api/v1/ca/authorities/{id}/offline-cross-signs`) never accept
  a private key: operators produce the successor and both cross-certificates on
  the disconnected root system, then submit only certificates under an exact
  ceremony purpose (see the [key-ceremony runbook](runbooks/key-ceremony.md)).
- All 14 external CA integrations are served when configured. `buildRunDeps`
  constructs tenant-bound AD CS, AWS PCA, Azure Key Vault, DigiCert, EJBCA,
  Entrust, GlobalSign, Google CAS, Let's Encrypt/ACME, Sectigo, shell CA,
  Smallstep, Vault PKI, and Venafi TPP/TLS Protect clients. The authenticated
  served issue route journals the request before the upstream call, and the acceptance
  proof independently validates the returned chain for every provider. F4
  remains partial only because its separate Kubernetes CSR/TrustBundle posture
  rows are still residual, not because CA breadth is library-only.
- Discovery collectors with residual connector-owned execution: SSH host-key
  scanning is served through the discovery outbox worker, and on-host
  SSH/private-key inventory is served through the agent mTLS inventory report
  path. Connector-specific external secret-store/API-key scanners remain
  source-plugin or provider-owned unless a native served source kind supplies
  findings. The network, ssh, cloud_certificate, cloud_secret, ct_log, drift,
  k8s_ingress_gateway, and manual source kinds are wired through the served
  discovery worker (see "Discovery control plane" above), alongside the NHI
  kinds (nhi_cross_surface, oauth_grant, service_account, nhi_behavior,
  credential_compromise) and observation-shaped api_key sources; secret-repo
  and third-party artifact scans dispatch through the same worker from their
  `/api/v1/secrets/scans/*` routes. A `secret_store` source runs through the
  same served secret-manager connectors as `cloud_secret`
  (aws-secrets-manager, gcp-secret-manager, azure-key-vault,
  hashicorp-vault; the kinds share the providers config shape), and a
  provider outside that set fails with the connector's specific
  "unsupported provider" error. One accepted kind carries no worker
  executor: `agent` sources report through the agent mTLS channel instead
  of the worker. On the agent side, the shipped binary collects filesystem
  certificates, OS/Java/NSS/browser trust stores, and private-key material
  (each behind its own default-off `--inventory-*` flag). PKCS#11 token,
  Windows certificate/trust store, and in-cluster Kubernetes Secret
  collection are **not offered**: the collector boundary exists in
  `internal/agent/discovery` but the agent constructs no enumerator for
  those platforms, so adding one is an enumerator plus a flag rather than a
  new discovery path.
  Discovery schedules tick server-side: a leader-only scheduler sweeps every
  minute and queues a run for each enabled schedule whose source has no
  in-flight run and no run newer than the schedule's `interval_seconds`,
  through the same event + outbox path an operator-initiated run takes
  (runs it queues carry `requested_by: discovery-scheduler`; a failed run
  counts as an attempt, so a broken source retries next interval instead of
  hot-looping; one sweep queues at most 100 runs per tenant). The CBOM
  scanner is also served, through its own `/api/v1/cbom/*` API rather than
  the discovery-run worker.
- Broker-issued agent credentials can be task-scoped: `POST
  /api/v1/broker/agent-identities` accepts an optional
  `task_envelope_base64` (the AGID-05 task envelope) and returns the
  `task_envelope_digest` the credential binds, so an AI/MCP agent badge can be
  scoped to one authorized task instead of standing scope alone. Verification
  is the core AGID gate's: the requester signature is checked over the
  envelope's canonical bytes against an **operator-provisioned** requester key
  (the caller cannot supply its own), plus the expiry window, and the bound
  digest is the verified envelope's own — a substituted envelope cannot be
  bound in place of the signed one. **Every build attaches this gate; an
  unverifiable envelope is refused, not ignored**: silently returning an unscoped
  credential in place of the scoped one the caller asked for would be the
  dangerous outcome. Requests carrying no envelope are the ordinary
  single-hop badge, unchanged.
- A migration can be reviewed before it runs: `POST
  /api/v1/pqc/migrations/plan` (and `trstctl-cli migration plan`, available
  in every build) previews the plan — which assets would be re-issued and to what,
  which TLS findings would be rolled out, and the **residuals it will not
  touch** — without queueing a run, minting a run id, or writing an outbox
  row. It calls the same plan builder the start path calls over the same CBOM
  assets, so the preview cannot describe a different migration from the one
  that would execute.
- Signing history is verifiable after the fact: `GET
  /api/v1/code-signing/identities` (and `trstctl-cli code-signing identities`)
  lists recent signing operations with their identity kind (`managed` for a
  signer-held key, `keyless` for an ephemeral Sigstore/Fulcio identity) and
  the transparency-log state of each — `verified`, `pending`, `failed` with
  its reason, or `not-published`. Verification is not a separate flag that
  could drift: Rekor publication rides the outbox and the handler refuses to
  acknowledge an entry whose signed receipt does not verify, so a delivered
  row *is* a verified entry. The view reads no sealed command bytes, so the
  plaintext identity assertion and the artifact digest never leave the signer
  boundary through it.
- The SSH estate outside the CA is readable: `GET /api/v1/ssh/fleet` (and
  `trstctl-cli ssh fleet`) rolls the tenant's discovered SSH keys up per host
  with standing-access and orphaned counts, key types, and the observation
  window, worst host first. Every row behind it is a **raw** key — a
  certificate minted by the SSH CA is not stored as an `ssh_key` — so the
  view is by construction the not-under-CA list, and each host carries
  `under_ca: false` explicitly rather than leaving a reader to infer the
  claim from an absence. It reports metadata only (fingerprints, key types,
  locations); no private key material is read or stored by discovery.
- The connector catalog reports sandbox truth, not description: each row in
  `GET /api/v1/connectors/catalog` carries `native` (this build has a native
  implementation), `capabilities` (the declared sandbox grant — `fs.read`,
  `fs.write`, `net.dial`, `process.exec`), and `replay_safety`
  (`reconciled` when the receiver converges on retry, otherwise
  `at-most-once`). Those come from the live registry, so the catalog cannot
  claim a capability the process would not enforce; a connector this build
  does not implement natively reports no capabilities and the conservative
  at-most-once contract. Factory-registered connectors build their grant per
  attempt and report none here.
- The running system is readable: `GET /api/v1/platform/system` (and
  `trstctl-cli platform system`) reports the build version/commit/date, the Go
  toolchain, process start time and uptime, the live signer topology
  (`child`/`external`/`none`), whether the FIPS module is active, and
  per-dependency reachability for the database, event log, and signer. It
  reuses the same probes as `/readyz`, so the console and a load balancer
  cannot disagree about whether the spine is up; it reports no addresses,
  DSNs, or configuration values. The same response and the
  **System health** console page, under **Configuration evidence**, includes `idempotency_results`: RLS-scoped
  counts of legacy, sealed, pending, and indeterminate mutation responses,
  plus the explicit fleet-readiness assertion and whether PostgreSQL has the
  validated sealed-only floor. Result bytes and raw datastore errors never
  enter this view; partial, failed, empty, recovery-required, and complete
  states carry concrete operator recovery guidance.
- Worker-pool backpressure is readable: `GET /api/v1/operations/bulkheads`
  (and `trstctl-cli operations bulkheads`) reports each bounded pool's
  workers, capacity, queue depth, saturation, and its
  submitted/completed/rejected/panicked counters, so AN-7 pressure is visible
  without scraping the metrics endpoint. The counters are process-wide
  operational telemetry — subsystem names and numbers, never tenant or
  credential data — and a control plane assembled without the bulkheaded
  surfaces answers `served: false` rather than 404.
- SSH trust *rewrite* (the privileged `authorized_keys`/CA-trust mutator): the
  applier that installs a trusted SSH CA and rolls it back on failure is wired
  into the `trstctl-agent` binary behind a **default-off operator opt-in**
  (`--ssh-trust-add-ca`) that additionally requires **explicit confirmation**
  (`--ssh-trust-confirm`) before it rewrites trust. The op is additive (it never
  removes existing trust), validates the new config with `sshd -t`, reloads,
  runs a separate operator-supplied post-reload health command
  (`--ssh-trust-health-cmd`) as a validated argv command line rather than a
  shell string, and **auto-rolls-back** to the last-known-good on any failure —
  so a bad rewrite cannot lock operators out. Reload success alone is not
  treated as health. Because weakening `sshd`/`authorized_keys` trust is a
  high-blast-radius mutation, the feature stays off unless the operator turns
  it on and confirms; with the flag off the agent only *discovers* SSH trust,
  it does not *mutate* it. Trust *removal* still requires its own explicit
  confirmation.
- Posture collectors and agents: CT-log monitoring and path-based credential
  drift detection now run through the served discovery worker when operators
  create `ct_log` or `drift` sources; findings are tenant-scoped and alert
  intents are outbox-backed. Dedicated Posture dashboards, resolution
  workflows, and automatic remediation remain future UI/workflow work. Generic
  agent/endpoint discovery is served through the mTLS `ReportInventory` channel
  and visible through `/api/v1/agents`, `/api/v1/discovery/findings`,
  `/api/v1/graph`, and the Agents console. The SSH-specific host/trust
  collector still runs on the agent, not a server-side discovery-worker
  scanner, because only the endpoint can safely inspect local SSH files and
  trust config; its metadata flows through the served agent inventory report
  path. The credential graph and risk-scoring read APIs (`/api/v1/graph*`,
  `/api/v1/risk/credentials`, `/api/v1/risk/contextual-priorities`) are
  also served. The contextual-priorities response carries a canonical
  `urgent_summary`: it merges the named credential-score and contextual-priority
  projections for one tenant, exposes both source counts, and deduplicates the union
  by `credential_id`. Dashboard and Risk use that same answer, and a projection read
  failure is unavailable rather than zero. Critical/high discovery findings enqueue
  one same-transaction `notification.risk` / `risk.urgent` outbox intent from the
  same score band. `status=complete` means every named projection read completed; it
  does not mean an undiscovered machine is safe, because discovery coverage still
  bounds what these projections can know. The AI/RCA/MCP surface is also served
  behind `ai.enable_api`.
- Ownership depth (I1): owners carry an application/service model —
  `application_id`, `service`, `business_unit`, `environment` — plus a stored
  `escalation_chain`, attributed `ownership_verified_by`, verification time, and
  digest of the exact application/environment pair a human confirmed. The stored chain
  is deliberately distinct from the computed approver snapshot: the snapshot
  answers who could approve right now, the chain answers who to wake and in what
  order, and the approver graph cannot answer the second because it is about
  responsibility rather than permission. Every field is nullable and EMPTY MEANS
  UNKNOWN, never "none" — an estate predating this model has owners nobody can
  retroactively classify, and treating blank as a deliberate answer would hide
  exactly the rows the queue exists to surface. `Store.ListUnownedIdentities`
  reports four distinct reasons rather than one boolean (`no_owner`,
  `owner_missing_application_model`, `ownership_never_attested`,
  `ownership_attestation_stale`) because they need different actions: a data-entry
  gap, a classification gap, a first trust decision, and a repeated decision.
  Editing application ID or environment invalidates the prior digest immediately;
  no timestamp is allowed to pretend it confirms a different model. New steady-state
  deployments require current evidence at the configurable cadence (90 days by
  default) or an active identity-bound exception with authenticated grantor, reason,
  and expiry of at most 30 days. The scheduler writes one immutable request and one
  outbox notification per stale verification edge. Served through the owner and
  ownership-exception APIs, `trstctl owners attest/exceptions`, and the Owners
  console, which can create/edit the full model, attest it, separate all four queue
  counts, and grant a bounded exception. Expiry is enforced from event time and
  needs no cleanup timer to become effective.
- Asset-specific ownership assignment: `POST /api/v1/ownership/assignments`,
  `trstctl owners assign`, and the Owners action queue accept one durable owner,
  1–100 canonical NHI inventory IDs, and an attributed reason. The mutation is
  tenant-scoped, permission-gated, idempotency-protected, and capped at 2,000 reason
  characters and 1,024 characters per inventory ID. It emits one immutable
  `ownership.assigned` event. The projector updates the current override and, for
  native identities or certificates, the lifecycle `owner_id` in one transaction.
  A cold replay reconstructs both. An asset-specific decision wins over older native
  or imported owner hints; its event ID stays visible as exact attribution evidence.
- Ownership provenance and CMDB reconcile (I2): owners record WHERE an ownership
  claim came from — `ownership_source` (unset / `manual` / `csv-import` / `cmdb`),
  `ownership_source_ref`, `ownership_source_observed_at`. All three are nullable
  and unset means UNKNOWN, never "manual": an unrecorded origin is not evidence
  a human said so, and the Owners grid renders it as "not recorded". Two ingest
  paths write it. `POST /api/v1/owners/import` (`trstctl owners import`) takes a
  CSV; `PUT/GET /api/v1/owners/cmdb-schedule` (`trstctl owners cmdb-schedule
  set|show`) configures a per-tenant, leader-only ticker that re-reads
  ServiceNow `cmdb_ci` on the tenant's own interval. Both funnel through one
  reconcile rule: a source FILLS IN what nobody recorded and NEVER overwrites
  what a human attested — that becomes a row in `owner_ownership_conflicts`,
  carrying both values and the source record that caused it, surfaced in an
  "Ownership disagreements" panel on the Owners console. A change to a value
  nobody attested IS applied and is still listed, because a change nobody was
  told about is how ownership data quietly stops matching reality. A blank cell
  is silence, not a deletion. Read-only is structural, not a flag: the network
  relay builds only GETs against a fixed `/api/now/table/cmdb_ci`, and
  `orchestrator.NormalizeServiceNowTable` — the only writer — rejects `cmdb_ci`,
  so there is no configuration that turns this into a CMDB write. A CI naming an
  owner this estate has never heard of does NOT create one; it is reported as
  unattributed, because a CMDB assignment group is not evidence that a trstctl
  owner should exist and auto-creating would build a parallel estate out of the
  CMDB's typos. The sync is RELAY-ONLY: the leader commits a tenant-scoped
  `cmdb.sync` outbox job, and a NETWORK relay inside the segment claims it over
  its outbound channel. There is no control-plane HTTP fallback and therefore
  no private-egress hole into the estate. The relay redeems the ServiceNow token
  per attempt through the job-credential path (`secret://` is required; an
  `env:` reference belongs to the brain process and is refused), reads the one
  permitted table through the shared endpoint builder, parses in place, and
  reports records — never the raw response, bounded at 8MB. The RECONCILE
  stays in the control plane on the reported records, so the
  never-overwrite-an-attestation rule has exactly one implementation. The signed
  result is bounded before ingest and projected before the job closes; stable
  event identities make a crash/retry converge. One relay job reads at most 500
  CIs in strict `sys_id` keyset order. A full page commits an immutable page
  event, the exact next cursor, cumulative read count, current expected count,
  and the next `cmdb.sync` outbox intent in one tenant transaction. A short or
  empty page is the only terminal proof. Dispatch and intermediate pages never
  set `last_run_at`; `GET /api/v1/owners/cmdb-schedule`,
  `trstctl owners cmdb-schedule show`, and the Owners console expose
  `read_count`, optional `expected_count`, `pages_completed`, `next_cursor`,
  `coverage_complete`, and the retained failure. Restart recovery derives the
  same idempotent next job from the event/checkpoint, so it resumes rather than
  rereading page one. The source inventory stores only CI key, matched local
  owner ID, and the four contributed ownership values. At terminal completion
  it withdraws a vanished/reassigned CI's still-identical, unattested values,
  never a human attestation or later edit, and serves changed/removed counts.
  One page is in flight per tenant; a second due tick leaves that incomplete
  checkpoint untouched instead of stacking an identical read. Scope, stated
  exactly: relay execution is mandatory; there is no run-now endpoint (a newly
  enabled schedule is due immediately and fires within one scheduler tick);
  resolving a conflict is a read surface only —
  a disagreement is CLOSED through `POST /api/v1/owners/ownership-conflicts/{id}/resolve`
  (`trstctl owners resolve-conflict`), which REQUIRES both a reason and an
  attributed operator — "resolved" with no explanation tells the next reader
  nothing about which side was right, and an unattributed judgment cannot be
  questioned later. The projection pins `resolved_at IS NULL` so a second
  operator cannot overwrite the first one's judgment. The console lists
  disagreements but has no resolve control yet;
  and the CI-to-CERTIFICATE mapping is by owner NAME, so a CMDB whose owner
  labels do not match this estate's owner names reconciles nothing and says so.
- Issuance requests as first-class objects (I3): the effect-free
  `POST /api/v1/issuance-requests/preview`, the mutating
  `POST/GET /api/v1/issuance-requests`, and `/{id}/approve|deny|cancel`
  (`trstctl issuance-requests preview|open|list|approve|deny|cancel`) give a request
  a real lifecycle —
  `requested` then `approved`, `denied`, `expired`, or `cancelled`, and
  `approved` is NOT terminal because issuance can still fail. Collapsing
  approved and issued would make a request whose mint failed read as fulfilled.
  Denial and expiry are deliberately distinct: a denial is somebody's decision
  and REQUIRES a reason (a denial with none teaches the requester only that
  somebody said no, so they re-ask); an expiry is nobody's, and the leader-only
  sweep records it with an EMPTY `decided_by`, because stamping a person on it
  would put a decision in the audit trail that no human made. The requester can
  withdraw their own request and can never decide it — self-approval would leave
  an approval record that looks legitimate while nobody independent looked — and
  only the requester may cancel, so anyone else closing it is a denial and is
  recorded as one. Permissions reuse the existing `certs:request` / `certs:issue`
  split rather than inventing a parallel `certs:approve` that could drift out of
  agreement with the gate guarding direct issuance. Requests default to a 7-day
  expiry; the list surface serves closed rows too and counts open separately,
  because one total cannot say whether a queue needs attention or is merely long
  with history. Direct API/console requests require `owner_id`. Preview and submit
  share one admission path: they validate an optional public CSR, resolve a profile
  name to the exact active version, and accept only a syntactically valid owner UUID
  that resolves through the caller's tenant RLS context. Preview returns blockers,
  key custody, approval authority, and later submission effects but writes no event,
  projection, identity, certificate, outbox job, or idempotency row and contacts no
  CA. The console refuses to submit a stale, missing, blocked, or unavailable
  preview and links to Profiles, Owners, and CA hierarchy for configuration.
  Missing/malformed identifiers return 400 before event append; missing and
  cross-tenant owners share one 422 response so the endpoint does not reveal another
  tenant's roster. Historical and ticket-intake events predate this binding and can
  still project with no owner; that absence remains explicit instead of being
  backfilled with a guessed account. TICKET-DRIVEN INTAKE is now real: `PUT/GET
  /api/v1/issuance-requests/intake-schedule` (`trstctl issuance-requests
  intake-schedule set|show`) configures a per-tenant ServiceNow or Jira read.
  Each provider has its own schedule row, so a slow ServiceNow sweep cannot
  hide or replace Jira progress. ServiceNow is bounded to one of the four
  request-shaped tables (`incident`, `sc_req_item`, `sc_request`,
  `change_request`); Jira is bounded to one validated project key. Both bounds
  are database CHECKs, because an unbounded source name would aim the intake
  token at records that are not this tenant's certificate-request queue. The
  intake opens one issuance request per ticket,
  IDEMPOTENTLY by ticket reference: a re-seen ticket opens nothing, and a
  DENIED request does not reopen — the denial was the answer to that ticket,
  and a fresh ask needs a fresh ticket. The field mapping is explicit
  (`subject_field`, `profile_field`, optional requester/justification); a
  ticket missing the mapped subject or profile is SKIPPED AND COUNTED, never
  guessed at, because an intake that opened requests from prose would fill the
  approval queue with noise. Requests opened here carry `origin=servicenow|jira`
  and the exact provider ticket reference, and the existing lifecycle — separation of
  duties, denial with a reason, expiry (7 days for intake-opened requests) —
  decides them unchanged. Each sweep first commits a tenant-scoped
  `ticket.sync` outbox job. A NETWORK relay redeems the provider's `secret://`
  token for one attempt and performs the only external call; the control plane
  has no ServiceNow/Jira HTTP or token fallback. ServiceNow advances by strict
  ascending `sys_id` keyset pages and Jira advances by the provider's opaque
  enhanced-search `nextPageToken`, with a hard 100-ticket page bound. The
  signed report must echo the exact provider, sweep ID, input cursor, source
  references, read count, and provider total. The page event and next outbox
  command commit together. Dispatch or failure updates `last_attempt_at` and
  retained error only; `last_run_at` and `coverage_complete=true` appear only
  after a terminal page whose observed count equals the provider total. The
  API and console serve `read_count`, optional `expected_count`,
  `pages_completed`, `next_cursor`, eligible/skipped counts, retained failure,
  and terminal coverage separately. Replay, relay retries, scheduler restart,
  snapshot restore, and cold event rebuild therefore resume the same cursor;
  stable request/page identities collapse duplicates without skipping later
  tickets. The GITHUB ACTION lives in-repo at
  `clients/github-action` (composite, `action.yml` + README with the sample
  workflow): the workflow's ambient OIDC token is fetched with the requested
  audience, an EC key is generated INSIDE the runner (only the public half
  travels), and `POST /api/v1/workloads/attested-issuance` with
  `method=github_oidc` returns the certificate. Its idempotency identity binds
  run, job, and Action but excludes `GITHUB_RUN_ATTEMPT`; a fresh-runner rerun
  presents a new public key and receives HTTP 409 from exact request binding,
  so it cannot mint twice or receive a certificate for the wrong private key.
  Fork pull requests are refused locally before OIDC, and the server still
  verifies the signed `repository_owner` against `allowed_owners`. CI extracts
  and executes the shipped composite run block against the full served test
  deployment, then proves success, foreign-owner refusal, rerun conflict, and
  one certificate row. The tag release pipeline packages the Action,
  `SHA256SUMS`, and SLSA provenance. Repository state is release-ready for
  `v0.6.0`, but that immutable tag is not published until an authenticated
  maintainer pushes the reviewed commits and creates the tag; the current
  local remediation does neither. The Action still requires an API token
  scoped to `certs:issue` alongside the OIDC attestation. Approving a request
  does not itself mint. The served
  `POST /api/v1/issuance-requests/{id}/prepare` command creates or recovers one
  deterministic requested identity, keeps the request at `approved`, and
  returns only the stored public CSR plus a stable request-derived issue key.
  The console sends that identity through the ordinary guarded
  `requested -> issued` transition, so RA separation, policy, optional dual
  control, profile binding, signer isolation, outbox delivery, and idempotency
  are not bypassed by the convenience journey. Finally,
  `POST /api/v1/issuance-requests/{id}/complete` moves the request to `issued`
  only when its linked identity has an immutable issuance transition AND inventory
  contains its real certificate under the exact canonical issue key. The signing
  worker also completes this receipt, so closing the browser cannot lose it.
  Recovery after revocation or retirement records historical fulfillment without
  reactivating the credential or signing again. Reviewer (`decided_by`) and original
  issuance actor (`issued_by`) remain separate facts; `issued_at` is the retained
  certificate-recording time, not the later recovery time. A
  signer or outbox failure therefore leaves an honest, retryable `approved`
  request instead of producing a false green status. The console keeps that
  approved row visible, explains the interruption, and labels the recovery action
  **Retry safely**; prepare and issue repeat with the same deterministic identity
  and stable request-derived issuance key rather than creating a parallel operation.
- Attested issuance is reachable (AUD-10, I3 prerequisite): `attested_issuance`
  in the config file turns on `POST /api/v1/workloads/attested-issuance` and
  `POST /api/v1/ssh/attested-user-certs`. Before this there was NO config key at
  all — `Deps.AttestedIssuance` was never assigned anywhere in production, so
  both routes were registered, documented, and permanently 503 on every
  deployment, and the six attestors behind them (including the GitHub OIDC
  attestor a CI pipeline needs) were constructed by code no request could reach.
  Off by default is correct for a mint that trades a cloud attestation for a
  certificate; unreachable when on was the defect. Attestors stay per-tenant from
  the workload attester-trust API rather than process-wide, so one tenant's trust
  decision does not become every tenant's. The other two members of this family
  are now fixed too (AUD-12, AUD-13): `agent_broker` turns on
  `POST /api/v1/broker/agent-identities`, and `pam` turns on
  `POST /api/v1/access/sessions` and its three siblings. All three were dead for
  one reason — a `Deps` field never assigned anywhere in production and no
  config key to populate it — so five routes were registered, documented, and
  permanently unavailable on every deployment while looking healthy. PAM TARGETS
  are deliberately NOT config: a Postgres DSN or SSH credential in the main
  config file is a credential in every backup of that file, so enabling PAM
  yields a working surface with no targets rather than one that asks for secrets
  in the wrong place. A malformed TTL on any of the three leaves zero so the
  built-in bound applies — silently substituting a LONGER lifetime than the
  operator wrote is the dangerous direction, and zero cannot do that.
- MDM device correlation and per-device enrollment trace (I5): `GET
  /api/v1/mdm/devices` and `GET /api/v1/mdm/{mdm}/devices/{id}/trace`
  (`trstctl mdm devices|trace`) join Intune and Jamf device records to SCEP
  transactions and answer the question a status field cannot: WHICH STEP an
  enrollment broke at. The trace runs `requested -> issued -> installed ->
  renewing` and the distinctions are the feature. A step nobody reported is
  `pending` only if an earlier step SUCCEEDED — otherwise a device that never
  asked would look mid-flight and sit in an "in progress" queue forever. Steps
  after a failure are `unknown`, not `pending`: nothing downstream was
  attempted, and `pending` suggests it still might happen. Only the FIRST
  failure is reported as the break, because reporting the last sends an operator
  to the symptom rather than the cause. An MDM that could not be reached yields
  `unknown`, never "not installed", and the list counts `unobserved` separately
  from `failed` — merging them sends somebody to re-push a profile that is
  already there. Intune's `deviceRegistrationState` is ALWAYS `unknown` for
  certificate installation: it says that the device is registered, not that a
  SCEP profile or certificate installed. Intune installation evidence comes
  from a completed `CertificatesByRAPolicy` export filtered to the exact enabled
  SCEP profile IDs. Jamf reads the fixed `GENERAL`, `HARDWARE`, and
  `CERTIFICATES` inventory sections. Neither provider can produce `installed=ok`
  until its exact device record contains the signer-minted certificate serial
  with an active/valid status; a completed read with a different serial is an
  actionable failure, while no certificate-specific read remains `unknown`.
  READ-ONLY IS STRUCTURAL — inventory uses fixed GET paths
  (`/v1.0/deviceManagement/managedDevices` and
  `/api/v1/computers-inventory`). The one non-GET provider operation is
  Microsoft's fixed `POST /beta/deviceManagement/reports/exportJobs` for the
  `CertificatesByRAPolicy` READ artifact; it cannot name a policy, assignment,
  or device mutation path, and the Graph bearer is never forwarded to the
  signed report-download authority. There is no MDM write route;
  `TestNoMDMCodePathCanWrite` rejects PUT/PATCH/DELETE and any mutation-capable
  resource fragment. Devices with no
  matching certificate and certificates with no matching device are BOTH
  reported, because a correlation that showed only its successes would make an
  estate look covered by hiding the gaps; the join key is the hardware serial,
  matched case-insensitively, because device NAME would silently join two
  laptops an admin happened to name the same. THE SURFACE NOW HAS ITS PRODUCER:
  `PUT/GET /api/v1/mdm/poll-schedule` (`trstctl mdm poll-schedule set|show`)
  configures a per-tenant, per-MDM schedule and a leader-only ticker re-reads
  Intune/Jamf on that interval. An identity inventory join remains metadata only;
  the lifecycle trace joins the MDM hardware serial to immutable
  `protocol.scep.request.observed` and `protocol.scep.issuance.observed` facts
  emitted by the actual SCEP handler, keyed by the exact CSR common name and
  transaction. A successful issuance fact carries the inspected signer-minted
  certificate serial, fingerprint, and expiry; every terminal refusal carries
  its failed stage and remediation. Correlation IDs and identity lifecycle rows
  never manufacture success. The sync is RELAY-ONLY: the leader first commits
  a tenant-scoped `mdm.sync` outbox intent, a NETWORK relay claims it over the
  outbound agent channel, and that relay redeems the `secret://` token for one
  attempt. `env:` references, `control_plane` execution, and the old
  `allow_private_endpoint`/`private_egress_cidrs` brain-egress grant are
  refused. The fixed endpoint is parsed in place and only a bounded typed,
  signed observation returns. The control plane binds that report to the exact
  durable job payload, projects it before atomically completing the claim and
  outbox row, and performs correlation through one shared core; it has no MDM
  HTTP/token fallback. The in-flight pending check reads the provider from the
  durable `mdm.sync` intent: a pending Intune read stops duplicate Intune work
  but does not suppress Jamf (and vice versa). Each provider's schedule stamps
  its own waiting or completed outcome instead of reporting invented health.
  RENEWAL-WINDOW AWARENESS FOR OFFLINE DEVICES is served on the device list:
  each correlated device with a certificate carries `renewal_at_risk` and a
  detail naming the dates, computed from the identity's expiry against the
  DEVICE'S OWN last check-in (Intune `lastSyncDateTime` / Jamf
  `lastContactTime` — never the poll time, which would make every device look
  fresh on every poll and defeat the check). A device inside its renewal
  window that the MDM has not seen since the window opened is flagged: a SCEP
  device renews by CHECKING IN, so nothing fails before the certificate
  expires in a drawer — and the count is served apart from `failed` because
  nothing has failed yet, which is the problem. The window is 30 days unless
  the schedule sets `renewal_window_days`. Scope, stated exactly: no built-in
  OAuth client-credential exchange — the token reference must resolve to a
  bearer the MDM accepts, rotated by the operator's own pipeline; a device
  with no certificate gets NO renewal verdict rather than a warning. The trace's
  `renewing` stage is now evidence-backed: a later distinct SCEP transaction
  supplies its request/result, while a certificate inside its renewal window
  with no later attempt and a stale device check-in is `unknown` with instructions
  to bring the device online and trigger an MDM check-in. The console device row
  opens this complete trace and shows the first failed stage plus its remediation.
  Intune report export currently uses Microsoft Graph's beta report endpoint;
  the operator-supplied bearer must already authorize both managed-device reads
  and report export because trstctl does not perform an OAuth credential exchange.
- AD CS coexistence, first increment (F4): the `/certsrv` transport now REFUSES
  to send a password over plaintext. Basic is base64, not encryption, and on a
  plaintext hop anyone on the path reads a credential that can issue from the
  enterprise CA directly — the compromise is not "an eavesdropper saw a request"
  but "an attacker can mint certificates the whole domain trusts". The refusal
  is at CONSTRUCTION, so a misconfiguration fails when an operator sets it up
  rather than silently on the first production issuance. A domain-joined relay
  can supply Kerberos/NTLM through a `WebEnrollmentConfig.Authenticator`, an
  interface rather than a GSSAPI dependency because the credential belongs in
  the host's credential store and core must have no code path that could
  serialize a domain password. Configuring BOTH a password and an authenticator
  is refused: the authenticator would win, leaving a live domain credential in
  configuration that nothing reads — which is exactly what somebody later
  "fixes" by making it take effect. A failing authenticator fails the request
  and never falls back to Basic, so a transient Kerberos problem cannot put the
  password on the wire. AD CS certificate-database rows parse into a vocabulary
  that keeps PENDING distinct from FAILED and from DENIED (a pending request
  rendered as failed makes an operator re-submit instead of going to get it
  approved; a human decided a denial), an unrecognized disposition code maps to
  `unknown` rather than `failed` so a code Microsoft adds does not report
  healthy certificates as broken, serials normalize so the same certificate from
  two exports is not two inventory rows, and an unparseable NotAfter is counted
  as a VISIBILITY GAP rather than treated as an expiry in year zero. Scope,
  stated exactly: this is the transport and parsing layer only. NOTHING YET
  CALLS THE DATABASE INGESTION — there is no scheduled or served ingest that
  pulls a CA database into inventory, so issued/pending/revoked state is not
  reconciled by C4/XREC; no Kerberos or NTLM Authenticator IMPLEMENTATION ships
  (the seam exists, the relay-side implementation does not); the ACME/EST
  front-end that would issue a leaf through an AD CS template under a trstctl
  policy gate is not built; and there is no "modernize this template" console
  action or AD CS issuer health view.
- Staged agent upgrades with an automatic canary halt (A5): `GET/POST
  /api/v1/agents/upgrade-campaign`, `/pause`, `/resume`, and
  `POST /api/v1/agents/upgrade-ring` (`trstctl agents upgrade-campaign
  show|start|pause|resume`, `trstctl agents upgrade-ring`) run a rollout through
  canary, early, then broad rings, and a leader-only sweep advances it. The halt
  is the product: ONE unhealthy agent halts, with no percentage tolerance,
  because a tolerance on a deliberately small canary means the ring can never
  stop anything — which is the entire reason the ring exists. SILENCE halts too;
  an agent that took an upgrade and stopped answering is the most likely shape
  of a bad build, so it is never scored as a success. An EMPTY ring halts as
  well: an unassigned canary proves nothing, and advancing through it would skip
  the stage whose failure is supposed to stop the rollout, on exactly the fleet
  nobody has triaged. Resume restarts AT the ring that halted, never past it —
  skipping ahead would leave the agents whose failure stopped the rollout on the
  broken build while the campaign reported success — and a halted campaign never
  un-halts on its own, so a flapping agent cannot resume a rollout nobody
  re-approved. Pause GATES DISPATCH (the sweep returns early and `fleet.Advance`
  refuses independently), not merely the button; a pause that grayed out UI
  while jobs kept flowing would be worse than none because the operator believes
  they stopped it. `upgrade_ring` empty means UNASSIGNED and is never read as
  `broad`, and the console counts unassigned separately. Halted and paused are
  distinct states: one is the machine's finding, the other a person's decision.
  A campaign started WITH per-platform artifacts (`artifacts: [{os, arch, url,
  sha256}]`) DISPATCHES: the sweep hands every agent in the active ring its own
  `agent.upgrade` job through the A1 ledger, each row narrowed to that one
  agent by `required_agent_id` (the control-plane dispatcher structurally
  refuses such rows — only the named agent's claim can reach them). The agent —
  with the `-self-upgrade` opt-in, which is the MACHINE operator's consent and
  is off by default — downloads its platform's artifact, verifies the pinned
  sha256 (a mismatch is refused and reported; the artifact host is a mirror,
  not a trusted party), swaps its binary keeping the previous one as `.old`,
  reports a SIGNED receipt, and restarts (exec on Unix; on Windows the process
  exits and relies on the service's recovery action — an agent that stays down
  reads as silence and halts the ring, which is the correct verdict). The ring
  is then scored against the DISPATCH LEDGER: a signed failed receipt halts
  immediately with no grace; an agent observed running the target version
  verifies (the executed receipt alone means "staged" — the reconnected
  version report is the proof the new build runs); an agent that neither
  failed nor arrived within the 10-minute grace is silent, and silence halts.
  Resume re-dispatches the halted ring as a NEW round, so the failed round's
  receipts stop counting against the retry.
  Scope, stated exactly: a campaign with NO artifacts is OBSERVE-ONLY — the
  pre-dispatch behavior, kept for fleets an external mechanism upgrades, where
  verification is "the agent reports the target version and has been seen
  since" and nothing is pushed; the console says which mode a campaign is in.
  The artifact sha256 is operator-supplied — the platform guarantees the fleet
  installs exactly those bytes, not that those bytes are good, and there is no
  publisher signature over artifacts beyond the digest pin. Ring assignment is
  manual with no automatic canary selection; there is no per-ring soak window
  beyond the 10-minute grace; and the verification remains a health signal
  (running the target build, answering the control plane), not a functional
  check of the agent's work.
- Provider console (L3 + AUD-58): the web app has a `/provider` route — a
  console for the provider's own staff, separate from the tenant plane. It lists
  customer tenants with their lifecycle state and drives the `/provider/v1` API
  the plane already served but no web client consumed: provision a customer,
  suspend, offboard, each mutation confirmed because one click changes a whole
  customer's world. The plane's operator is authenticated by the provider IdP
  (L1), so the console carries an operator bearer rather than a tenant session,
  and holds it IN MEMORY ONLY — never web storage — per the SPA's XSS posture
  (SURFACE-I01): the token lives in the tab's JS heap, is lost on reload, and an
  auth refusal returns the operator to the sign-in gate rather than showing an
  error. Each customer row expands to show its quota (max agents, certificates,
  secrets), reading `/provider/v1/tenants/{id}/quota`; an UNSET limit renders as
  "unlimited", never zero, because a missing cap is the absence of a limit, not
  a limit of nothing. Scope, stated exactly: this is the tenant-lifecycle
  console with per-customer quota MANAGEMENT — each customer row expands to
  view and EDIT its limits (max agents, certificates, secrets), a blank field
  saved as unlimited never zero — and per-customer WHITE-LABEL BRANDING: a brand
  editor (product name, custom domain, login message) that writes through
  `/provider/v1/tenants/{id}/brand`, a route wired to the tenant-scoped provider
  authority event receiver and its white-label read projection, behind the same
  per-customer delegation gate (an
  operator can brand only a customer they are delegated, because a custom domain
  is a claim on a host and branding another's customer could seize it). A
  duplicate custom domain is refused by the projection's uniqueness constraint
  and the refusal is surfaced. Customer lifecycle, quota, brand, delegation,
  and break-glass state now rebuild exactly from one immutable provider
  authority history; the six PostgreSQL views, now including
  `provider_operators`, expose no production mutator.
  Every provider mutation requires a key bound to operator + method + path +
  body, and the console sends one; identical sequential or concurrent retries
  return the original HTTP bytes, while changed commands return 409. The
  console also triggers the served siloed-isolation drill and shows its checks.
  Its Authority activity panel reads `GET /provider/v1/activity` and renders
  newest-first event id/sequence/type/time/customer/actor evidence derived from
  the same immutable authority history. Current delegation filters customer
  events before serving, global drill evidence is admin-only, and the response
  deliberately omits command bindings, authority payloads, and break-glass
  snapshots.
  AUD-58 adds the Provider-admin/MFA access panel. It lists SCIM operator
  lifecycle/source/role and exact customer-operation grants with expiry, last
  use, and retained revocation; it grants, revokes, and changes the Provider
  role through idempotent event-backed routes. SAML login is discovered from
  `/provider/v1/auth/methods`; the browser uses the separate HttpOnly Provider
  session and sends only the non-credential CSRF value from JavaScript. OIDC
  bearer input remains as a memory-only option for operator tooling. The local
  `trstctl provider-grant` command remains the install-time bootstrap path;
  AUD-59 adds invoice evidence in the same console: an operator selects a
  delegated billing customer and closed period, pulls the signed JSON without
  impersonating a tenant, sees billable/reconciliation/digest plus independent
  **Signature verified** posture, and downloads either the signed JSON or the
  finance CSV whose every row retains customer, period, verdict, and digest.
  AUD-60 adds **Customer health** beside that **Invoice evidence** for the same
  selected customer. `GET /provider/v1/tenants/{id}/health` requires the exact
  customer's `read` delegation before `DirectTenantSnapshot` opens the
  customer's forced-RLS certificate transaction. It reports lifecycle-derived
  health and the active-certificate count; a missing customer is 404 and an
  unavailable snapshot is an explicit 503. Before a pull, or after a failed
  read, the console says health is unknown/unavailable — it never turns missing
  telemetry into a healthy zero. Another customer's active certificates cannot
  enter the count because the query carries and is confined by the selected
  customer's tenant identity.
  break-glass request, consent, and result-use APIs are still not exposed in
  this console.
- AD CS certificate-database lifecycle visibility (F4, PARTIAL): `POST
  /api/v1/adcs/ca-database/ingest` and `GET /api/v1/adcs/ca-database` (plus
  `trstctl adcs ca-database ingest|list` and a Posture console panel) turn
  certutil rows a domain-joined relay collected into a per-CA breakdown by
  disposition — issued, PENDING a CA manager's approval, revoked, denied,
  failed. Pending is kept distinct from failed and denied throughout, because
  the fix for a pending request is approval, not resubmission; an unrecognized
  disposition code is `unknown`, never folded into failed; an issued row whose
  expiry could not be read is counted `unparsed`; and a row carrying no request
  id is counted `rejected`, never dropped — so a collection problem cannot read
  as an empty or healthy CA. This wires `adcs.ParseDBRow` and `adcs.Summarize`,
  which existed with NO production caller — parsing that nothing ran and a
  summary nobody saw. It is deliberately VISIBILITY, not control: trstctl reads
  the CA database, it does not approve or revoke through this surface. Scope,
  stated exactly: the control-plane ingestion, projection, serving and console
  are built and proven end-to-end (a relay posts rows, the per-CA summary reads
  back, a re-sweep replaces rather than accumulates); the relay-side COLLECTION
  is not — the CA database is read by `certutil` on the domain-joined Windows
  relay, which this repository does not yet drive, so the rows arrive over the
  ingest endpoint but nothing yet runs certutil to produce them. The rest of F4
  — in-domain Kerberos/NTLM authentication (an `Authenticator` interface, not a
  Kerberos implementation) and fronting AD CS templates with trstctl ACME/EST —
  remains unbuilt.
- PQC readiness reports are signed and offline-verifiable (M1, PARTIAL): a
  cohort's handshake evidence — every targeted client's outcome WITH its
  handshake size and latency — is turned into a verdict by `Assess` and
  exported as a readiness report signed inside the isolated signer under its
  own `pqc-readiness-report` key, verifiable offline from the report alone. The
  signer key refuses every other artifact kind, so being in the shared signer
  chain grants it no authority over XREC or VDEC artifacts; the signature
  covers the whole body, so an edited verdict cannot pass verification, and the
  report carries the FULL evidence so a reader re-derives the verdict rather
  than trusting the sentence. Cost travels in the signed body on purpose — a
  cohort that negotiated but tripled handshake size is a different
  recommendation, and a report omitting cost would recommend an outage. Scope,
  stated exactly: this is the EXPORT and the verdict rule, not the lab. Nothing
  yet issues parallel classical/PQ pilot hierarchies or drives a cohort's
  probes as a wave, so the report still has no live evidence to sign unless a
  caller supplies it; the relay records handshake cost (`HandshakeMillis`,
  `ChainBytes`) but no wave orchestration, canary-halt execution, or PQC lab
  console view is built. The acceptance's end-to-end pilot is not demonstrated.
- Per-tenant silo isolation identifiers all key on the tenant ID (L4): a siloed
  tenant's Postgres schema, JetStream subject lane, and object-key prefix are
  each derived from the tenant's unique, immutable ID. The event LANE used to be
  the exception — it was derived from the operator-supplied slug, which has no
  charset validation and normalizes lossily, so `acme-corp`, `acme_corp` and
  `acme.corp` all collapsed to one lane and two distinct tenants with those
  slugs would have SHARED a JetStream stream — one customer's events landing in
  another's, a cross-tenant isolation breach in the sovereignty feature. The
  lane now carries the slug only as a readable prefix with the ID as the
  uniqueness suffix, and a structural assurance test proves distinct tenants
  stay disjoint on all three axes (schema, lane, object prefix — with no prefix
  a prefix of another's) even when their slugs collide. Scope, stated exactly:
  this hardens the derivation and adds the assurance; the per-tenant KEK/HSM,
  the per-tenant audit stream, tenant-scoped break-glass with dual consent, and
  the provider assurance console remain unbuilt, and the doctor's operator-run
  isolation suite does not yet drive an object-store lane against a live backend.
- XREC reconciliation rounds are configurable (AUD-1, C4): a `reconcile` block
  in the config file supplies the schedules the rounds worker needs. Before
  this, `roundSchedules` was declared and never assigned, so the worker —
  registered, licensed, and visible in the runtime roster — hit its
  `len(Schedules)==0` guard on the first tick and blocked for the life of the
  process. Zero anti-entropy rounds ever ran, no `xrec.witness.recorded` event
  was ever appended, and `GET /api/v1/reconcile/agreement` answered "0 open
  witnesses" forever. A licensed operator watching a healthy worker would
  reasonably conclude reconciliation was running while nothing was ever
  compared. A schedule naming FEWER THAN TWO authorities is dropped rather than
  scheduled: comparing an authority to itself produces no witness and would make
  the report claim `collecting=true` on a deployment that still compares
  nothing — the same illusion in a new place. An unparseable cadence or liveness
  takes a sane default rather than zero, because a zero cadence busy-loops the
  scheduler against a customer's authorities and a zero liveness marks every
  authority instantly stale. With C4's adapters, two authorities are DURABLE:
  `trstctl-self` reads the certificate inventory and `trstctl-ca` reads the
  internal CA issuance ledger — independently written state under RLS — both
  projected onto the shared assertion vocabulary (issuer+serial identity,
  active-vs-revoked standing, scoped to the internal-CA jurisdiction so a
  DigiCert certificate in inventory is not reported as drift the ledger never
  claimed to know about). A round whose digests disagree hands each differing
  pair to the runtime's witness emitter: witness built over the exact sets the
  digests committed to, signed in the isolated signer, recorded with both
  signed digests on the ledger event, quarantine admission updated, and the
  rounds worker now survives a failed round (logged, retried next tick) instead
  of dying on the first transient error. The claim-1 acceptance is demonstrated
  end-to-end on the production assembly in
  `internal/reconcile/conformance/storebacked_e2e_test.go`: seeded divergence, a real
  scheduled round, a witness naming exactly the differing subset, offline
  verification from the recorded event alone, and remediation authorized only
  after in-signer plan verification. Boundaries, stated exactly: the vault,
  cloud-kms and kmip reducers still have nil sources — scheduling them fails
  observation closed and logs, it does not fabricate an authority — and
  inventory rows with no captured DER cannot participate in the comparison
  (no issuer bytes to derive the shared identity from), so a metadata-only
  scanner import is invisible to this pair of authorities.
- CA-key retirement (H4): `GET /api/v1/ca/keys/{id}/retirement` and
  `trstctl ca keys retirement` list the dependents standing between a CA key and
  destruction. An operator with `keys:write` can submit the exact final dependency
  epoch through `POST /api/v1/ca/keys/{id}/retirement`, the explicit-confirmation
  lifecycle control, or `trstctl ca keys retire <id> --force -f <request.json>`.
  The wire request contains only `final_epoch` and `confirm_irreversible`: the
  server fixes the policy class to `ca-signing-key` and derives the sole approval
  identity from the authenticated principal, so a caller cannot name a weaker
  class or impersonate another approver.
  The request only appends a frozen evidence command and its same-transaction
  outbox intent. The outbox worker replays that frozen event prefix and calls
  `GatedDestroy` over the signer UDS; the API process never receives a private key
  or a key-backend destruction handle. Incomplete evidence produces a signed
  refusal and leaves the key alive. Complete evidence destroys the signer-local
  handle first, then mints one full public record bound to the command ID, tenant,
  stable key ID, final epoch, required/completion/revocation digests, quorum and
  audit head. Both outcomes are immutable events and rebuild the tenant-RLS
  projection after restart. The console displays signed refusals and downloads the
  complete destruction record for offline verification.
  VDEC attaches in every build and remains fail-closed on missing evidence.
  If the tenant has no recorded dependency state for the requested key, the
  checklist returns HTTP 404 with an explanation to verify the key ID and collect
  dependency evidence. This does not establish whether the key itself exists;
  another tenant's dependency state is never disclosed. A recorded history whose
  dependents are all accounted for still returns HTTP 200 with its actual counts.
  A missing dependency report is not an empty outstanding list: an empty list
  reads as "this key has no dependents", which must never authorize an irreversible
  act on evidence nobody gathered. Served on the CA hierarchy console's lifecycle
  tab, where retirement belongs beside rotation. Its selector is populated only
  from served, signer-backed CA authorities already marked `superseded` or
  `revoked`; it sends that authority's exact ID, while the API repeats the same
  precondition check. A failed checklist read renders an explicit unavailable
  state and no destruction control, never a reassuring zero.
- Incident fleet-reissue batch gates (H3): each batch's health gate is recomputed
  on read from THAT BATCH's own replacement identities, through the same
  verification summary D6's canary uses. It previously round-robined the run's
  gate list across batches (`gates[(index-1)%len(gates)]`), so a batch's gate
  described some other batch — worse than showing nothing, because during an
  incident it reads as per-batch evidence and the operator deciding whether to
  continue is exactly who would act on it. The verdict rules are unchanged and
  deliberately refuse to round up: any failed replacement fails the gate, and a
  single UNVERIFIED replacement keeps it `not_evaluated` rather than passed — a
  run that is 99% verified is a run with an endpoint nobody looked at. Only
  receipts paired with an accepted signed agent-job receipt count. Batches that
  are planned, queued, or halted keep `not_evaluated`, because a batch that never ran
  has nothing to verify and a halted one changed nothing; a read failure leaves
  the gate as it stands rather than inventing a verdict in either direction.
- Migration waves (H2): `internal/migration` is the generic ordered-cohort engine
  behind served CA rollover. `POST /api/v1/migrations/assess` remains a separate,
  read-only operation and reports UNKNOWNS separately from findings: a member with
  no observed trust store is not a member confirmed to have an empty one. A reviewed
  manifest then names one active signer-backed CA authority, ordered waves, exact
  deployed identities, exact enrolled host agents, and exact public trust-anchor
  paths. The server derives the public anchor from that authority; it never accepts
  an operator-supplied key or silently changes authorities after review.

  Execution is event-sourced and restart-safe. Each wave runs distribute public
  trust → signed readback → issue from the manifest authority against a host-generated
  CSR → deploy → signed live-listener handshake → advance. Both observations are
  gates, not progress labels: one missing receipt licenses no next action, one failed
  receipt stops forward publication, and later waves never enter the outbox. The
  failure automatically begins the newest-first inverse, including every member effect
  already published for the failed gate; signed receipts that arrive late are retained
  without restarting forward motion and their serialized inverse still runs. Pause
  stops new work from being published but cannot recall work an agent already leased;
  its signed result is retained and resume continues the same gate. Rollback restores
  and reverifies predecessor leaves newest wave first, projects the predecessor active
  and successor superseded in the same event transaction, then removes successor
  trust. A rollback failure halts on a durable attempt cursor and a manual retry gets
  fresh idempotent outbox identities. The exact-agent jobs, immutable aggregate,
  outbox effects, receipt evidence, and rollback cursor all survive PostgreSQL
  projection loss and event replay.

  Served through `/api/v1/migrations/runs` plus `/{id}/pause`, `/{id}/resume`, and
  `/{id}/rollback`, the matching `trstctl migrations` commands, SDKs, and the
  `/migration` console. Scope: executable membership is deliberately narrower than
  assessment today — one active internally issued DNS-only predecessor per identity,
  an enabled host-agent connector with `verify_address`, and an active host-role
  agent. Network-appliance, cloud-store, externally issued, IP/email/URI SAN, and
  offline-authority migrations are refused at start rather than represented as
  executable.
- Trust in the graph (H1): trust-store anchors agents collect are promoted from
  flat discovery findings into relationships — a `trust-store` node kind, `TRUSTS`
  (store → issuer, oriented the way impact travels) and `HOSTS` (resource → store).
  `GET /api/v1/graph/trust-stores/{id}`, `trstctl graph trust-stores`, and the
  Graph console's issuer detail answer "trusted by N stores across M hosts"; hosts
  are counted distinctly, because one machine running both an OS store and a JVM
  cacerts is two stores and one machine to visit. A store is its own node rather
  than a host attribute on purpose: a machine routinely carries several with
  DIFFERENT contents, so "is this CA trusted on host X" has no single answer.
  Scope, stated exactly: an authoritative store → issuer edge requires either the
  same certificate SHA-256 fingerprint or the same SPKI SHA-256 public-key
  identity. The SPKI path deliberately recognizes a cross-signed copy of the same
  CA key. A subject-name-only match is exposed separately as an unverified
  candidate and is excluded from authoritative store/host counts, blast-radius
  traversal, and automation; two roots can share a subject while holding different
  keys. Stores nobody has scanned do not appear, which is the honest answer rather
  than a reassuring one; a CA showing zero trusting stores means none have been
  observed, not that none exist.
- Third-party secret scanning: CI/CD log, container-registry, Slack, and Jira
  artifact scanning is served through
  `/api/v1/secrets/scans/third-party/{provider}/ingest` and the matching CLI.
  The contract intentionally accepts an operator-owned `artifact_path`; raw
  logs, registry metadata, chat exports, and issue exports stay outside trstctl
  storage — discovery stores only redacted rule/file/line/provider metadata.
  Native provider API polling, provider signature verification, artifact
  retention automation, and provider-native annotations remain architecture
  shortfalls.
- React console scale work: cursor-aware inventory pages consume `next_cursor`
  and accumulate additional pages on explicit operator action. Every
  DataGrid-backed large table switches to a bounded, overscanned DOM window
  after 100 loaded rows; the certificate inventory has a focused multi-page
  acceptance test proving the second cursor is sent and that scrolling
  replaces, rather than appends, rendered row nodes.

## The React web console: served by the binary

The React 18 + Vite + shadcn/ui single-page app (F12) is the real embedded
artifact the running binary serves:

- The shipped binary serves the real console. The release pipeline builds the
  SPA into the binary's embedded asset bundle; the built bundle is committed,
  so even a plain control-plane build serves the real console at `/` — hashed
  `/assets/index-*.{js,css}` and an `index.html` that references them, not the
  old "not built" placeholder. A test boots the served handler over the real
  embedded bundle and fails if it ever regresses to the placeholder, and a
  release gate (`TRSTCTL_REQUIRE_BUILT_UI=1`) blocks a release that would embed
  the placeholder.
- Generated frontend↔backend contract. The frontend's API types are generated
  from the served OpenAPI contract, not hand-duplicated: the generator emits
  TypeScript types from the served API spec, and the API client re-exports
  those types so a backend field add/rename/remove that isn't regenerated fails
  the TypeScript build. A CI regenerate-and-diff gate fails the build on drift,
  so a frontend/backend status mismatch can no longer recur silently.
- Operational console routes. First-class routes, nav entries, typed API
  wrappers, and route-test coverage cover the GA operator slice: Profiles
  (`/profiles`), Graph (`/graph`, inventory + blast-radius query), Audit
  (`/audit`, event list + evidence export in JWS/NDJSON/CSV/Splunk-HEC/Sentinel),
  dual-control approvals from the
  identity table, core incident execution (`/incidents` — replacement
  issue/deploy, fleet reissuance, revocation queue, connector receipt,
  rollback evidence, remediation playbooks, response dispatch, sealed audit
  bundle), and Product help (`/assistant`) with grounded questions, cause
  investigation, and on-demand read-only MCP tools. Deliberately
  API-only surfaces stay labeled until they get their own UI, including the
  bounded break-glass reconciliation workflow — a UI boundary, not a claim
  that the underlying API is library-only.
- Console UX hardening. A destructive-transition confirmation (revoke/retire
  require an explicit, credential-named confirm dialog) and
  429/`Retry-After` handling (a concrete "retry in Ns" hint) are served and
  tested. Cursor-based pagination and bounded list virtualization are also
  served: the client carries `next_cursor`, accumulates rows, and the shared
  DataGrid renders only the visible window plus overscan for large result sets.

## Interactive OIDC, SAML, and LDAP / Active Directory browser login & sessions: served by the binary

The OIDC authorization-code login, SAML 2.0 Service Provider login, and LDAP /
Active Directory bind login + sessions are served by the running binary
(behind `auth.oidc.enabled`, `auth.saml.enabled`, and `auth.ldap.enabled`).
OIDC remains in the Free core; tenant SAML and LDAP require Enterprise SSO,
included in Enterprise and inherited by Provider. An enabled tenant SAML, LDAP
or SCIM configuration without that implementation refuses startup with
`SAML, LDAP and SCIM login require an Enterprise licence.` Core-only builds
cannot attach it. The separate Provider operator authentication plane is unchanged.
OIDC mounts `/auth/login` and `/auth/callback`; SAML mounts
`/auth/saml/login`, `/auth/saml/acs`, and `/auth/saml/metadata`; LDAP mounts
`POST /auth/ldap/login`; all three share `/auth/me` and `/auth/logout`. OIDC
verifies the id_token's signature, issuer, audience, nonce, and temporal
claims (exp/nbf/iat). SAML verifies signed POST-binding assertions against
configured IdP metadata through the same isolated cryptography boundary. LDAP
binds the user, then performs a configured group search; production
directories should use `ldaps://` — plaintext `ldap://` is accepted only for
loopback development fixtures. All paths set an `HttpOnly` +
`SameSite=Strict` session cookie (marked `Secure` whenever the control plane
serves TLS) plus a double-submit CSRF token, authorizing API calls under the
same RBAC and per-tenant database-isolation scoping as an API token;
mutations on the cookie path require the CSRF header. When browser sign-on is
disabled the binary authenticates with scoped API tokens only, exactly as
before; an enabled-but-misconfigured OIDC, SAML, or LDAP block **fails closed
at startup**.

- Per-user → tenant mapping is served. Each authenticated user is mapped to
  its real tenant at session issue — by a configurable OIDC claim or SAML
  attribute (`auth.oidc.tenant_claim` / `auth.saml.tenant_claim`), by an IdP or
  LDAP group → tenant table, or by an explicit subject/claim/group → tenant
  mapping (`auth.*.tenant_mappings`) — instead of collapsing every browser
  user to one tenant. A user that maps to no tenant is rejected (the login
  fails closed, never minting a session in a fallback tenant unless an
  operator explicitly opts into `allow_default_tenant`). Per-tenant database
  isolation then confines each session to its mapped tenant, so two SSO users
  in different tenants see only their own data via the served API. The legacy
  single default tenant is retained only as that opt-in fallback. This is the
  served half of the defense against cross-tenant leakage; a freshly
  logged-in user still cannot self-issue (issuance stays behind the served
  RA/policy gate and the requester scope excludes `certs:issue`).

## SCIM 2.0 provisioning: served by the binary

The SCIM 2.0 provisioning surface requires Enterprise SSO and is served by the
running binary behind `auth.scim.enabled`. It mounts `GET /scim/v2/ServiceProviderConfig`,
`/scim/v2/Users`, and `/scim/v2/Groups`; bearer tokens are loaded from
configured token files, hashed, and bound to one tenant before a request body
is trusted. SCIM user create/update/PATCH writes the same tenant-member event
path used by RBAC. SCIM `active:false`, DELETE, or group removal changes the
projected tenant-member roles, so the next browser-session API request sees
the new authorization result.

Current SCIM limits are deliberate and fail closed: SCIM Bulk is not
implemented; password management and password-change flows are not
implemented; SCIM groups do not create new custom roles (a group's
`displayName` or id must match a configured RBAC role such as `admin`,
`operator`, `viewer`, `auditor`, or `ra-officer`). Directory writeback is not
implemented. Token rotation is operator-managed: write a new token file and
restart the control plane so the new hash loads.

### Unified NHI inventory

Unified NHI inventory (CAP-NHI-02) is served as metadata, not credential
material. `GET /api/v1/nhi/inventory` requires `nhi:read` and merges
tenant-scoped identities, certificate inventory, API-token metadata, enrolled
agents, and discovery findings into one normalized inventory across
certificates, SSH keys, secrets, API keys, OAuth apps, tokens/PATs, service
accounts, IAM roles, webhooks, workload IDs, and agents. It does not return
secret values, private keys, raw API tokens, client secrets, or other
credential bytes; use the specific governed secret/issuance endpoints for
those flows.

Malicious / abused OAuth-grant detection (CAP-ITDR-03) is served from metadata
exports. `oauth_grant` Discovery sources emit normal `oauth_grant` inventory
findings and, when the export contains concrete abuse evidence, additional
`oauth_grant_abuse` findings tagged `CAP-ITDR-03`. The detector stores
provider threat signals, reason codes, evidence refs, and source event ids
only; OAuth client secrets, access tokens, and refresh tokens are rejected.
Live IdP/SaaS grant revocation and provider-side enforcement remain
connector/remediation work rather than being hidden inside discovery.

### AI, RCA, and MCP surface

The AI surface — model adapter (F76), grounded RCA / NL query (F75/F77), and
the guarded MCP tool server (F78) — is served, mounted under `/api/v1/ai/*`
and `/api/v1/mcp/*` (off by default — `ai.enable_api` — and fail-closed when
off, so an upgrade does not silently expose it):

- `POST /api/v1/ai/query` answers a typed semantic / natural-language query
  over the tenant's own data surfaces (owners, certificates, the credential
  graph, the CBOM, the event log), grounded and citing real records (F75).
- `POST /api/v1/ai/rca` answers a grounded root-cause / NL question from
  cited real records gathered through the tenant-then-RBAC scoping seam,
  preferring "insufficient evidence" to a guess (F77).
- `GET /api/v1/mcp/tools` + `POST /api/v1/mcp/tools/{tool}` expose the
  tenant-scoped MCP tools an external AI agent can list and invoke (F78).
  Investigation tools are read-only by default; guarded write tools
  (`issue_certificate`, `rotate_certificate`) appear only when
  `TRSTCTL_AI_MCP_WRITE_TOOLS=true`, each still requiring `certs:issue`, an
  `Idempotency-Key`, and emitting `mcp.tool.write`.

Every route is auth-gated (API token or session, `graph:read`), tenant-scoped
(the tenant is the authenticated principal's, never a request field), rate
limited, and injection-inert (a hostile string in a record is inert, cited
data, and cannot by itself trigger a write). The AI model is air-gapped /
opt-in by default — no model is configured, so grounding and citations work
and nothing phones home; when an operator opts into a cloud/local model,
every prompt crosses a redactor plus a residual-entropy refuse-gate before
any egress, so no key/secret material leaves to a model (secret bytes live
only in wipeable, zeroed memory and never reach a prompt). Proven end-to-end
by acceptance tests (grounded NL-query/RCA citing real records, cross-tenant
denial, injection-inert + secret-redacted, MCP list+invoke).

### Secrets and identity frameworks

**Transit keys are sealed at rest; multi-replica sharing is still open.** The
transit (encryption-as-a-service) keyring is persisted KEK-sealed under
`transit.keyring_dir`: AEAD, HMAC, and signing key material is sealed with the
deployment KEK, written atomically, and re-locked into protected memory on load
(AN-8). A checkpoint runs after every create and rotate, so a restart between
minting a key and the next flush cannot lose it, and a failed checkpoint fails
the mutation rather than handing back a key that disappears later: the
unpersisted key (or the unpersisted new version) is rolled back out of the
in-memory ring and its material wiped, so nothing can encrypt under it and a
retry succeeds instead of reporting that the key already exists.

Two properties bound what this gives you:

- **Persistence requires a KEK.** With no deployment KEK (or no configured
  directory) the keyring stays in memory only and keys do not survive a restart,
  exactly as before. Key material is sealed at rest or it is not written at all —
  there is no plaintext fallback. The directory is set with `transit.keyring_dir`
  in the config file or `TRSTCTL_TRANSIT_KEYRING_DIR` in the environment, and the
  effective value is echoed by `-check-config` as `transit.keyring_dir`; it is
  empty by default, so durability is an explicit operator decision.
- **A keyring that cannot be opened refuses to start.** If the sealed file exists
  but the KEK cannot open it, the control plane fails to start rather than coming
  up with an empty keyring: starting anyway would mint fresh keys and silently
  turn every existing ciphertext into garbage.

Still open: **a multi-replica deployment does not share the keyring.** Each
replica seals its own file, so a decrypt routed to a replica that did not serve
the encrypt still fails. Sharing the keyring across replicas — and event-sourcing
the create/rotate lifecycle facts alongside the sealed material — is tracked as
follow-up work.

**Private-egress allowlist entries must be exact network prefixes.** Every
`allow_private_cidrs` / `private_egress_cidrs` surface (connectors, Rekor
code-signing, incident notifications, managed keys, secret integrations,
external CAs, ServiceNow bindings) now refuses an entry whose host bits are
set (for example `10.1.2.3/8`) or that covers every address (`0.0.0.0/0`,
`::/0`) at configuration load, naming the offending value. Such entries used
to pass validation on most surfaces and were then silently ignored at dial
time, so private egress failed as SSRF-blocked with nothing explaining why.
**Migration:** operators whose entries currently carry host bits should write
the network address the entry already effectively meant (for `10.1.2.3/8`,
write `10.0.0.0/8` — or, if a single host was intended, `10.1.2.3/32`). The
dial-time guard remains as defense in depth and now logs and counts any entry
it skips.

**CMP binds every CSR to the authenticated protection identity by default.**
A PKIMessage's protection identity must chain to the operator-configured
anchors (`protocols.cmp_client_trust_anchor_file`), and — new — the CSR's
subject and SANs must be asserted by that identity, so a device credential can
renew only itself and a stolen credential stays one device in blast radius.
RFC 4210 registration-authority enrollment on behalf of third parties remains
available as an explicit opt-in: `protocols.cmp_allow_ra_enrollment` in the
config file or `TRSTCTL_PROTOCOLS_CMP_ALLOW_RA_ENROLLMENT=true` in the
environment (echoed by `-check-config` as
`protocols.cmp.allow_ra_enrollment` when CMP is enabled). Cross-identity
requests under the default are refused with a distinct audit reason
(`csr not bound to protection identity`), so an operator can tell an
impersonation attempt from a malformed message. Deployments that relied on the
previous unbound behavior must set the RA opt-in deliberately on upgrade.

Six of six secrets/identity frameworks are mounted on the running binary
under `/api/v1/secrets/*` (off by default — `secrets.enable_api` — fail-closed
when off, requiring a KEK when on):

- Auth-method framework (F58) backs `POST /api/v1/secrets/login` — a machine
  presents a token, Kubernetes SAT, AWS IAM signed `GetCallerIdentity`
  request, GCP identity JWT, Azure workload JWT, generic OIDC token, or
  generic JWT and receives a scoped, tenant-scoped session (distinct from the
  human OIDC SSO bridge). Token credentials MAC-bind tenant, audience,
  principal, and expiry; JWT methods require a tenant claim or tenant-pinned
  config; AWS IAM is tenant-pinned through allowed account/ARN config.
  `X-Tenant-ID` is only a lookup hint — mismatched tenant headers are rejected.
- Application secrets SDK (F64) backs the secret store
  `POST/GET/PUT/DELETE /api/v1/secrets/store/...` (create, read, rotate,
  delete), `GET /api/v1/secrets/store/{name}?resolve=true` (`${secret.path}` reference
  expansion with cycle rejection), `GET
  /api/v1/secrets/store/history/{name}?version=N` (read one prior sealed
  version), and `POST /api/v1/secrets/store/recover/{name}` (point-in-time
  recovery). Values are sealed at rest under the KEK. `trstctl-cli run --secret
  ENV=path -- <cmd>` wraps the same read path, injecting values only into the
  child process environment. Bulk import is not served: the retained compatibility
  route `POST /api/v1/secrets/store/import` returns `501` without writing, the web
  console shows a disabled disclosure, and the CLI exposes no import command until
  an atomic event-sourced batch command exists.
- The Vault/OpenBao compatibility shim backs the common migration paths
  `GET /v1/auth/token/lookup-self`, KV mount-discovery preflight for
  `secret/`, `POST/PUT/GET /v1/secret/data/{path}`, and
  `POST/PUT /v1/pki/sign/{role}` for requester-generated CSRs, and the deprecated
  `POST/PUT /v1/pki/issue/{role}` server-keygen path for stock `vault` CLI token lookup, KV v2
  put/get, and PKI issue — deliberately a subset over the native secret store
  and dynamic PKI secret; it does not implement Vault mount management, ACL
  policy authoring, cubbyhole, response wrapping, transit paths, or every
  Vault/OpenBao secret engine.
- Dynamic secrets (F65) are served when tenant providers are configured:
  `POST /api/v1/secrets/leases`, `GET /api/v1/secrets/leases/{lease_id}`,
  `POST /api/v1/secrets/leases/{lease_id}/renew`, and
  `POST /api/v1/secrets/leases/{lease_id}/revoke` — issue returns the backend
  credential once, later reads return metadata only, renew extends an active
  lease, and revoke closes it; the leaseworker expires leases through an
  outbox-backed backend revocation queue. `buildRunDeps` constructs a
  tenant-bound registry for `postgresql`, `mysql`, `mongodb`, `aws-iam`,
  `gcp-iam`, `azure-entra`, `kubernetes`, and `redis`. Issuance is
  outbox-only: the pending event and sealed command commit first, provider
  retries reuse one stable lease identity, and only the authorized issue
  response opens the sealed credential. The acceptance proof logs in with each
  generated credential, rotates it, revokes both copies, and verifies both are
  rejected afterward.
- Secret rotation (F37) backs `POST /api/v1/secrets/rotations` for worker-queued
  `connector:<target>` secret-sync handoffs. Concrete PostgreSQL, MySQL, and AWS
  IAM four-phase engines remain library/configuration components only: manual
  static-provider and `dynamic-lease:<provider>` requests return `503` before
  any stage, issue, cutover, delivery, verification, rollback, revoke, event, or
  outbox effect because those phase chains do not yet have one crash-recoverable
  worker receiver. Dynamic lease issue/renew/revoke remain separate served
  operations. Rotation `ttl_seconds` is a compatibility field only: a connector
  request that supplies it returns `400`, while static and dynamic-lease requests
  still return their cached request-bound `503` regardless of that field. New schedules accept
  only `connector:<target>`; static and dynamic schedule creation returns `503`.
  Historical non-connector schedules are marked `unsupported`, disabled, and make
  zero provider calls. Scheduled ticks bind each exact due edge to one durable,
  deterministic command before effects, execute at most 50 rotations while
  scanning at most 500 due rows, report every `approval_pending`,
  `command_in_flight`, `command_claimed`, or `config_revision_unanchored`
  deferral, and continue past row-local poison.
  A shared store/event/custody/integrity failure returns a cached `503` partial
  envelope; the same idempotency key replays it byte-for-byte without child
  execution, while a new key reconciles retained terminal evidence and continues.
  `delivery_failed` advances a connector schedule only after its canonical local
  version committed; generic `failed` never promotes `new_ref`. Verified terminal
  command rows are purged only after the schedule advanced, the exact event remains
  retained, and a newer command exists; the newest lineage fence and all claimed
  or ambiguous rows remain.
- PKI-as-a-secret / dynamic certificate leasing (F67) backs
  effect-free `POST /api/v1/secrets/pki/preview` and mutating
  `POST /api/v1/secrets/pki`. Preview and execution share the same subject, SAN,
  public-key, profile, and overflow-safe TTL validator. Preview signs nothing,
  writes nothing, makes no external call, returns no credential material, and
  reports structured CA/custody/revocation/audit prerequisites plus exact effects,
  recovery, verification, CLI/Vault parity, and a server-keyed request fingerprint.
  Supplying that fingerprint on execution makes a changed plan fail closed. The
  recommended `csr_pem` mode signs a
  requester-generated PKCS#10 request and returns only the certificate. The
  mutually exclusive `common_name` mode still returns a usable certificate and
  private key for compatibility, but is deprecated and fails before key generation
  unless its `issuance.server_side_keygen` receipt is durable. Both modes use the
  issuing CA in the out-of-process signer and record the serial on the served
  revocation pipeline so a revoked dynamic-secret cert stops validating.
- Secret sharing (F60) backs effect-free, value-free `POST
  /api/v1/secrets/shares/preview`, reviewed idempotent creation at
  `POST /api/v1/secrets/shares`, and atomic `.../redeem`. The server-keyed review
  fingerprint rejects a changed lifetime; an exact same-key retry returns the
  original one-time bearer rather than creating a duplicate. Redemption succeeds
  exactly once, and neither value nor bearer token enters the audit/event log.

Every served route is auth-gated (API token or session, `secrets:read` /
`secrets:write`) and tenant-scoped. Every mutation is idempotent (deduplicated by
`Idempotency-Key`) and recorded as immutable events; effect-free previews
intentionally create neither. Secret values are held
in wipeable, zeroed memory (never as a string), never logged, and never
returned beyond their design. Proven end-to-end by acceptance tests.

### Secret sync, Transit, and KMIP

Secret sync external stores (F68) — served when configured. The running
binary mounts `POST /api/v1/secrets/syncs` and
`trstctl-cli secrets syncs run`. A request reads one stored secret, writes a
sealed tenant-scoped outbox row before any external write, records immutable
sync intent, and returns metadata only. `buildRunDeps` constructs
tenant-bound targets for AWS Secrets Manager, GCP Secret Manager, Azure Key
Vault, GitHub Actions, GitLab CI/CD variables, Vercel project environment
variables, generic CI JSON endpoints, and Kubernetes Secrets, plus
first-class Terraform Cloud/OpenTofu Variables API and Vault KV v2 targets
(Terraform writes are workspace-scoped with category/sensitive metadata;
Vault writes use the KV v2 data/metadata paths and preserve version/CAS
semantics). Only the outbox dispatcher resolves the target credential and
writes externally. The acceptance proof enforces exact target authentication,
decrypts GitHub's X25519 sealed box in a separate receiver process, and
independently reads every destination value back. `GET
/api/v1/secrets/syncs/targets` shows the catalog and this installation's
configured targets.

AWS, GCP, and Azure targets independently opt into OIDC workload identity instead
of their static target credential. The matching
`aws_workload_identity`, `gcp_workload_identity`, or
`azure_workload_identity` switch is false by default, and workload-identity mode
rejects the provider's static credential fields rather than keeping a quiet fallback.
The served
`/api/v1/secrets/syncs/workload-identity-sources` API, CLI, and Secrets console
bind a tenant JWT/JWKS trust source, exact audience/subject, provider target, and
remote-key scope. Three thin, hand-written REST exchanges use one shared
`internal/cloudauth` minter: AWS calls `AssumeRoleWithWebIdentity`; GCP calls the
RFC 8693 STS endpoint and may then impersonate one service account; Azure calls the
Entra v2 token endpoint with the configured application client ID and Key Vault
scope. Azure's federated-credential binding accepts the already validated OIDC proof,
which the form sends unchanged in its JWT-bearer `client_assertion` field. trstctl
does not create another assertion, sign one with a certificate, or take custody of
an Entra certificate/private key.

Proof resolution, signature and exact-claim validation, exchange, locked
short-lived credential caching, and refresh happen only inside the bounded
secret-sync outbox worker. Air-gapped mode records `offline_disabled` before either
the token endpoint or target can receive a request, fails that delivery once, and
does not retry forever. The resulting GCP or Azure bearer is passed to the existing
hand-written `internal/secretsync` pusher; no vendor SDK or provider-specific cache
is added. For Azure this replaces the `azure-key-vault` sync target's static
`token_ref`. It does **not** replace
`TRSTCTL_MANAGED_KEYS_AZURE_BEARER_TOKEN(_FILE)`: those settings and
`internal/kms/azurekv` belong to the separate managed-key child-signer path.
`TestServedAzureFederatedOutboxTenantIsolationTokenRedaction` and
`TestServedAzureFederatedAirGapIsTerminalWithoutNetwork` prove the served Azure
exchange, target readback, tenant isolation, token redaction, and zero-network
air-gap result.

Related read-only posture routes: `GET /api/v1/secrets/cloud-secret-managers`
(CAP-SEC-04 — read-only `cloud_secret` discovery for AWS/GCP/Azure/Vault, plus
sealed-outbox sync for AWS/GCP/Azure); `GET /api/v1/secrets/kubernetes-operator`
(CAP-SECR-04 — the `TrstctlSecretSync` controller reconciles secret references
into Kubernetes `Secret.data` and patches pod-template annotations for
reload); `GET /api/v1/secrets/workload-injection` (CAP-SECR-05 —
`TrstctlSecretInjection` patches `Deployment`/`StatefulSet`/`DaemonSet` pod
templates with the shipped `trstctl-agent --secret-inject` sidecar, a
memory-backed shared volume, app mounts, optional `valueFrom.secretKeyRef`
entries, and status/content-hash annotations; the operator reads only Secret
metadata, and secret bytes never appear in API/status/audit/pod-template
metadata); and `GET /api/v1/secrets/unvaulted` (CAP-SECR-07 — combines
configured repository/third-party scan sources, redacted `leaked_secret`
findings, AWS/GCP/Azure/Vault discovery visibility, and vault-augmentation
sync targets). Arbitrary webhooks intentionally remain the generic JSON
target; Terraform/OpenTofu and Vault no longer depend on it. If a target is
not configured, the route returns `503` rather than attempting an external
call.

Transit/KMIP (F66) — served, with a bounded OASIS KMIP 1.4 profile. The
running binary mounts `/api/v1/transit/*` and the `trstctl-cli transit`
command group for tenant-scoped key create/rotate, complete metadata-only
version history, effect-free sealed-restore/KMIP posture, encrypt/decrypt,
rewrap, HMAC, sign, and verify. The Secrets console exposes the same workflow,
filtered immutable receipts, and explicit no-auto-retry recovery. Transit keys
never leave the process as exportable
material, request plaintext uses wipeable `[]byte` buffers, keyrings are
zeroized on shutdown, and mutating operations emit immutable `transit.*`
audit events. The binary also mounts an opt-in raw KMIP mTLS listener when
`protocols.kmip.enabled` is true and `protocols.kmip.tenant_id`,
`protocols.kmip.cert_file`, `protocols.kmip.key_file`, and
`protocols.kmip.client_ca_file` are configured. That first served KMIP
profile is intentionally bounded: it accepts verified client certificates,
decodes TTLV with frame-size, field-count, and nesting-depth caps, serves
Query and DiscoverVersions, AES-256 `SymmetricKey` Create/Register/Get
(including AES-GCM wrapped Get/Register), plus Locate/Revoke/Destroy over the
wire for stock clients, records `kmip.object.created`, `kmip.object.revoke`,
and `kmip.object.destroyed`, and zeroizes in-memory key material on
rekey/destroy/shutdown. Appliance-specific templates and tenant self-service
listener management remain deliberate product-scope boundaries. Production
Transit remains conditional on a protected keyring directory and deployment
KEK; the KMIP listener additionally remains conditional on its licensed runtime,
one tenant binding, and configured mTLS trust.

## Authorization policy gates and ABAC overlays: served by the binary

The RBAC guard, ABAC deny overlay, OPA/Rego default-deny policy gate, RA scope
split, and dual-control approval are enforced by the running binary, not just
in library code. The RBAC guard runs on every guarded API route. When
`auth.abac.enabled` is set, the ABAC deny overlay runs after RBAC on guarded
routes using request, actor, environment, and time attributes; on the served
lifecycle transition (`POST /api/v1/identities/{id}/transitions`) for issue,
deploy, and revoke, trstctl adds identity resource tags before the deny check.
The OPA/Rego lifecycle policy gate then gates issue/deploy/revoke fail-closed
before the orchestrator records the transition or enqueues the mint/revoke
effect. The gate is tenant-scoped under per-tenant database isolation,
recorded as immutable events, and runs on its own bounded worker lane so a
policy flood fast-rejects rather than starving other subsystems.

Registration-authority (RA) separation and dual-control approval are served.
The gate enforces the RA scope split: a privileged issue/revoke transition
requires the `certs:issue` authority, so a `certs:request`-only requester (the
`ra-officer`) cannot self-issue. When dual control is enabled
(`ca.policy.require_approval`), a privileged action is denied until a
distinct approver records an `issue`, `rotate`, or `revoke` approval via
`POST /api/v1/identities/{id}/approvals` (itself requiring `certs:issue`);
self-approval is rejected, backed by tenant-isolated approval-request and
approval records. This is the served half of the "loaded gun" defense — the
bootstrap token already withholds `certs:issue`; the served mint now enforces
the RA split and dual control too. The `/request` and `/approvals` console
pair is served for profile-bound certificate requests: it records
requester/profile/purpose metadata, keeps the request in `requested`, blocks
requester self-issue, accepts a distinct approval, and mints through the
signer-backed outbox. The remaining gap is a first-class `issuance_request`
API object with its own cancel/deny/expiry status; today that state is
represented by identity metadata plus the approval tables.

The OPA/Rego policy gate is default-deny on issue/deploy/revoke. With
`ca.policy.enabled` set, the served binary invokes the embedded policy engine
on every issue/deploy/revoke transition: the request is denied unless the
deployed Rego policy explicitly allows it (default-deny, fail-closed). The
policy input carries the action, `tenant_id`, the actor, and the bound
profile name, so an operator can enforce a real Rego document at runtime. A
non-compiling policy module is a hard startup error, an evaluation error
denies, and a saturated policy pool sheds with a 503 (never an allow). The
built-in base policy is default-deny, permits revocation, and requires a
bound certificate profile to issue/deploy (composing with the profile
enforcement below). Enforcement is off by default (`ca.policy.enabled=false`)
so an in-place upgrade does not silently start denying; the RA scope split is
enforced for privileged transitions regardless of this flag. Live policy
authoring, activation, listing, and rollback are served through
`POST /api/v1/policy/versions`, `GET /api/v1/policy/versions`,
`POST /api/v1/policy/versions/{id}/activate`, and
`POST /api/v1/policy/versions/{id}/rollback`; activation compiles the module,
records `policy.version.activated`, and only then installs it into the
running mutation gate.

The ABAC deny overlay is served. With `auth.abac.enabled` set, the served
binary compiles a `package trstctl.abac` Rego module at startup and evaluates
it after RBAC. It is deny-only: it cannot grant access that RBAC refused.
Every guarded route carries `input.permission`,
`input.resource.request.method`, `input.resource.request.path`, actor roles,
`input.env`, and UTC time fields; issue/deploy/revoke transitions also carry
identity metadata and flattened identity attributes such as
`input.resource.env` and `input.resource.tags.service` — supporting controls
like "prod certs may issue only during a change window." Bad Rego is a
startup error, evaluation errors deny with `403`, saturated policy workers
return `503`, and decisions are recorded as `policy.abac.decision` events.
Candidate policy dry-runs are tenant-facing through `/api/v1/policy/dry-run`
and the `/policy` workbench.

Independently of the policy flag, when a default certificate profile is bound
(`ca.default_profile`) the served mint validates the request against the
active profile version and rejects an out-of-profile request before signing
(an `issuance.profile_evaluated` deny event) — so the served mint is
profile-gated, not ungated.

Regulated CA governance mode is one coherent posture switch. Previously the
policy gate, four-eyes dual control, the bound default profile, revocation
publication, and FIPS were each enabled independently, with no single mode
that refused to start unless they were all coherently present — a compliance
deployment could half-enable the posture and silently drop a control. With
`ca.governance_mode=regulated` the running binary fails startup unless all of
the OPA policy gate (`ca.policy.enabled`), distinct-approver four-eyes dual
control (`ca.policy.require_approval` with a `>= 2` threshold), a bound
default certificate profile (`ca.default_profile`), revocation publication
(`ca.crl_distribution_points` and/or `ca.ocsp_servers`), and — when
`ca.require_fips` is declared — an active FIPS 140-3 module are present
together, each with an actionable error. A complete regulated config boots;
the default (`standard`) posture imposes no coupling. The switch is enforced
in the served startup/config validation path, where the FIPS power-on
self-test already asserts the module when required. See
[configuration → regulated CA governance mode](configuration.md#regulated-ca-governance-mode).

## Plugin isolation: first-party in-process, third-party sandboxed

This is a deliberate, documented trust boundary, not an accident.

- Shipped first-party CA and connector integrations run as trusted in-process
  Go code; they are not sandboxed through the WASM host. Their blast radius
  if one is defective is the control plane's address space: the database
  connection pool (confined to the tenant by per-tenant database isolation)
  and the signer client handle (it can request signatures), but not the CA
  private key, which stays in the separate signer process. They are
  mitigated by code review, the conformance suite, the connector SDK's
  capability-scoped sandbox facade, and per-subsystem bounded worker lanes.
- The WASM plugin host (wazero) is real and is the isolation boundary for
  third-party plugins. A loaded plugin has no ambient capabilities and only
  the host functions its grant permits; the host holds no database pool or
  signer handle; and a deliberately misbehaving plugin is proven contained
  by test. Migrating the first-party integrations onto it is future work.
  See the [plugin trust model](security/threat-model.md).
- Plugin extensibility is served by the binary. The WASM plugin host is
  wired into the served control plane: when `plugins.enabled` the running
  binary loads operator-supplied CA plugins from `plugins.ca_dir` and
  connector plugins from `plugins.connector_dir` (or the legacy connector
  alias `plugins.dir`). A signed CA plugin is listed under
  `GET /api/v1/external-cas` and issues through
  `POST /api/v1/external-cas/{id}/issue`; a signed connector plugin routes
  served `connector.deploy` work through the plugin's capability sandbox (the
  same capability-grant model the connector SDK uses) — tenant-scoped under
  per-tenant database isolation, recorded as immutable events, on the
  plugin's own bounded worker lane. The plugin runs in its own wazero runtime
  with no database pool or signer handle, an operation outside its grant is
  denied at runtime, and the surface is off by default. The shipped
  first-party CA/connector integrations still run as trusted in-process Go
  (see above); migrating those built-ins onto the host remains future work.
- Served plugins are signature/provenance-verified. The served loader admits
  a `.wasm` module only after its detached Ed25519 signature verifies
  (through the single isolated cryptography path) against the
  operator-configured trusted-key set (`plugins.trusted_key_files`), with an
  optional content-digest pin (`plugins.pinned_digests`). An unsigned,
  wrong-key, byte-tampered, or unpinned module is refused and the binary
  fails closed at startup — it never instantiates an unverified plugin. A raw
  unverified load path remains only for the in-process/conformance path; the
  served surface always runs the provenance gate first and keeps the wazero
  sandbox as defense-in-depth.

## Protocols

- ACME server with ARI: all three domain-validation challenges are validated
  for real, each failing closed — HTTP-01 (RFC 8555 §8.3), DNS-01 (§8.4, the
  `_acme-challenge` TXT digest), and TLS-ALPN-01 (RFC 8737, the `acme-tls/1`
  `id-pe-acmeIdentifier` handshake) — behind a multiplexer with an automatic
  method selector (wildcards → DNS-01, no inbound `:80` → TLS-ALPN-01, else
  HTTP-01). The prior accept-everything validator has been removed from the
  production build (it survives only in the test binary). A DNS-01 solver
  with a reference provider and conformance harness ships for the publish
  side. A real RFC 8555 client conformance suite exercises HTTP-01 end to end
  (the production validator fetches the published key authorization,
  multi-SAN issuance, a wrong key authorization fails closed), and the same
  protocol-conformance routine runs as a differential against Pebble (the
  reference test ACME CA) in CI — so a divergence from the reference surfaces
  as a failure. Hosted DNS provider coverage is served through the DNS-01
  provider catalog (`GET /api/v1/acme/dns-01/providers`): Route 53,
  Cloudflare, Google Cloud DNS, Azure DNS, RFC 2136, webhook, NS1, Akamai,
  UltraDNS, and acme-dns; the catalog exposes secret-reference fields and
  capability grants, not raw provider tokens. Tenant DNS-01 provider configs
  are served through `POST/GET/PUT/DELETE /api/v1/acme/dns-01/provider-configs`,
  and `POST /api/v1/acme/dns-01/preflight` evaluates delegation, TXT
  propagation, live CAA, method, and wildcard policy before issuance. Served
  ACME DNS-01 challenge acceptance checks live CAA before any DNS write, then
  publishes and cleans through `acme.dns01.present` / `acme.dns01.cleanup`
  outbox rows using tenant provider configs and secret-reference-backed
  credentials. Wildcard X.509 identity issuance requires an explicit
  blast-radius acknowledgment and `validation_method=dns-01`; deployed
  wildcard identities renew through the lifecycle scheduler's `ca.renew` path
  with rotation evidence. The ACME server is served by the running binary:
  it is mounted on the control-plane TLS listener at `/directory` +
  `/acme/...` and brokers issuance through the orchestrator-backed path —
  signed in the isolated signer (so the CA key never enters the API
  process), tenant-scoped, recorded as immutable events, idempotent
  (deduplicated by `Idempotency-Key`), and profile-gated. A stock
  `golang.org/x/crypto/acme` client with an ECDSA account key drives the
  served handler end to end (new-account → new-order → http-01 → finalize)
  and downloads a real, signer-issued certificate; a served acceptance test
  asserts the cert verifies and a `certificate.recorded` event exists, then
  revokes via ACME `revokeCert` and asserts the served OCSP responder
  returns *revoked*. The directory advertises the mandatory `revokeCert` and
  `keyChange` resources, and the server accepts ECDSA and Ed25519 account
  keys (not only RSA). Enable it with `protocols.acme.enabled` plus
  `protocols.acme.tenant_id`; it activates only when an issuing CA is
  provisioned and fails closed otherwise. The Protocols console now exposes the
  tenant-scoped, read-only ARI publication and scheduler-consumption posture.
  Roadmap residual: a dedicated ACME admin console for account/order/challenge
  drilldown, revocation operations, and richer client setup controls remains
  outside the F5 GA-served protocol denominator.
- **External account bindings are authorizations, not door keys.** RFC 8555
  §7.3.4 EAB proves an ACME account key was pre-authorized out of band. The
  server used to verify that proof and discard the key id, which made every
  admitted account identical: nothing recorded which credential let it in, so
  nothing could scope what it asked for next, count what it had taken, or stop
  one credential without stopping all of them. An account now remembers its
  `kid` — in its state event, so it survives a replay — and every order under
  that account is checked against that credential's policy. A credential may
  carry allowed identifiers (exact names or `*.suffix`, which covers the apex
  too), an order quota, and a validity window; an out-of-scope identifier,
  an exhausted quota, or a closed window refuses the order fail-closed, names
  the cause, and records an `acme.eab.order_denied` event. A single out-of-scope
  identifier refuses the whole order — issuance is granted or it is not.
  `GET /api/v1/acme/eab-credentials` serves each credential's scope, quota,
  window, and live accounts-bound / orders-created / orders-denied counters, and
  `POST /api/v1/acme/eab-credentials/{kid}/disable` (and `/enable`) stops or
  resumes new accounts and orders under one credential at runtime. Disabling is
  a closed tap, not a revocation: certificates already issued under the
  credential stay valid. The Protocols console shows the same list and carries
  the disable action.
  What is **not** served: the policy lives in `protocols.acme_eab.keys[]`
  configuration, and **rotation is a configuration operation** — add the new key
  id, then disable the old one here while clients migrate. trstctl does not mint
  external account credentials over the API, because that would mean returning a
  shared MAC secret in a response body; the HMAC key stays byte-backed in locked
  memory where configuration put it and appears in no served response, in any
  encoding. Binding a credential to a certificate profile is also **not**
  served: the ACME server does not select profiles — that decision is made at
  the issuance seam — so a per-credential profile setting would be policy that
  nothing reads. The served disable verb cannot re-enable a credential that
  configuration disables; config is the floor.
- EST (RFC 7030), SCEP (RFC 8894), CMP (RFC 4210/6712), the SPIFFE Workload
  API, and the SSH CA issuance servers are served end-to-end by the running
  binary, each behind the same issuance seam as the API mint: signed in the
  isolated signer, tenant-scoped, recorded as immutable events, idempotent,
  and profile-gated:
  - EST at `/.well-known/est/...` (Bearer-API-token authenticated on top of
    TLS). The challenge is emitted by the configured authenticator: the served
    tenant route advertises Bearer plus `certs:request` and returns bounded RFC
    6750 `invalid_request`, `invalid_token`, or `insufficient_scope` results,
    while BasicAuthenticator continues to advertise Basic. The conventional
    uppercase header spelling and a strict libest token wrapper keep the pinned
    challenge-driven reference client interoperable without changing ordinary
    raw Bearer behavior. SCEP at `/scep`, CMP at `/cmp` — mounted on the control-plane mux
    and exercised by served round-trip acceptance tests (a stock
    base64-PKCS#10 EST enroll, a CMS-enveloped SCEP `PKIOperation`, a CMP
    `p10cr`) that each download a real, signer-issued certificate verifying
    against the served CA and assert a `certificate.recorded` event in the
    tamper-evident log. SCEP/CMP use a sealed RSA *transport* identity at
    `protocols.ra_key_file` for CMS (deliberately not the CA key, which stays
    in the isolated signer); keep that file on shared persistent storage in
    HA so cached clients survive restarts and rolling deploys.
  - The SPIFFE Workload API is served as a gRPC service on a Unix domain
    socket (`protocols.spiffe.enabled`), so a `spiffe-helper`/go-spiffe/Envoy-SDS
    client dials the socket and fetches X.509-SVIDs, JWT-SVIDs, X.509
    bundles, and JWT bundles. X.509-SVIDs are signed through the isolated
    signer; JWT-SVIDs use the signer-backed JWT handle and the served
    `ValidateJWTSVID` RPC validates them against the served JWT bundle. A
    served acceptance test drives the SPIFFE Workload API wire protocol
    (with the mandatory `workload.spiffe.io` metadata) over the socket and
    validates both SVID families. A required CI job also runs stock
    go-spiffe and stock `spiffe-helper` against that served socket;
    go-spiffe is a test-only dependency so the served binary does not take a
    new runtime dependency for the proof.
  - Host-served Workload API (B3): a host agent started with
    `--workload-api-socket` serves the same Workload API on its OWN machine, for
    the workloads that run there. It attests each caller from the kernel's record
    of the connecting process (SO_PEERCRED on Linux, LOCAL_PEERCRED on darwin) and
    renders SPIRE-shaped `unix:uid:`/`unix:gid:`/`unix:path:` selectors; a
    platform with no peer-credential mechanism REFUSES to serve rather than
    issuing without attestation. The SVID key is generated on that host and only
    its public half travels: the control plane signs an SVID for a key it has
    never seen, over the `FetchWorkloadSVID` node API on the agent channel.
    Authorization is per node, not per agent-fleet: a registration entry carries a
    `ParentID` naming the node permitted to deliver it, taken from the certificate
    the agent authenticated with, so an agent that misreports selectors reaches
    only the workloads on its own machine. An entry with NO `ParentID` is
    deliverable by no agent at all and stays on the control plane's socket — so a
    forgotten field refuses rather than widening who may impersonate a workload,
    and scoping an entry moves it rather than duplicating it.
    SCOPE, stated exactly: darwin reports uid and gid but not the peer's pid, so
    `unix:path:` selectors are unavailable there and an entry requiring one will
    not match on a darwin host. The control plane's own socket is retained for one
    release and now emits a `spiffe.workload_api.local_socket_used` audit event on
    every issuance, so an operator can see which workloads have not yet moved
    rather than assuming they all have. The Workloads console reports, per host,
    whether it serves the socket, how many SVIDs it has issued since its agent
    started (a counter that resets on restart, and says so), and when it last
    reported — with "not reported" kept distinct from "not serving", because the
    first is fixed by upgrading an agent and the second by changing a flag.
  - Kubernetes TrustBundle distribution is served for public CA-bundle
    propagation: the agent reconciles cluster-scoped
    `TrustBundle.trstctl.com` resources, validates that `spec.caBundlePEM`
    contains only PEM `CERTIFICATE` blocks, writes namespace ConfigMaps, and
    marks status with target count, `bundleSHA256`, and Ready=True. The
    posture route `GET /api/v1/kubernetes/trust-bundles`, CLI command
    `trstctl-cli kubernetes trust-bundles`, and Workloads console disclose
    the CRD, RBAC, ConfigMap target, and residuals: the controller is
    poll-based, multi-cluster rollout still means applying the same
    CRD/object to each enrolled cluster, and Secret/projected-volume/CSI
    trust distribution modes are not claimed.
  - The SSH CA is served at `/ssh/...` (`protocols.ssh.enabled`): cert
    issuance plus the OpenSSH binary KRL at `/ssh/krl` (`sshd`'s
    `RevokedKeys` consumes it); a served acceptance test issues a user cert
    (verified with `ssh-keygen -L`), revokes it, and confirms the served KRL
    is the binary format. The SSH workflow API and CLI also serve status,
    explicit-confirmation trust-rollout evidence, attestation-gated user
    cert issuance, KRL revocation, and host retirement handoff. The SSH CA
    key lives in the isolated signer under its own handle constrained to
    SSH-cert signing.
  - The RFC 3161 TSA is served at `/tsa` (`protocols.tsa.enabled`): clients
    POST `application/timestamp-query` `TimeStampReq` bodies and receive
    `application/timestamp-reply` `TimeStampResp` bodies. The timestamping
    key lives in the signer under its own stable handle, the TSA certificate
    is persisted at `protocols.tsa_cert_file`, and the certificate carries
    the critical `timeStamping` EKU that stock OpenSSL enforces.
    The authenticated `POST /api/v1/protocols/tsa/qualification` surface and
    Protocols console panel review the exact tenant-bound mount, certificate,
    isolated signer, audit, and bulkhead posture without reading files, calling
    the signer/network, issuing a timestamp, or writing state. They name a secure
    repair for each failed gate and keep retry available. This is readiness only;
    stock OpenSSL over `/tsa` remains the wire and signature-verification proof.
  - The code-signing service is served by the running binary at
    `POST /api/v1/code-signing/sign` and `POST /api/v1/code-signing/keyless`
    when `code_signing.enabled` is configured. Tenant-scoped persistent keys
    and one-use keyless keys stay in the isolated signer process. GitHub
    OIDC identity is verified from tenant-pinned JWKS before the Fulcio
    SAN/issuer is derived. Rekor publication uses the transactional outbox
    and acknowledges only an exact HashedRekord receipt whose signed-entry
    timestamp verifies under the operator-pinned log key.

  Each protocol surface is gated by `protocols.<name>.enabled` and binds a tenant via
  `protocols.<name>.tenant_id`. All protocol toggles default off until an operator
  explicitly binds the served endpoint to a tenant; if a protocol is enabled without a
  tenant, startup validation fails before the route is exposed (per-tenant isolation
  forbids minting evidence into a blank tenant). All protocols activate only when an
  issuing CA is provisioned. HTTP protocol namespaces stay machine-only even while a
  toggle is off: `/directory` + `/acme/`, `/.well-known/est/`, `/scep`, `/cmp`,
  `/ssh/`, and `/tsa` return a stable `404 application/problem+json` response instead
  of falling through to the React console. Unknown `/directory/`, `/cmp/`, and `/tsa/`
  children are reserved too. The Protocols register does not infer availability from
  HTTP 200 alone; it verifies each responder's protocol-specific status, media type,
  and public discovery payload, so console HTML cannot masquerade as ACME, EST, SCEP,
  CMP, SSH CA, or TSA readiness.
  - Reference-implementation differentials: cross-checked against
    an *independent* implementation in addition to our own parser. ACME: a
    differential against Pebble (the reference test ACME CA) as a dedicated
    CI job, plus a stock certbot CI transcript (certbot manual DNS-01
    issues, renews, and revokes through the served `/directory` endpoint
    while CI archives public challenge records, client logs, and issued
    certificates). EST: a differential against the OpenSSL `pkcs7`
    parser/verifier on every `make test` (so `/cacerts` and `/simpleenroll`
    output is validated by code we did not write), plus a dedicated CI job
    that builds a checksum-pinned libest `estclient` from source, removes its
    verbose access-token print before archiving transcripts, and requires it to
    follow the Bearer challenge and perform simpleenroll against the served EST
    endpoint.
    SPIFFE Workload API: a served stock-client differential — the real
    go-spiffe `workloadapi` client fetches an X.509-SVID, a JWT-SVID, and
    JWT bundles, and validates the JWT-SVID over the served UDS; stock
    `spiffe-helper` writes the served X.509-SVID, key, and trust bundle to
    disk. CMP: a dedicated stock-client CI transcript — OpenSSL
    `cmp -cmd p10cr` creates the request, enrolls through the served `/cmp`
    endpoint, accepts the protected response, and uploads the
    request/response/cert/log artifacts. SCEP: a dedicated stock-client CI
    transcript — a SHA-256-pinned `sscep` v0.10.0 build fetches the served
    CA-plus-RA bundle, classifies its numbered public files by exact issuing
    certificate and signing constraints rather than suffix order, enrolls through
    `/scep/pkiclient.exe`, and uploads both CA/RA files plus the captured
    PKIOperation request/response and client logs. TSA: a dedicated
    stock-client CI transcript — OpenSSL `ts -query` creates a DER
    `TimeStampReq`, CI POSTs it to the served `/tsa` endpoint, OpenSSL
    `ts -verify` validates the returned `TimeStampResp`, and public
    request/response/log artifacts are uploaded.
  - SSH KRL distribution format. The SSH CA's key-revocation list is emitted
    in the OpenSSH binary KRL format, the artifact `sshd`'s `RevokedKeys`
    and `ssh-keygen -Q -f` consume — verified end-to-end by a test that has
    stock `ssh-keygen` report a revoked certificate as revoked using
    trstctl's KRL (and a non-revoked one as valid). A legacy JSON revocation
    snapshot is retained for programmatic callers.
  - Public-CA profile linter. Issued certificates are checked by a built-in
    structural RFC 5280 / CA-Browser-Forum profile linter in the issuance
    test suite — version, serial bounds, validity ordering/length,
    basicConstraints, key usage, SAN presence, SKI/AKI presence,
    weak-signature and minimum-key-strength checks — and the suite is red
    on a deliberately-broken profile. The CI gate also generates a PEM
    corpus for every emitted X.509 profile shape (served leaves, mTLS agent
    certificates, SPIFFE X.509-SVID, TSA, and the issuing CA), runs pinned
    zlint over the served CA plus that corpus, and uploads the generated
    fixtures and JSON lint transcripts as artifacts. This is a private-CA
    assurance gate (for your own internal PKI), not a claim that trstctl
    operates as a WebPKI public CA.
- SPIFFE transport (Workload API): the X.509-SVID document is spec-shaped (a
  single `spiffe://` URI SAN, correct key usage), and the Workload API is
  served as a gRPC service on a Unix domain socket
  (`protocols.spiffe.enabled`). A `spiffe-helper`/go-spiffe/Envoy-SDS
  workload dials the socket for `FetchX509SVID`, `FetchX509Bundles`,
  `FetchJWTSVID`, `FetchJWTBundles`, and `ValidateJWTSVID`. The X.509-SVID
  workload key is minted server-side and returned in the response (per the
  spec); the X.509-SVID CA is the served issuing CA in the signer and the
  JWT-SVID signing key has its own signer handle. The Workload-API
  gRPC/protobuf contract is vendored verbatim from go-spiffe so the wire
  format is byte-identical without a build-time go-spiffe dependency.
- SPIRE upstream authority: the `trstctl-spire-upstream-authority` plugin puts
  the served CA hierarchy behind SPIRE as its X.509 upstream: SPIRE sends its
  local CA CSR to `/api/v1/ca/authorities/{id}/intermediates/csr`, trstctl
  signs it through the served CA hierarchy, and a real SPIRE server container
  mints an SVID chained to the trstctl root in CI. The plugin binary is built
  by `make build` and published from every release tag as
  `trstctl-spire-upstream-authority-linux-{amd64,arm64}` GitHub Release
  assets with a SHA-256 manifest and SLSA provenance. SPIRE loads it from its
  own host filesystem (`plugin_cmd`), so it ships as a standalone binary and
  is **not** part of the trstctl container image. The plugin intentionally
  returns `Unimplemented` for SPIRE's optional JWT upstream publication RPC;
  it anchors X.509-SVID trust, while SPIRE's local JWT key remains
  SPIRE-managed for same-domain JWT-SVID use.
- Attested issuance transport (REST): `POST /api/v1/workloads/attested-issuance`
  is the served proof-before-trust mint for workloads that already have
  their own key pair. The request carries the attestation method, base64
  proof payload, public key PEM, and requested TTL; the response carries the
  signer-issued X.509-SVID PEM, credential id, verified subject, expiry, and
  attestation metadata. The SPIFFE ID is derived from the verified
  attestation subject, not caller-supplied text. Acceptance coverage
  exercises a Kubernetes projected service-account token, an AWS
  instance-identity document with an emulated trusted root, idempotent
  replay, and a forged AWS document rejection.
- AI-agent broker issuance (REST): `POST /api/v1/broker/agent-identities` is
  served when the agent broker is configured with attestors, a policy
  module, trust domain, and signer-backed issuing CA. The route requires
  `certs:issue` and an `Idempotency-Key`; it verifies the agent proof,
  evaluates policy before signing, mints a short-lived X.509-SVID, records
  `certificate.recorded`, emits `agent.identity.issued` or
  `agent.identity.refused`, and projects the agent-to-credential edge into
  the graph. The Workloads page now has an effect-free server preview,
  explicit issuance, unchanged-request retry after uncertain delivery, and
  durable broker history with search, state/method filters and detail readback.
  History requires `certs:read` independently of issuance. It shows original
  public issuance facts and projection freshness, never raw proof, task text or
  internal recovery bindings. Missing or privacy-erased facts remain explicitly
  unavailable. Clearing or reloading the form is not cancellation: inspect
  history and audit before choosing a new recovery key. Revocation uses shared
  certificate controls. Fresh-image API/CLI/browser, negative-security and
  preserved-volume restart qualification is still required before this source
  workflow can be called a complete F61 vertical slice.
- Ephemeral / JIT issuance: effect-free `POST /api/v1/ephemeral/preview` and
  mutating `POST /api/v1/ephemeral` are served when
  ephemeral issuance is enabled with approval TTL/threshold, trust domain, and
  signer-backed issuing CA. Each tenant supplies public verification material
  through an enabled workload attester trust source; no process-wide trust source
  silently applies to every tenant. A requester with
  `certs:request` presents a proof and public key; trstctl verifies the
  proof, opens an approval request, and enqueues the approval notification
  intent in the same tenant transaction. A distinct approver with
  `certs:issue` records approval at
  `POST /api/v1/ephemeral/{id}/approvals`, where `{id}` is the genuine queue
  `approval_request_id` and the JSON body carries `action: issue`, the same UUID
  as `request_id`, and its matching `intent_digest`; the requester then calls
  `/api/v1/ephemeral` with a fresh `Idempotency-Key` to mint the short-TTL
  credential. The Workloads page now provides the same exact-preview,
  send-for-approval, approval-queue handoff, safe-retry, and public-certificate
  collection workflow. It retains only digests and public metadata after issue;
  the proof is cleared and private-key bytes never enter trstctl. Ephemeral API keys are served separately at
  `POST /api/v1/ephemeral/api-keys` and `trstctl-cli ephemeral api-keys
  issue`: callers provide `subject`, `scopes`, and `ttl_seconds`, the raw
  token is returned once, and the leaseworker emits `api_token.revoked` at
  expiry. Headless operators can use `trstctl-cli ephemeral preview`,
  `ephemeral issue`, and `ephemeral approve`; the approval command requires the
  genuine `approval_request_id` in both the path and body plus its matching
  `intent_digest`.
- Agent ↔ control-plane mTLS gRPC channel: the agent steady-state channel is
  served by the running binary when `agent_channel.enabled` (off by default
  — an upgrade does not silently open an agent port). The control plane
  mounts an agent-facing gRPC listener (default `:9443`) over mutual TLS,
  and an enrolled agent connects to it to (a) heartbeat its
  inventory/status — the server records the agent tenant-scoped and emits
  an `agent.heartbeat` event in the tamper-evident log; (b) renew its own
  certificate before expiry — a fresh cert is minted through the
  signer-custodied agent CA, idempotently on the presented serial
  (deduplicated so a retry does not mint twice), recorded as an
  `agent.cert.renewed` event; and (c) report local inventory as
  metadata-only discovery findings, including public OS/Java/NSS/browser/
  Windows trust-store anchors and private-key-material locations/
  classifications from configured roots. Inventory reports create a
  tenant-scoped discovery source, run, finding rows, `discovery.*` events,
  and credential-graph nodes; they do not carry private keys, PEM/DER key
  bytes, or secret values, and secret-looking inline metadata keys are
  rejected before projection. The tenant is derived from the agent's
  verified client-certificate SPIFFE SAN, never a request field. The
  `GET /api/v1/agents` response also publishes the served
  `agent.mtls.ReportInventory` path and the source kinds the shipped agent
  binary can actually collect — `filesystem`, `trust-store`,
  `k8s-secret`, `windows-store`, `private-key`, and `ssh` — each with the
  flags that switch it on, so a capability that is listed but unconfigured
  is not read as coverage that is running. **`pkcs11` ships only in a
  cgo-enabled agent build**, because it dlopens a vendor module and the
  default agent binary is deliberately statically linked; the census is
  build-dependent so a cgo-free binary neither carries the reader nor
  advertises the kind. All three formerly-unbuilt kinds were
  previously listed here and on the API, which read as a Windows estate,
  token store, and Kubernetes Secrets being inventoried when nothing was
  collecting them. Advertised capability is derived from the agent
  package's own record of what it ships, and
  `docs/agent_advertised_capability_test.go` fails the build if a kind is
  advertised without a constructor the agent binary calls. `k8s-secret`
  left the unbuilt list when its enumerator was actually wired: with
  `--inventory-k8s-secrets` the agent enumerates the TLS Secrets in its own
  namespace through the in-cluster service account, reading `tls.crt` and
  never `tls.key`, and reports metadata-only findings over the same mTLS
  inventory path as every other source. It needs list access to Secrets in
  that namespace and sees only that namespace. `windows-store` left the
  unbuilt list when its crypt32 reader shipped: with
  `--inventory-windows-stores` the agent opens the named machine or user
  stores **read-only**, walks each certificate context, and reports
  metadata only — it never asks the platform to export a private key, so a
  key held in a TPM or on a smart card is untouched and irrelevant. `MY`,
  `WEBHOSTING`, `CA`, `ROOT` and `TRUSTEDPUBLISHER` are supported;
  `WEBHOSTING` is where IIS keeps site certificates on current Windows
  Server, which is the population most likely to expire unowned. An
  unreadable store fails the report rather than contributing nothing, and
  on a non-Windows build the source returns an **error**, never an empty
  inventory — telling a Linux operator their Windows estate is clean would
  be worse than the original defect, because it would arrive with the
  authority of a scan that never happened. `pkcs11` completed the set: a
  cgo build opens the configured module, walks each matching token over a
  **read-only, non-read-write** session, and reads `CKA_VALUE` from objects
  of class `CKO_CERTIFICATE`. It never searches for `CKO_PRIVATE_KEY`,
  never calls `C_Sign`, and never asks a token to export anything — a
  PKCS#11 key is normally `CKA_EXTRACTABLE=false` and could not leave
  regardless, but the code does not ask. Login is optional: public
  certificate objects are readable without one, and the PIN, when a token
  needs it, comes from a **file** rather than a flag, because process
  arguments are readable by anyone who can list processes — the same rule
  the bootstrap token follows. A cgo-free build returns an error rather
  than an empty token inventory, and does not advertise the kind at all. The channel is behind its own bounded agent
  worker lane and per-connection gRPC stream cap, so a heartbeat or renewal
  storm sheds with `ResourceExhausted` rather than starving API, protocol,
  outbox, or signer capacity. Agents announce an explicit
  protocol/capability handshake and schedule heartbeats from the server
  hint with bounded jitter, so rolling upgrades and fleet restarts do not
  synchronize a thundering beat. The agent CA key lives in the isolated
  signer under a stable handle, so it does not regenerate per boot — an
  agent's pinned CA survives a control-plane restart (the earlier
  in-process/per-boot stand-in is replaced when the channel is enabled, and
  the same signer-custodied agent CA also signs the bootstrap enrollment,
  so a bootstrap-enrolled agent is accepted on the steady-state channel).
  The shipped chart exposes the channel: when `agentChannel.enabled`, the
  control-plane Service publishes the agent port `9443` (`agent-grpc`), the
  container exposes it, and the NetworkPolicy admits it (from the
  configured `agentChannel.allowedCIDRs` plus the in-cluster peers the API
  admits) — so the fleet manifests (`deploy/kubernetes/daemonset.yaml`, the
  Windows MSI) that point agents at `:9443` reach a served port. This is
  distinct from the *isolated signer's* `:9443` (a signer-only Service
  under `signer.mode=isolated`, which admits only the control plane). An
  untrusted/unpinned agent client is rejected at the mutual-TLS handshake
  (fail-closed). Proven end-to-end by acceptance tests (real signer +
  embedded Postgres: enroll → heartbeat → endpoint inventory report →
  served API capability readback → Discovery findings → graph node, plus
  renew → idempotent retry → reject untrusted) and rendered-chart
  assertions.
- Embedded HTTP enrollment renewal: `POST /enroll/bootstrap` is mounted on
  the served control-plane HTTPS listener. When `agent_channel.enabled`,
  the binary also mounts `POST /enroll/renewal` on a dedicated agent-CA
  mTLS HTTPS listener (`agent_channel.http_renewal_addr`, default `:9444`)
  that uses `tls.RequireAndVerifyClientCert` semantics against the
  signer-custodied agent CA. Bootstrap consumes a one-time token. Renewal
  requires the current verified agent client certificate, rejects missing
  or untrusted peers at the live TLS boundary, rejects expired verified
  peers in the handler, and deduplicates on the presented certificate
  fingerprint plus CSR when the served API has idempotency storage. The
  renewed certificate is tenant-attributed from the verified peer, never
  from a request header or CSR field.

## Revocation

Revoking a credential through the running binary is real and recorded, not
a no-op. Transitioning an identity to *revoked* drives the served outbox
handler to mark the issued certificate revoked in the inventory — via a
projected `certificate.revoked` event, so the status is reconstructable
from the log on a read-model rebuild, and the certificate API returns
`status` / `revoked_at` / `revocation_reason` so the revocation is visible
on the served surface (a revoked cert reads `"revoked"`, not silently
`"active"`) — and project the certificate's serial into the revocation
read model from the same event, so OCSP/CRL state is rebuilt from the log
instead of from a side write.

The online revocation-distribution surface is served: the running binary
mounts an RFC 6960 OCSP responder at `/ocsp/{tenant}` (GET base64-in-path
and POST `application/ocsp-request`), an RFC 5280 full CRL endpoint at
`/crl/{tenant}`, a manifest at `/crl/{tenant}/manifest.json`, partitioned
shard CRLs at `/crl/{tenant}/shards/{index}`, and RFC 5280 delta CRLs at
`/crl/{tenant}/delta/{base}`. The freshness scheduler regenerates each
tenant's CRL set ahead of `nextUpdate`. Trusted issue, renewal, revocation,
protocol-enrollment, and scheduler paths publish CRLs; public CRL reads
are read-only and return 404 until artifacts are already published for a
tenant that has issued certificates. A query for a revoked serial returns
`revoked` over OCSP and the serial appears on the full CRL, its shard, and
any applicable delta CRL within the freshness window; a query for an
issued-but-not-revoked serial returns `good`; an unknown serial returns a
signed `unknown`. The shard plan is 4-1024 partitions targeting roughly
100k revoked serials per shard, so 10-100M-row estates use bounded
shard/delta fetches while retaining the compatibility full CRL. These
endpoints are public by RFC design (relying parties check status without
credentials) but run on the API worker lane, so an OCSP/CRL flood sheds
rather than starving the rest of the control plane.

OCSP responses and CRLs are signed through the out-of-process signer: the
signing op crosses the single isolated cryptography path using the same
signer-held CA key the leaf path uses, so the CA private key never
materializes in the control plane — only the digest crosses. Every query
is tenant-scoped. Each published CRL emits a `ca.crl.published` event that
carries the CRL DER artifact metadata, parent/base CRL number, revoked
count, and validity window, so the published-CRL read model is rebuilt
from the event log. This is exercised end to end in the local acceptance
suite: issue, revoke, assert OCSP returns `revoked` (and `good` before
revocation), assert the full/sharded/delta CRLs list the right serials
within the freshness window, and verify the signatures against the issuing
CA over real HTTP against the assembled binary and the real out-of-process
signer.

The CDP/AIA pointers stamped on issued leaves are operator-configured
(`ca.crl_distribution_points` / `ca.ocsp_servers`) because the externally
reachable URL is deployment-specific; point them at the binary's
`/ocsp/{tenant}`, `/crl/{tenant}`, and, where clients support it, the
shard/delta distribution URLs (behind your ingress) so relying parties
discover and fetch revocation status automatically. Existing leaf
certificates keep the URLs they were issued with until reissued. trstctl
revocation is both authoritative in the product's own inventory/records
and publishable to external relying parties over served OCSP/CRL.

CT log submission is served as an outbound side effect, not as an inline
API call: the API validates public certificate PEM and CT log URLs,
records `ct.submit` outbox rows in the tenant transaction, and the worker
posts RFC 6962 `add-pre-chain` / `add-chain` requests. Public HTTPS logs
are required by default; `allow_private_endpoint` additionally requires
`egress:private` and `private_egress_cidrs` destination grants. trstctl
records queued and delivered events, but final inclusion and SCT
acceptance remain external CT log facts.

## Single sign-on

trstctl's interactive sign-on is served for OIDC, SAML 2.0, and LDAP / Active
Directory. OIDC is core; tenant SAML and LDAP require Enterprise SSO.
OIDC supports the authorization-code flow against Microsoft Entra ID /
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

The assembled issuing CA's key is persisted, sealed at rest in the signer's
key store: a signer restart preserves the CA instead of silently rotating
it, and the key survives across restarts. Root/intermediate m-of-n
ceremonies and signer-backed leaf issuance are served. The release also
publishes a cgo-enabled HSM signer artifact that links the native PKCS#11
binding; the default static control-plane artifact does not load native
modules. The conditional managed-key path has required launched-binary
receipts for all six advertised providers, while the sealed local signer
key store remains the default when no provider is configured. Helm
`externalKMS` separately wraps signer key-store DEKs through an
operator-supplied AWS KMS, GCP KMS, Azure Key Vault, or PKCS#11 adapter
instead of mounting the local signer KEK. Online break-glass issue,
signer-backed CA rotation with bidirectional overlap cross-certificates,
and target-CA cross-signing are production-assembled when the online
block is configured. Approvals come from authenticated immutable ceremony
events, not caller-supplied names. Break-glass bundle reconciliation
remains served at `POST /api/v1/breakglass/reconcile`. The credential-store
key-encryption key is a local file by default. See the
[key-ceremony runbook](runbooks/key-ceremony.md),
[incident response](runbooks/incident-response.md), and
[disaster recovery](disaster-recovery.md).

In-memory custody of the reference-path CA keys: the served CA-hierarchy
path does not use these in-process reference keys — it binds each served
root/intermediate to an isolated-signer handle. The library reference
manager still holds live ECDSA signing keys in locked, wipeable secret
buffers (`mlock` + `MADV_DONTDUMP`) rather than as a bare unprotected key
on the garbage-collected heap for the lifetime of the in-process CA; the
key is reconstructed only for the instant of each signature and the
transiently parsed copy is best-effort zeroized afterward (the same
hardening the isolated signer uses). This narrows — but, given Go's
runtime, does not eliminate — the window in which an unprotected key sits
in dumpable heap; it is complemented process-wide by `RLIMIT_CORE=0` /
`PR_SET_DUMPABLE=0`.

BYOK / HSM key lifecycle: the conditional Enterprise surface supports AWS
KMS, Azure Key Vault / Managed HSM, GCP Cloud KMS, PKCS#11, TPM 2.0, and
YubiHSM 2. The required wiring census reports six of six backends served
through the shipped control-plane plus cgo HSM signer artifact; package
reachability or a registry built only by a test is not used as evidence.

With an active BYOK license and `managed_keys.enabled`, the control-plane process
does not construct a provider or receive provider credentials. Its tagged EE attach
seam installs the tenant-scoped event/projection factory and durable PostgreSQL
outbox handler. A separate dispatcher delivers the lifecycle command over the
authenticated signer transport. The isolated signer constructs exactly one selected
provider under the `ee/` fence and stores provider ownership, operation outcome, and
consumed sign-authorization nonces in its fsync-backed journal. An `executing` operation
is not abandoned after restart: every shipped receiver finds or reconciles the same
durable operation identity. AWS stamps it atomically in `CreateKey`; Azure and GCP use
deterministic provider resource names; PKCS#11 and YubiHSM use deterministic `CKA_ID`;
TPM enumerates persistent objects and accepts only a full SHA-256 operation tag from
immutable `TPM Public.AuthPolicy`, probing past foreign handles without adopting or
overwriting them. Revoke and zeroize read provider/device state before and after the
terminal transition, so a lost response does not repeat the effect. The swtpm gate also
pre-occupies the first deterministic handle with a same-algorithm foreign object and
proves that object remains untouched.

The handlers at `POST /api/v1/managed-keys`, its dedicated JSON approval route, and
its rotate, revoke, and zeroize
companions return only opaque handles, public DER, algorithm, non-extractable state,
and lifecycle state. Every mutation requires `Idempotency-Key`; immutable events
build the tenant/RLS projection, and the provider call comes only from the sealed
outbox. Managed-key signing additionally requires a short-lived, request-bound token
from the configured content-authority command. The signer consumes its random nonce
durably before calling the provider, so token replay fails both in-process and after
restart. Provider credentials must be file-backed, are copied into locked byte
buffers, and are wiped on shutdown; the one unavoidable PKCS#11 `C_Login` conversion
exists only at the upstream string-only ABI edge.

| Provider | Production binding in the shipped HSM signer | Gate substrate and lifecycle proof |
| --- | --- | --- |
| AWS KMS | Official AWS SDK v2 asymmetric KMS client | SigV4-checking emulator; atomic operation tag, ambiguous-create recovery, disable/deletion readback |
| Azure Key Vault / Managed HSM | Keys data-plane client with bearer-token file | Managed-HSM emulator; deterministic key identity, ambiguous-create recovery, revoke/delete readback |
| GCP Cloud KMS | Cloud KMS REST data plane with bearer-token file | Deterministic-resource emulator; ambiguous-create recovery, disable/destroy readback |
| PKCS#11 | cgo module session with operation-derived `CKA_ID` handles | SoftHSM token; restart find-or-create plus independent `pkcs11-tool` state readback |
| TPM 2.0 | `google/go-tpm` device or swtpm socket with tagged persistent handles | swtpm plus `tpm2-tools`; full operation-tag readback, forced foreign-handle collision, restart and eviction |
| YubiHSM 2 | Yubico `yubihsm_pkcs11` ABI through the PKCS#11 connector | Vendor-ABI emulator with deterministic `CKA_ID`; independent sign/revoke/deletion readback |

The cloud receipts are high-fidelity protocol emulation, not a claim that this test
ran in a customer's live cloud account. Likewise, SoftHSM proves the PKCS#11 ABI and
swtpm proves TPM command/lifecycle behavior; an operator still validates its exact
device firmware, module certificate, network policy, and cloud IAM. The LocalStack
demo is not the acceptance proof's receipt source. Static no-cgo signer builds fail closed for native
PKCS#11/YubiHSM selection; use the published HSM signer artifact. Provider selection
is startup-static: this is ordinary Go interface injection, not a runtime crypto
plugin engine or a policy-selected algorithm marketplace.

Still library-tier (reachable from no served verb yet): the in-process key
lifecycle for the local CA/issuing signing key and the secrets KEK
(generate-or-import → rotate → revoke → zeroize is implemented and
end-to-end tested but not yet exposed as its own served route). Break-glass
issue/rotation/cross-sign and offline-root public re-key/cross-sign import
have served, ceremony-gated verbs; reconciliation remains served at
`POST /api/v1/breakglass/reconcile`. The signer's at-rest CA key is still
sealed under a local key-encryption file by default. See the
[key-ceremony runbook](runbooks/key-ceremony.md),
[incident response](runbooks/incident-response.md), and
[disaster recovery](disaster-recovery.md). The remaining external residual
is the product NIST CMVP certificate (see
[compliance → FIPS](compliance.md#fips-cryptography-a-fips-capable-build-path)),
a lab process software cannot perform. The validated-module path itself is
served: `GET /api/v1/editions` and the Platform page expose the live FIPS
POST booleans, `make fips-build` build target, `fips-capable build
(GOFIPS140)` CI gate, and `internal/crypto` boundary as the CAP-KEY-03
operator posture.

Signer UDS peer-uid is Linux-only: the signing service's Unix-domain-socket
listener authenticates the connecting process's uid via `SO_PEERCRED`,
which exists only on Linux — the supported production target
(Docker/Helm). On non-Linux hosts, `trstctl-signer` fails closed when
process hardening, locked memory, or UDS peer credentials are unavailable.
Local developers
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

- ML-DSA (FIPS 204; `mldsa44` / `mldsa65` / `mldsa87`) — the NIST-standard
  lattice signature.
- ML-KEM (FIPS 203; `mlkem512` / `768` / `1024`) — the NIST-standard key
  encapsulation. trstctl can generate ML-KEM keys, encapsulate to an
  ML-KEM public key, and decapsulate the resulting ciphertext; all three
  parameter sets are checked against FIPS 203 known-answer vectors. The
  served HTTPS and mTLS listeners prefer `X25519MLKEM768` for TLS 1.3
  hybrid key exchange when a peer supports it, with classical TLS 1.3
  groups retained for compatibility.
- SLH-DSA / SPHINCS+ (FIPS 205; `SLH-DSA-SHA2-128s` / `128f` / `192s` /
  `256s`) — the NIST-standard stateless hash-based signature. Its security
  rests only on the hash function, so it is the conservative choice for
  long-lived roots where you want assumptions independent of the lattice
  schemes; the trade-off is much larger signatures.
- A hybrid signature (`HybridEd25519Dilithium3`) — classical Ed25519 paired
  with ML-DSA, so breaking either component alone does not forge a
  signature.

Private key material is held in locked, zeroized buffers and parsed only
for the moment of each operation, exactly like classical keys. The isolated
signer can generate and use signer-held ML-DSA and SLH-DSA keys over its
UDS or mTLS gRPC channel, and those keys are sealed in the signer key store
so a restart does not silently rotate them. ML-KEM is not exposed as a
signer key because it is encapsulation, not a signature; use it as the
key-establishment primitive for protocol wiring rather than as an issuing
CA key.

The served CA can mint a hybrid transition leaf: the certificate remains a
normal ECDSA P-256 leaf for stock TLS clients, while a signed ML-DSA-44 +
ECDSA-P256 composite binding is carried inside the certificate for
PQ-aware verifiers — deployable without forcing every client to understand
draft composite public keys on day one. The ACME, EST, SCEP, and CMP
served enrollment paths all run through that same issuer, and a CSR
carrying the hybrid proof (a classical ECDSA-P256 CSR with the
composite-binding extension) issues through all four. Pure ML-DSA CSRs are
narrower today: EST accepts and issues them (the PQC PKCS#10 parser
sits behind EST's verifier seam, proven against a stock OpenSSL 3.5
client), and ACME hands the CSR bytes to the same PQC issuer without
parsing them first; SCEP and CMP still verify CSRs with the core parser
before the PQC parser is consulted and therefore reject pure ML-DSA —
SCEP additionally cannot deliver its CMS-enveloped reply to a
signature-only subject key, a protocol limit rather than a code gap. One
ceiling applies everywhere: the issuing CA key itself remains classical
ECDSA-P256 (post-quantum keys are subject keys, not issuer keys, in the
served path). Certificate-profile `allowed_key_algorithms` labels accept
the post-quantum and hybrid names in every build — a pure label
matches its exact inspected CSR algorithm, while a hybrid enrollment
carries a classical subject key and stays governed by its classical family
label. The selected profile still controls which algorithms an enrollment may use.

The core CBOM posture recognizes ML-DSA, ML-KEM, and SLH-DSA / SPHINCS+
(and hybrid labels) when it finds them in your estate. Algorithm recognition
and posture classification attach in every build without a commercial license. Because all cryptography enters through one isolated
path, each scheme is a contained boundary implementation (a CIRCL scheme
plus known-answer tests), with no ripple into the rest of the system. The
served CBOM inventory exposes this posture through
`GET /api/v1/cbom/assets`: classical signing algorithms
are mapped to ML-DSA-65/FIPS 204 targets, key-establishment findings (TLS
protocols and ciphers) to ML-KEM-768/FIPS 203, deprecated DSA to
SLH-DSA/FIPS 205, and `migration_progress` shows how much of the observed
estate is already post-quantum-ready — pure post-quantum assets count as
future-ready, while hybrids stay migration-required until they shed their
classical component.

The core attach serves three former end-to-end residuals in every build: a stock OpenSSL 3.5 client creates an RFC 9881
ML-DSA-65 CSR, enrolls it through EST, and verifies the returned pure
ML-DSA-65 subject leaf; the stock SPIFFE Workload API returns a two-entry
response for one SPIFFE ID (the normal classical SVID and an ML-DSA-65
SVID with its matching private key); and CBOM TLS protocol/cipher findings
can be bound to a posture-capable connector target, where the migration
worker seals the forward intent in the outbox, applies TLS 1.3 plus
`X25519MLKEM768`, reads receiver evidence, projects per-finding progress,
and performs exact rollback. The shipped-binary proof drives that TLS
finding rollout against Envoy rather than constructing the migration
runtime in a test.

Those proofs define the compatibility boundary: they do not claim every
legacy TLS client or every connector understands ML-DSA. A hybrid-to-pure
cutover for an existing hybrid certificate remains evidence-gated by
succession/retirement policy; direct pure ML-DSA enrollment is served
through EST (and as the SPIFFE Workload API's second SVID), and
CMP consults the same PQC parser for its carried CSR (PKIMessage
protection stays classically verified). SCEP cannot by protocol. The direct
identity API now accepts a caller-supplied CSR — supply `subject_csr_pem`
on the transition to `issued` and trstctl signs that request rather than
generating a subject key — so CSR-based enrollment, including post-quantum
subject algorithms, is no longer confined to the enrollment protocols. See
[Lifecycle & PQC](features/lifecycle-and-pqc.md) for operator flow and
compatibility limits.

**Key custody, stated per credential kind.** Whose process created a private
key and whose disk holds it is answered in one CI-checked table at
[Key custody](custody.md), not in prose scattered across pages. The short
version: every enrollment protocol, and the identity API when given a CSR,
generate keys in your environment and the control plane never sees them; CA
keys are created inside the isolated signer and never leave it; and every
remaining path that can generate a subject key in the control plane is named there
with what replaces it. The identity API without a CSR is one of those three:
it still works for one release train and records an
`issuance.server_side_keygen` event every time it runs, so you can find which
of your flows still rely on it. An identity issued from your own CSR cannot
be deployed by a control-plane connector — the key that deployment needs is
on your side, which is the correct consequence and the reason host-executed
renewal is the next piece of work.

**And stated per credential, not only per kind.** The table above is the right
level for a design review and the wrong level for an audit, because an auditor
is not asking about a kind — they are asking about the certificate in front of
them, and a kind-level table cannot tell them whether that one took the modern
path or the deprecated one. So custody is also recorded on each certificate at
issuance, from what the issuing code did rather than from what the table says
it should: an identity issued from your CSR records that the control plane
never held the key; one issued through the deprecated server-keygen path
records that it did. The certificate API returns it and the console shows it on
the certificate.

Two honest gaps. Certificates issued before this shipped have no custody
recorded, and so does every certificate found by discovery — trstctl did not
witness their issuance and has no basis for a claim about it. Both read as
**not recorded**, which is deliberately a different value from any custody
claim rather than a default that quietly resembles the good one. And what is
recorded is the control plane's own account of what it did; it is evidence, not
an attestation, and it is not signed by the hardware that holds the key. A
device-bound custody claim you can verify cryptographically is a different and
larger piece of work.

Recording it per certificate also made a fourth control-plane keygen path
visible that the kind-level table had not named: automated renewal builds the
successor's CSR itself, so every certificate produced by the scheduled
renew-before-expiry pass or by rotate reads `control_plane`. Worse than the
custody label, the key is destroyed once the successor is recorded — so an
automated renewal produces a correct inventory row and a certificate no endpoint
can serve with. [Key custody](custody.md) states this in full. Host-executed
renewal is what fixes it, and until it lands the count of successors reading
`control_plane` is the honest measure of the gap.

## Served TLS floor and stock enrollment clients

The control plane's HTTPS listener negotiates TLS 1.3 only by default. Stock device
enrollment clients that cap at TLS 1.2 (cisco libest `estclient`, some SCEP agents)
cannot complete the handshake against that default; the conformance job that builds
libest proves it against a Go test server that still allows TLS 1.2, not against the
served policy. `TRSTCTL_SERVER_TLS_MIN_VERSION=1.2` (AEAD suites only) is the
documented opt-in for such fleets. EST `/simplereenroll` authenticates with the
bootstrap token rather than the presented client certificate (DP2-037), so devices
keep the scoped token for renewals. Found by the cold design-partner run
20260906t143500z (DP2-036, DP2-037).

## ACME certificate profiles

trstctl's ACME client (the `letsencrypt` external CA type, built on `x/crypto/acme`)
does not send the `profile` field of draft-ietf-acme-profiles in `newOrder`, and the
external CA configuration has no way to name one. The certificate lifetime is therefore
whatever the authority applies to an order without a profile:

- Let's Encrypt production applies its classic profile today; when the short-lived
  (six-day) profile becomes a default it will apply without any change on this side.
- Pebble 2.10 picks a **random** profile for such orders ("in true pebble chaos fashion"),
  so its stock configuration alternates between 90-day and 6-day certificates. The
  partner lab pins Pebble to a single 90-day profile (`deploy/demo/lab/pebble-config.json`)
  so lab issuance is deterministic.

When an external CA returns a certificate whose whole lifetime is shorter than the
tenant's expiry alert window, the control plane logs a WARN naming the tenant and the
authority; the ordinary expiry alert then fires immediately, which is honest but noisy.
Profile selection will follow once the ACME client can express it. Found by the cold
design-partner run 20260906t143500z (DP2-032).

## Upstream domain validation

trstctl is an ACME server and an ACME client, and until now only one of those
could do DNS-01.

**What was wrong.** As a client to a public CA, the driver looked only for
`http-01` and errored if the authority offered none, so DNS-01 was never
attempted and wildcards were impossible. Worse, the production constructor wired
a solver whose present and cleanup did nothing. The upstream path therefore
worked **only against orders the authority had already authorized out of band**.
Every test passed, because the fixture returned orders as pre-authorized — the
same shape of defect as a feature whose executor is never asked for work.

**What is served now.** The client negotiates challenge type from what the
authority actually offers, and solves DNS-01 through the same publish path, the
same providers and the same credentials the server direction already uses. A
missing solver fails closed with a named reason rather than silently validating
nothing. The record is retracted on **every** exit path, including when the
context expired — which is exactly when a validation token is most likely to be
left live in public DNS.

**Consent is explicit, and it is two decisions, not one.** The authority must
be configured with `upstream_dns01`, and each DNS-01 provider config must set
`allow_upstream_dv`. Both default to false, including on configs that already
existed. Credentials an operator supplied so
that trstctl could *verify* a challenge somebody else published are not consent
for trstctl to *publish* into that zone whenever an external authority asks —
and as validation-reuse windows compress, that publishing becomes frequent and
unattended. A migration cannot grant that permission; a content harness asserts
no existing config comes out consenting.

**CAA is checked against the right issuer.** The server-side check uses the
config's own CAA identifier, which is correct when trstctl is the issuer.
Upstream the certificate comes from someone else, so the check uses the external
CA's identifier, and refuses to run at all if none is configured — a CAA check
against an empty issuer authorizes everything while appearing to check.
Configuration validation requires `caa_issuer_domain` whenever `upstream_dns01`
is on, so that state is unreachable rather than merely handled. The identifier
is bound per authority: two configured ACME CAs do not share one, because a CAA
check that authorizes the *wrong* CA passes while being wrong, which is harder
to notice than one that authorizes everyone.

**Reused authorizations are recorded, and served.** An authority that already
considers an identifier authorized issues without a challenge. That is normal
and it is also the thing worth watching: automating validation removes the
human from the cycle, and with them the human who used to notice when
validation broke. `GET /api/v1/acme/dns-01/upstream-authorizations` and the
console's *Upstream authorization freshness* panel report, per identifier and
per authority, when control was **last actually proved** — not when a
certificate was last issued. Those two diverge silently, and the gap is the
warning. An identifier that has never been validated by this deployment is
called out by name: every issuance for it so far rode a reuse this install did
not earn and cannot repeat, and when the window closes they fail together
rather than one at a time. A reuse never overwrites the last real validation
date; that is asserted by a test, because the convenient single "last seen"
column would erase the only signal here.

**What is not served.** trstctl does not wait for DNS propagation before telling
the authority to validate. The record is published through the provider's API
and the challenge is accepted as soon as that call returns, so a zone whose
nameservers are slow to converge can have its authorization marked invalid and
the order retried rather than waiting. The operator-run preflight
(`POST /api/v1/acme/dns-01/preflight`) checks propagation for a domain, but it
evaluates TXT values the caller supplies rather than querying DNS itself, so it
cannot be reused as an automatic gate. Closing this needs authoritative-nameserver
TXT verification that does not exist in the tree yet; until it does, a slow zone
costs a retry, not a wrong answer.

Also not served: http-01 upstream — it would require an inbound listener
on the validated host, which this architecture does not have and will not grow.
The challenge census says so rather than claiming a type that would be selected
and then fail. The publish is bounded, but by whichever deadline is tighter: the
caller's context if it carries one, and otherwise the DNS-01 automation's own
30-second outbox wait. There is no separate, configurable propagation budget,
and the 30 seconds is a floor for callers that set no deadline rather than a cap
that always applies.

## Issued, delivered, verified

Three claims about the same certificate, with three different lifetimes, and
only the third is what an operator actually wanted:

- **Issued** — a CA produced it. Recorded in the certificate inventory.
- **Delivered** — a connector applied it to a target. Recorded on a
  `connector.deploy` delivery receipt. This is trstctl's own account of what it
  did, and it is where every deployment surface stopped before D3.
- **Verified** — a TLS handshake observed the endpoint serving it. Recorded on a
  second delivery receipt and, separately, as current endpoint state.

**Delivered and verified are counted separately and never summed.** A renewal can
succeed at the CA, be delivered by a connector, and never reach the listener,
with every delivery record staying truthfully green. A health surface that
counted deliveries would be reporting intentions; `GET /api/v1/platform/system`
counts by verified state for exactly that reason, and `verified_percent` is of
DELIVERED targets — "of what we have deployed, how much is confirmed live".

**Verification writes a second receipt rather than editing the delivery one.**
Both facts belong in the evidence chain and they have different lifetimes: "a
connector applied the credential" is true forever once it happens, and "the
endpoint was serving it" is true of the moment it was observed. A certificate
verified in June whose listener silently reverted in August shows a June receipt
still reading `verified` and an endpoint state reading `diverged`. Overwriting
the first would destroy the record that delivery succeeded, which is what an
operator needs to tell a pipeline problem from a listener problem.

**`unverified` is the honest middle.** A delivered target nobody has probed is
neither a failure nor a pass — it means nothing has looked. Folding it into
either direction would be an overclaim, and on a fresh install every target sits
here, which is the correct starting picture rather than a discouraging one.

## Renewal windows, canaries and SLOs

**Maintenance windows defer, they never drop.** A renewal deploys to a listener
and reloads a service, and there are hours in every organization's week when
nobody wants that unattended. Before this the only control was switching renewal
off, which trades an outage risk for an expiry risk. A window that closes now
holds the sweep and records why, naming when it reopens — because a change
freeze that quietly stopped renewals looks exactly like a scheduler working
correctly, right up until certificates expire, and expiry is the more expensive
failure by a wide margin.

An empty window list means **unrestricted**, never "never": an operator who
configured no windows has not asked for a freeze, and defaulting to closed would
turn an upgrade into a fleet-wide expiry event. A malformed window refuses to
start rather than being ignored — an operator who wrote a freeze this could not
read would believe production was protected while the scheduler renewed through
it. Windows are expressed in named timezones so they follow daylight saving the
way the person who wrote them expects, and a window whose end precedes its start
wraps midnight, which is the shape most operators actually want.

**Fleet gates are computed, not asserted.** Until D2/D3 nothing re-read an
endpoint, so every gate trstctl filled in itself was `not_evaluated` — correctly,
because a verdict nobody computed is not a pass. The replacement-deployment gate
is now derived from verification receipts under two rules an operator relies on
mid-incident: **failure dominates** (one replacement serving the wrong
certificate fails the gate however many others passed) and **absence beats
success** (one replacement nobody probed keeps it unevaluated). A gate an
operator asserted is never overwritten by a computed one — they may have
inspected something this control plane cannot see. Gates evaluate at read time,
so a fleet that has since diverged stops showing a pass.

The other two gates stay `not_evaluated` because nothing computes them: graph
enumeration has no completeness oracle, and revocation publication is R1's
freshness signal, which is not wired to a run. Saying so beats deriving them
from something adjacent and calling it proof.

**Canary-first halts propagation.** Starting a run persists its cursor and
publishes exactly one internal outbox command for batch one. The bounded worker
publishes replacement work only for that cursor, waits without spending its
retry budget, and accepts a verdict only when the connector verification row is
paired with an agent-job receipt whose signature was accepted. A failure stores
the explicit halt reason and leaves later batches absent from the outbox.
`halted` is distinct from `failed`: a halted batch was never attempted. Resume
reuses the same cursor and deterministic replacement ids, so crash recovery and
redelivery converge instead of reissuing or publishing a later batch twice.

**The SLO counts terminal runs only.** A renewal still executing is neither a
success nor a failure, and forcing it into either would move the number for
reasons unrelated to reliability. A window in which nothing was due reports 100%,
not 0% — an estate with no renewals pending is not in breach, and paging on the
absence of work is how a team learns to ignore an SLO. Error-budget burn is
clamped at zero, because a figure like -340% is not more actionable than
none-remaining and the raw counts sit beside it.

**What is not served.** The fleet state machine does not treat an unsigned
control-plane assertion as endpoint proof. A deployment executed only by a
control-plane connector therefore cannot advance this signed-receipt gate; it
remains `waiting_verification` until a bound agent reports the endpoint result.

## Endpoint verification

Every other record in this product reports what trstctl DID. An outbox row
delivered, a connector returned success, a certificate was issued — all of them
can be true at once while the listener serves something else entirely, because
a connector's reload is one exec call inside its own `Deploy` method and nothing
downstream observes whether it took effect.

**The failure this exists to catch.** A renewal succeeds at the CA. The connector
writes the file. The reload fails, or the service ignores it. Every delivery
receipt stays green, the inventory correctly describes the new certificate, and
clients keep getting the old one until it expires. Inventory-based expiry
alerting cannot see this, because the inventory is *right* but does not
describe what is being served.

**Two vantages, and the difference is not redundancy.** The host agent's check
runs inside `connector.deploy`, in the only window where it can: after the
reload, before the redeemed material is destroyed. It verifies against the exact
bytes it deployed rather than a description of them. The relay's check is a
separate `endpoint.verify` job — network vantage, no credential redeemed — and
it is the only witness for an appliance, because nothing runs on an F5. A local
pass means the box thinks it is fine; only a relay pass means a client could get
it. The two are stored as separate rows and never merged.

**A verdict never claims more than it checked.** Each record carries whether the
name set and chain were compared in addition to the fingerprint. An
expectation that supplied no SAN set yields a verification that does not claim to
have checked names.

**Unreachable is not a pass.** It is stored as its own state, with no mismatch
class, no comparison flags and no observed fingerprint — enforced in three
places (the agent's transcript validation, the projector's decode, and a database
CHECK constraint) because an endpoint nobody could connect to, recorded as
verified, would be a worse false assurance than the blindness this replaces.

**`last_good_at` is never erased by a failure.** The gap between it and
`last_checked_at` is how long an endpoint has been failing, and losing it on the
first failure would destroy the only measure of the outage's age. An endpoint
that has never once been observed serving what it should reads as *never
verified*, which is a stronger statement than "not recently" and renders as one.

**Re-verification is a loop, not an event.** A post-deploy check proves the
reload took effect at that moment; it says nothing about the weeks afterward,
and a listener can start serving the wrong certificate long after a deploy — a
failover to a node that never got the file, a config reload elsewhere, a restored
backup. Sweeps run hourly by default (`EndpointVerificationInterval`), batched at
50 endpoints per job so one tenant cannot hold a relay indefinitely. Each sweep's
expectation comes from the control plane's own record of what should be there,
never from the last observation — re-probing against what was last *seen* would
re-verify a divergence as correct on the next sweep and silence its own alarm.

**Divergence alerts route by severity, not by finding score.** A served-identity
divergence is `critical`; an unreachable endpoint is `warning`, because a probe
that could not connect may be a firewall or a maintenance window and paging at
critical for that teaches people to ignore the channel. The alert kind is
distinct from `credential.drift` deliberately: drift drives a file-repair
workflow keyed on a filesystem path, and a served-identity divergence usually has
a perfectly correct file that a process never reloaded.

**Automatic rollback is opt-in, per target, default off.** Setting
`auto_rollback_on_verify_failure` on a deployment target closes the loop: a
`verify_failed` deploy queues D4's executed re-bind to the predecessor. It fires
only on `verify_failed` and never on plain failure — a deploy that failed did not
change the target, so rolling it back would undo something that was never done.
Absent flag means off; a target whose config predates this feature never starts
changing itself because a new version shipped. The four appliance re-bind
families and all 14 host-local restore families can execute it. Host work is
pinned to the agent that retained the predecessor; a first deployment still has
nothing to roll back to.

Manual and automatic rollback share a tenant-scoped inventory check: the
predecessor must be known and unrevoked, and a bound identity must not be revoked
or retired. The control plane repeats that check before handing out queued work;
the updated agent requests fresh authorization before opening its predecessor
store or redeeming an appliance credential. Upgrade both components to obtain
all three checks. A control-plane refusal is recorded as `rollback_refused`,
without claiming agent execution. These checks cannot cancel a remote operation
already in progress or remove compromised material already installed on a target.

**Configuring it.** Local post-deploy verification runs when a deployment target
carries `verify_address` (and optionally `verify_server_name`) in its config —
for example `{"cert_path": "/etc/nginx/server.crt", "verify_address": "api.example.test:443"}`.
The address cannot be derived and is not guessed: on an appliance target
`endpoint` is the MANAGEMENT API, and the connector's target string is a routing
label, so an F5's management plane and the virtual server it fronts are
different sockets.

**What is not served.** Verification only covers endpoints an operator has given
a listener address for; there is no discovery of listeners from deployment
targets, because a guessed address produces confident, wrong records. An endpoint
with no address is never verified and never claims to be.

## Per-issuer capabilities

`GET /api/v1/issuers/capabilities` and `trstctl issuers capabilities` serve one
row per authority kind: discover, issue, renew, revoke, whether trstctl can
satisfy its domain validation unattended, where the private key is generated,
and what the authority validates before issuing. The console shows revocation
and domain validation beside each configured issuer.

**Unattended DV is checked against the source, in both directions.** It is true
only where the issuer's package wires a challenge solver into the ACME driver —
one authority kind today — and an authority that reads false must say why, because
"there is no challenge to solve" (an internal CA) and "a human completes DCV in
the vendor's console" (public OV/EV) are opposite operational situations. It is a
property of the build; whether a given authority is actually configured for it is
the `upstream_dns01` flag on that authority.

**Revoke is the field that matters, and it is deliberately conservative.** It is
true only where this build ships an implementation that contacts the authority
and is proven against that authority's protocol by a test:

| Issuer | Revoke | How |
|---|---|---|
| `letsencrypt` | yes | RFC 8555 §7.6 `revokeCert`, JWS-signed with the account key |
| `vaultpki` | yes | `POST {mount}/revoke` by serial number |
| `ejbca` | yes | REST `PUT /certificate/{issuer_dn}/{serial}/revoke` |

Everything else reports `false` with a note saying where to revoke instead.
DigiCert, Sectigo, Venafi, AWS Private CA, Google CAS and step-ca all document a
revocation API; trstctl does not drive any of them, and a documented endpoint
nobody has implemented is a plan rather than a capability. AD CS revocation runs
through the CA's own management interface, and Azure Key Vault disables
certificates rather than revoking them.

**No silent no-ops.** A revocation request to an authority that cannot revoke
returns `ErrRevocationUnsupported`, and the console disables the path rather
than offering it. This is the specific failure the epic exists to remove: an
operator revoking a compromised key and being told it worked, while the
authority still considers the certificate valid, is worse off than one told
plainly that trstctl cannot do it — the second sends them to the vendor console,
the first sends them home.

ACME is worth one further note. The protocol identifies the certificate to
revoke by its DER, not by serial, so trstctl cannot revoke an ACME certificate
it does not hold a copy of. A request carrying only a serial is refused with the
reason rather than sent as something the protocol cannot express.

A CI guard parses every issuer package and fails the build if the matrix and the
code disagree in either direction — a claimed capability with no implementation,
or an implementation the matrix does not advertise.

## Coverage, provenance and blind spots

A certificate count is not an inventory, and the difference is the whole of this
section. "We found 4,312 certificates" answers how many discovery happened to
turn up. An auditor asks a different question — how much of the estate did you
look at, and when — and a system built only from findings cannot answer it,
because what it never looked at leaves no trace in what it found.

**Coverage is measured against a declaration.** An operator names the segments
they own, with the ranges, an exclusion flag and reason where a segment is
deliberately out of scope, and a staleness window that is theirs to set — a DMZ
and a lab do not deserve the same answer. Coverage is then the share of
declared, non-excluded segments swept inside their own window. Excluded segments
are removed from **both** halves rather than counted as covered; a number that
rose when somebody excluded something would reward exactly the wrong behavior.

The consequence is worth stating plainly: **an estate with nothing declared
reports no coverage, not full coverage.** That reads as unhelpful on day one and
is the only defensible answer — the alternative is a system that declares itself
complete because nobody told it what it was missing.

**Every certificate carries provenance.** Which source last observed it, of what
kind, and when. `last_seen_at` is deliberately distinct from `created_at`: the
first says something confirmed the certificate still exists, the second only
says trstctl once recorded it. Conflating them makes a stale inventory look
freshly verified. A certificate this control plane issued that nothing has since
scanned has **no observation at all**, and is reported that way — it is evidence
of an issuance, not of a deployment.

**The blind spots are named, not implied.** The register lists segments never
swept, segments outside their own staleness window, segments declared out of
scope with the reason, asset classes no configured source can ever see, and the
count of inventory rows with no observation behind them. Each carries the action
that closes it, or says plainly that nothing does.

What this does not do: it does not verify that a certificate found at an address
is the certificate that address serves to a real client — that is verification,
and it is a separate claim. It does not detect a segment an operator forgot to
declare; nothing can, which is why the declaration is the operator's
responsibility and why the console says how many segments exist rather than
implying the list is complete.

## Kubernetes deployment

The control plane ships a production-shaped Helm chart
(`deploy/helm/trstctl`): the API/UI with the signing service isolated (its
own locked-down, network-unreachable sidecar), external PostgreSQL and NATS
as the default, a default-deny `NetworkPolicy`, and TLS.

- Kubernetes Operator scope: a focused CRD-driven operator ships today. The
  `trstctl-operator` binary (it rides inside the same multi-binary
  control-plane image and is run by `deploy/operator/operator.yaml` via an
  entrypoint override) reconciles `TrstctlControlPlane` custom resources
  into a managed control-plane Deployment. Its manifest documents the
  postgresql dsn secret, nats url, sidecar-signer, leader-elect, and
  coordination.k8s.io controls that keep that reconcile path bounded. It
  also reconciles `TrstctlSecretSync` custom resources into Kubernetes
  Secrets plus reload annotations, and `TrstctlSecretInjection` custom
  resources into no-code sidecar/env/file injection patches for opted-in
  `Deployment`, `StatefulSet`, and `DaemonSet` workloads. The Helm chart
  remains the richer path for the full production install. The operator
  keeps the managed Deployment's replica count, image, PostgreSQL DSN
  Secret reference, NATS URL/replica knobs, sidecar-signer socket/volumes,
  and managed-key provider enablement matching each resource's `spec`, and
  writes the observed phase back to resource status. For SecretSync
  resources it resolves values through the served secret-store API, writes
  `Secret.data`, records `status.contentHash`, and patches pod-template
  annotations instead of deleting pods. For SecretInjection resources it
  reads source Secret metadata only, patches the shipped
  `trstctl-agent --secret-inject` sidecar, app mounts, and optional env
  references, and records `status.injectedWorkloads`. It is a real,
  level-based reconcile loop (poll, diff, converge), not a stub; it speaks
  the Kubernetes API directly (no client-go/controller-runtime). The
  shipped operator manifest runs two replicas and `--leader-elect`; the
  replicas coordinate with a real `coordination.k8s.io` Lease so exactly
  one reconciles while the other remains a hot follower. It is still
  focused: it does not yet manage Services, ingress, `NetworkPolicy`, or
  the cross-pod isolated-signer Service topology. For a complete,
  production-shaped control-plane install (ingress/service wiring,
  generated secrets, default-deny `NetworkPolicy`, cross-pod signer mTLS)
  the Helm chart (`deploy/helm/trstctl`) remains the richer, recommended
  path.
- Kubernetes certificate CRDs: the Kubernetes agent ships a real trstctl
  `Issuer`/`ClusterIssuer`/`Certificate` controller. It marks trstctl
  issuer resources Ready, signs matching cert-manager
  `CertificateRequest`s through a served trstctl issuance endpoint using a
  mounted API token, signs approved native Kubernetes
  `CertificateSigningRequest`s from `certificates.k8s.io/v1`, and also
  fulfills a trstctl-native `Certificate` directly into a `kubernetes.io/tls`
  Secret. `GET /api/v1/kubernetes/certificate-signing-requests` and
  `trstctl-cli kubernetes csr` expose the CAP-K8S-04 posture, supported
  signer names, RBAC, status fields, and residuals. The cert-manager path
  is proven in CI on `kind` with real cert-manager from `Certificate` to
  TLS `Secret`; the native trstctl path is proven by the served controller
  acceptance test from trstctl `Certificate` to local CSR, signer, Secret,
  and Ready status; native Kubernetes CSR support is proven by a
  controller test that writes `status.certificate` while preserving
  `Approved` only after Kubernetes approval (native CSRs do not define a
  Ready condition). It is still a small poll-based controller rather than
  an informer/work-queue controller. Because the agent runs as a DaemonSet,
  the cluster-scoped controller elects a single reconciler through a
  `coordination.k8s.io` **Lease** (`trstctl-agent-issuer-controller`, 30s
  duration, identity from the pod's `POD_NAME`): one pod reconciles, the
  others idle, and a follower takes over within one lease duration if the
  holder dies. If the Lease RBAC is absent the agent logs once and reconciles
  anyway — duplicated idempotent work beats no controller. The namespaced
  cert-manager bridge does not contend. CSR approval policy remains a
  Kubernetes approver responsibility — operational/governance boundaries, not
  missing signing functionality.
- Multi-replica HA: the Helm chart runs the control plane multi-replica by
  default (`replicaCount: 2`, `RollingUpdate maxUnavailable: 0`,
  PodDisruptionBudget, pod anti-affinity), and running >1 replica is safe:
  leader election (a PostgreSQL session-scoped advisory lock) gates the
  continuous background workers — the outbox dispatcher, audit retention,
  idempotency/outbox GC, the projection tailer, the CRL scheduler, and the
  read-model snapshot worker — to exactly one replica so they never
  double-apply, with automatic failover to a follower on leader loss; all
  replicas serve reads. A shared signer key store
  (`persistence.signerKeysAccessMode: ReadWriteMany`) means every pod's
  locked-down sidecar signer (the isolated key-holder process) loads the
  same sealed issuing-CA key, so all replicas are the same CA (first-boot
  provisioning is serialized by an advisory lock). For a single signer pod
  that serves all replicas independently, set `signer.mode: isolated`: the
  signer runs as its own pod reached over a cross-node mTLS gRPC channel —
  TLS 1.3, AEAD-only, with the control plane and the signer each pinning
  the other's certificate (an untrusted or merely CA-signed-but-unpinned
  peer is rejected). The `trstctl-signer` binary serves `--mtls-listen` and
  the control plane dials it with `signer.mtls_address`; the chart renders
  the signer Deployment/Service/NetworkPolicy on `:9443` when you supply
  the `signer.mtls.*` certificate material. The default co-located sidecar
  (UDS) topology remains the simplest single-pod option and is not
  required to change for the HA above. See
  [disaster recovery → High availability](disaster-recovery.md). (The
  agent, separately, runs as a DaemonSet across all nodes.)
- Cross-cluster federation is passive read-state replication: a passive
  cluster can import a peer event log, keep a durable per-peer cursor, and
  project the imported tenant/trust/certificate/audit read state locally
  for failover. It is intentionally not an active-active write conflict
  resolver — keep one writable region for a tenant at a time, stop or fence
  primary writes before promotion, and use `TRSTCTL_FEDERATION_RPO` /
  `TRSTCTL_FEDERATION_RTO` as measured runbook targets.

## Non-functional targets: what is measured vs. aspirational

We separate NFRs that have executable evidence from ones that are
aspirational and not yet measured in CI, so neither is silently
over-claimed.

- Performance & scale NFRs are measured: the hot-path latency/throughput
  SLOs and the capacity model are pinned to committed measurement receipts
  by an executable smoke gate (`make perf-smoke`) and a served
  realistic/peak live-load gate (`make perf-live`), and sustained-load
  endurance is pinned by a soak gate (`make soak`) that fails on a leak
  slope or an SLO breach. These are local eval/self-test scale
  denominators, not a substitute for a customer-specific multi-hour load
  test at your own capacity tier.
- Usability outcome NFRs are evidence-gated. `USABILITY-SLO-001` has
  automated wizard timing evidence: the
  `scripts/usability/first-run-receipt.json` receipt is generated by
  `scripts/usability/measure-first-run.mjs`, which walks the first-run
  wizard contract (internal CA confirmation, first certificate issuance,
  served connector deployment, upstream-CA issuance, dynamic-secret lease
  issuance, enrollment-token minting, and agent detection) and keeps that
  assisted path inside a 15 minute time-to-first-certificate budget. The
  scope is intentionally narrow: it measures the browser journey and
  served API-client contract in CI, not human reading time, package
  download time, real network latency, or the physical agent installation
  step. `USABILITY-SLO-002` for operator-satisfaction / NPS has a receipt
  gate but no numeric NPS claim: the current
  `scripts/usability/operator-study-receipt.json` is `no_numeric_claim`,
  and release tooling fails closed if release notes publish NPS, CSAT, or
  operator-satisfaction numbers before a real measured external-operator
  study receipt replaces it. See [Usability outcome SLOs](usability.md).

## How to read the roadmap against this

The source-checkout `README.md` capability table
describes what is built and tested; this page tells you what is served by
the binary today. When the two differ, this page is the authority for what
you can rely on at runtime.

## Non-production entitlement boundary

The signed non-production entitlement is an offline deployment binding, not a
traffic classifier. Version 2 licenses enumerate one production ID and at most
three non-production IDs; the binary refuses an operator-declared runtime ID or
environment that does not match. It cannot independently prove that a host
called `non_production` carries no real-user traffic, because doing so would
require surveillance or phone-home state that the product explicitly avoids.

Version 1 license files predate environment binding. They remain loadable for
upgrade continuity but are production-only and cannot claim the bundled
non-production entitlement. Issue a v2 file before moving a legacy deployment
into a staging or test slot.
