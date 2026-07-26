# Current limitations & what's not yet served

trstctl is pre-1.0 and under active hardening. This page states plainly what the
running binary serves today versus what is built and tested as library code but
not yet wired into the served product, and which surfaces are explicitly Phase 2.
Maturity is separate from edition gates: Community self-host includes the core
control plane; Enterprise and Provider capabilities activate by an offline signed
license behind the `ee/` boundary. trstctl is MPL-2.0 open core under `LICENSE`;
Enterprise, Provider, PQC, and other license-gated features are proprietary
material under `ee/LICENSE`.

If a capability matters to your evaluation, check this page before relying on it.

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
| F66 | Encryption-as-a-service and KMIP | docs/features/secrets.md |

### Library-only

| ID | Feature | Primary docs |
|----|---------|--------------|

### Roadmap

| ID | Feature | Primary docs |
|----|---------|--------------|

<!-- feature-served-state-matrix:end -->

## Status at a glance

One line per domain below, for a reader who wants the answer without the prose.
"Served" here always means the running binary, not a library package.

| Domain | Status | Detail |
|---|---|---|
| Core inventory, lifecycle, connectors, discovery | Served end to end | [Served by the running binary today](#served-by-the-running-binary-today) |
| Tenant offboarding & audit retention | Served; PostgreSQL rows erased, event log/archive follow separate retention | [Tenant offboarding boundary](#tenant-offboarding-boundary) |
| Library-only backlog | Empty — nothing is stuck library-only right now | [Built and tested, but not yet served](#built-and-tested-but-not-yet-served-by-the-binary) |
| Conditional/partial residuals | Real served spine; specific operator-facing edges remain | [Conditional, partial, and residual boundaries](#conditional-partial-and-residual-boundaries) |
| React web console | Served: real embedded Vite build at `/`, generated API types | [The React web console](#the-react-web-console-served-by-the-binary) |
| OIDC/SAML/LDAP browser login & tenancy | Served behind config flags; each user maps to a real tenant | [Browser login & sessions](#interactive-oidc-saml-and-ldap-active-directory-browser-login-sessions-served-by-the-binary) |
| SCIM 2.0 + NHI inventory/posture | Served; SCIM Bulk and directory writeback not implemented | [SCIM 2.0 provisioning](#scim-20-provisioning-served-by-the-binary) |
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
  bytes are returned.
- Automated endpoint binding: `POST /api/v1/lifecycle/endpoint-bindings` creates the
  X.509 identity for an existing owner, provisions or references the connector
  target, binds the identity to that endpoint, and queues issue/deploy work through
  the outbox. The leader lifecycle scheduler later renews the identity and sends the
  successor back through credential-bearing `connector.deploy` work.
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
  `buildRunDeps` constructs the operator-selected production registry; strict
  target schemas bind endpoint/filesystem/process and same-tenant secret
  references before a served issue/deploy route can enqueue work.
  Credential-bearing `connector.deploy` payloads exist only while needed, travel
  through the durable outbox, and are wiped after delivery. The DoD proof requires
  provider-specific mutation plus independent external readback before a connector
  counts as served. Inventory: nginx, Apache, Caddy, Envoy, IIS, HAProxy, F5,
  NetScaler, A10, Kemp, Cisco, FortiGate, Palo Alto, Postfix, Traefik, AWS ACM,
  Azure Key Vault, GCP Certificate Manager, Java keystore, PostgreSQL, MySQL,
  RabbitMQ, Elasticsearch, and Tomcat.
- Discovery control plane + network, cloud-certificate, CT-log, drift execution,
  and SSH host-key execution: the running binary serves discovery sources,
  schedules, and runs under `/api/v1/discovery/*` — create/list a source,
  create/list a schedule, queue a run (idempotent, deduplicated by
  `Idempotency-Key`), read runs and findings (keyset-paginated), and read
  `GET /api/v1/discovery/monitoring` for the centralized continuous-monitoring view
  across sources, schedules, last runs, findings, and inventory counts.
  `GET /api/v1/certificates/health` and `trstctl certificates health` serve the
  estate-wide expiry/source dashboard over the same inventory projection,
  including certificates issued elsewhere and later imported or discovered.
  Queuing a run is an immutable `discovery.run.queued` event; the scan intent is
  journaled to the outbox, and an outbox worker then executes the run with
  at-least-once delivery. For a **network** source the worker runs a real
  certificate sweep on its own bounded worker lane (a flood fast-rejects rather
  than starving other subsystems) — the served network scan execution path. For a
  **cloud_certificate** source the worker executes AWS ACM, Azure Key Vault, and
  GCP Certificate Manager enumeration through credential references — served
  cloud-certificate discovery execution. For a **ct_log** source the worker polls
  configured RFC 6962 log fixtures or public logs, checkpoints each log, and
  records unexpected issuance as `ct_unexpected_issuance` findings — this is
  served through the served discovery worker, queuing notification alerts the
  same way expiry alerts do. For a **drift** source the worker compares configured
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
  migration targets and `migration_progress`. The MPL core names only
  edition-neutral transition targets; with the Enterprise PQC feature
  licensed, the targets are the concrete FIPS 203/204/205 algorithms and
  `migration_progress` counts which assets are already post-quantum-ready.
- Credential-compromise incident execution: when the Enterprise `remediation`
  feature is licensed, `POST /api/v1/incidents/executions` drives a served,
  idempotent (deduplicated by `Idempotency-Key`), history-reconstructable
  single-identity remediation — replacement issue/deploy, revocation,
  blast-radius capture, and a sealed evidence pack readable via
  `GET /api/v1/incidents/executions{,/{id}}`. Automated remediation playbooks are
  also served under the same Enterprise feature: `GET /api/v1/remediation/playbooks`,
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
  separately at `POST /api/v1/incidents/fleet-reissuance-runs` with
  pause/resume/rollback and evidence export routes under
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
  auth remains the default when SSO is disabled.
- SCIM 2.0 provisioning is served when `auth.scim.enabled` is set — see
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
  CAP-CMP-05 (CC6/CC7/CC8-style access, monitoring, and change evidence), keeping
  CPA examination and trust-services scope as residuals. `GET
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
- notification routing matrix and inbox: expiry, CT, drift, and workflow alerts
  resolve through the configured severity-to-channel matrix, dedup by
  per-subject/threshold/channel, and are inspectable through the served
  notification inbox with owner/approver escalation fields and dead-letter requeue.
- MCP-vs-REST parity guard: the served MCP automation surface includes broad
  route-backed REST tools in addition to the named investigation tools, and CI
  fails when a served REST route is missing both an MCP mapping and an explicit
  allowlist.
- Cert-ops console parity: issuer catalog and Test connection, operations queue,
  Notifications inbox, richer certificate filters, dashboard charts, CTA empty
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
archive-then-prune of audit records, and use **Privacy Retention** for non-audit
personal data pseudonymization. WORM/object-store archive cleanup and legal
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
  served issue route journals the request before the upstream call, and the DoD
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
  also served, as is the AI/RCA/MCP surface behind `ai.enable_api`.
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
  (`/audit`, event list + evidence export), dual-control approvals from the
  identity table, licensed incident execution (`/incidents` — replacement
  issue/deploy, fleet reissuance, revocation queue, connector receipt,
  rollback evidence, remediation playbooks, response dispatch, sealed audit
  bundle), and the Assistant/RCA/MCP console (`/assistant`). Deliberately
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

The SCIM 2.0 provisioning surface is served by the running binary behind
`auth.scim.enabled`. It mounts `GET /scim/v2/ServiceProviderConfig`,
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
  delete), `POST /api/v1/secrets/store/import` (all-or-nothing tree import),
  `GET /api/v1/secrets/store/{name}?resolve=true` (`${secret.path}` reference
  expansion with cycle rejection), `GET
  /api/v1/secrets/store/history/{name}?version=N` (read one prior sealed
  version), and `POST /api/v1/secrets/store/recover/{name}` (point-in-time
  recovery). Values are sealed at rest under the KEK. `trstctl-cli run --secret
  ENV=path -- <cmd>` wraps the same read path, injecting values only into the
  child process environment.
- The Vault/OpenBao compatibility shim backs the common migration paths
  `GET /v1/auth/token/lookup-self`, KV mount-discovery preflight for
  `secret/`, `POST/PUT/GET /v1/secret/data/{path}`, and
  `POST/PUT /v1/pki/issue/{role}` for stock `vault` CLI token lookup, KV v2
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
  response opens the sealed credential. The DoD proof logs in with each
  generated credential, rotates it, revokes both copies, and verifies both are
  rejected afterward.
- Secret rotation (F37) backs `POST /api/v1/secrets/rotations` — a
  four-phase stage/cutover/verify/retire flow through concrete PostgreSQL,
  MySQL, and AWS IAM rotators, `connector:<target>` secret-sync handoffs, and
  `dynamic-lease:<provider>` replacement leases. A failed cutover or
  verification returns rollback metadata only, restores the previous consumer
  pointer when possible, and revokes the staged backend credential without
  returning secret material.
- PKI-as-a-secret / dynamic certificate leasing (F67) backs
  `POST /api/v1/secrets/pki` — issues a short-lived certificate and its
  private key (a usable TLS identity, `tls.X509KeyPair`-loadable) through the
  issuing CA in the out-of-process signer, recorded on the served revocation
  pipeline so a revoked dynamic-secret cert stops validating.
- Secret sharing (F60) backs `POST /api/v1/secrets/shares` + `.../redeem` —
  a one-time self-destructing share that redeems exactly once; the bearer
  token is never written to the audit/event log.

Every served route is auth-gated (API token or session, `secrets:read` /
`secrets:write`), tenant-scoped, idempotent (deduplicated by
`Idempotency-Key`), and recorded as immutable events; secret values are held
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
writes externally. The DoD proof enforces exact target authentication,
decrypts GitHub's X25519 sealed box in a separate receiver process, and
independently reads every destination value back. `GET
/api/v1/secrets/syncs/targets` shows the catalog and this installation's
configured targets.

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
command group for tenant-scoped key create/rotate, encrypt/decrypt, rewrap,
HMAC, sign, and verify. Transit keys never leave the process as exportable
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
listener management remain deliberate gaps.

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
  blast-radius acknowledgement and `validation_method=dns-01`; deployed
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
  provisioned and fails closed otherwise. Roadmap residual: a dedicated ACME
  admin console for account/order/challenge drilldown, revocation/ARI
  operations, and richer client setup controls remains outside the F5
  GA-served protocol denominator.
- EST (RFC 7030), SCEP (RFC 8894), CMP (RFC 4210/6712), the SPIFFE Workload
  API, and the SSH CA issuance servers are served end-to-end by the running
  binary, each behind the same issuance seam as the API mint: signed in the
  isolated signer, tenant-scoped, recorded as immutable events, idempotent,
  and profile-gated:
  - EST at `/.well-known/est/...` (Bearer-API-token authenticated on top of
    TLS), SCEP at `/scep`, CMP at `/cmp` — mounted on the control-plane mux
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
  issuing CA is provisioned.
  - Reference-implementation differentials: cross-checked against
    an *independent* implementation, not just our own parser. ACME: a
    differential against Pebble (the reference test ACME CA) as a dedicated
    CI job, plus a stock certbot CI transcript (certbot manual DNS-01
    issues, renews, and revokes through the served `/directory` endpoint
    while CI archives public challenge records, client logs, and issued
    certificates). EST: a differential against the OpenSSL `pkcs7`
    parser/verifier on every `make test` (so `/cacerts` and `/simpleenroll`
    output is validated by code we did not write), plus a dedicated CI job
    that builds a checksum-pinned libest `estclient` from source and
    requires it to perform simpleenroll against the served EST endpoint.
    SPIFFE Workload API: a served stock-client differential — the real
    go-spiffe `workloadapi` client fetches an X.509-SVID, a JWT-SVID, and
    JWT bundles, and validates the JWT-SVID over the served UDS; stock
    `spiffe-helper` writes the served X.509-SVID, key, and trust bundle to
    disk. CMP: a dedicated stock-client CI transcript — OpenSSL
    `cmp -cmd p10cr` creates the request, enrolls through the served `/cmp`
    endpoint, accepts the protected response, and uploads the
    request/response/cert/log artifacts. SCEP: a dedicated stock-client CI
    transcript — a SHA-256-pinned `sscep` v0.10.0 build fetches the served
    CA, enrolls through `/scep/pkiclient.exe`, and uploads the captured
    PKIOperation request/response plus client logs. TSA: a dedicated
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
  the graph. The React Workloads page submits broker proof fields to the
  served route, clears them after issue, and stores only returned metadata
  in browser state; a tenant-wide broker history list remains a roadmap
  residual, so use REST/CLI automation and audit search for durable broker
  evidence.
- Ephemeral / JIT issuance (REST): `POST /api/v1/ephemeral` is served when
  ephemeral issuance is configured with attestors, approval TTL/threshold,
  trust domain, and signer-backed issuing CA. A requester with
  `certs:request` presents a proof and public key; trstctl verifies the
  proof, opens an approval request, and enqueues the approval notification
  intent in the same tenant transaction. A distinct approver with
  `certs:issue` records approval at
  `POST /api/v1/ephemeral/{request_id}/approvals`; the requester then calls
  `/api/v1/ephemeral` with a fresh `Idempotency-Key` to mint the short-TTL
  credential. Ephemeral API keys are served separately at
  `POST /api/v1/ephemeral/api-keys` and `trstctl-cli ephemeral api-keys
  issue`: callers provide `subject`, `scopes`, and `ttl_seconds`, the raw
  token is returned once, and the leaseworker emits `api_token.revoked` at
  expiry. The React Workloads page still does not collect raw proof
  material or render approval controls; use REST or
  `trstctl-cli ephemeral issue/approve` / `trstctl-cli ephemeral api-keys
  issue`.
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
  `agent.mtls.ReportInventory` path and the endpoint source kinds accepted
  by that channel (`filesystem`, `pkcs11`, `windows-store`, `k8s-secret`,
  `trust-store`, and `private-key`), so the console can show a real
  endpoint-discovery capability panel instead of treating agent discovery
  as unavailable telemetry. The channel is behind its own bounded agent
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
Directory. OIDC supports the authorization-code flow against Microsoft Entra ID /
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
demo is not the DoD receipt source. Static no-cgo signer builds fail closed for native
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
narrower today: EST accepts and issues them (the licensed PKCS#10 parser
sits behind EST's verifier seam, proven against a stock OpenSSL 3.5
client), and ACME hands the CSR bytes to the same licensed issuer without
parsing them first; SCEP and CMP still verify CSRs with the core parser
before the licensed parser is consulted and therefore reject pure ML-DSA —
SCEP additionally cannot deliver its CMS-enveloped reply to a
signature-only subject key, a protocol limit rather than a code gap. One
ceiling applies everywhere: the issuing CA key itself remains classical
ECDSA-P256 (post-quantum keys are subject keys, not issuer keys, in the
served path). Certificate-profile `allowed_key_algorithms` labels accept
the post-quantum and hybrid names when PQC is licensed — a pure label
matches its exact inspected CSR algorithm, while a hybrid enrollment
carries a classical subject key and stays governed by its classical family
label; unlicensed builds keep failing closed on those labels.

The discovery side knows these algorithms when licensed: the licensed CBOM
posture recognizes ML-DSA, ML-KEM, and SLH-DSA / SPHINCS+ (and hybrid
labels) as quantum-safe when it finds them in your estate, while the MPL
core deliberately names no licensed algorithm and classifies those labels
as unrecognized. Because all cryptography enters through one isolated
path, each scheme is a contained boundary implementation (a CIRCL scheme
plus known-answer tests), with no ripple into the rest of the system. The
served CBOM inventory exposes this posture through
`GET /api/v1/cbom/assets`: with PQC licensed, classical signing algorithms
are mapped to ML-DSA-65/FIPS 204 targets, key-establishment findings (TLS
protocols and ciphers) to ML-KEM-768/FIPS 203, deprecated DSA to
SLH-DSA/FIPS 205, and `migration_progress` shows how much of the observed
estate is already post-quantum-ready — pure post-quantum assets count as
future-ready, while hybrids stay migration-required until they shed their
classical component.

The proprietary EE attach serves three former end-to-end residuals behind
one license boundary: a stock OpenSSL 3.5 client creates an RFC 9881
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
through EST (and as the SPIFFE Workload API's licensed second SVID), and
CMP consults the same licensed parser for its carried CSR (PKIMessage
protection stays classically verified). SCEP cannot by protocol, and the
direct identity API intentionally has no CSR input at all — it generates
classical keys server-side, so CSR-based enrollment, including licensed
subject algorithms, belongs to the enrollment protocols. See
[Lifecycle & PQC](features/lifecycle-and-pqc.md) for operator flow and
license placement.

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
  fulfils a trstctl-native `Certificate` directly into a `kubernetes.io/tls`
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

The [README capability table](https://github.com/ctlplne/trstctl#capabilities)
describes what is built and tested; this page tells you what is served by
the binary today. When the two differ, this page is the authority for what
you can rely on at runtime.
