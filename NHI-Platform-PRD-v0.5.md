# Product Requirements Document
## Unified Non-Human Identity Platform

> **Name:** *certctl* — pronounced "cert control." Final, founder-owned name (domain held). Echoes `kubectl`: a command-line, infrastructure-native credential control plane.
> **Owner:** Shankar
> **Status:** Draft v0.5
> **Last Updated:** May 28, 2026
> **Changelog (v0.5):** Renamed the product from the working title *Helix* to **certctl** (pronounced "cert control") throughout — it is now the final, founder-owned name, with the domain held. Removed Appendix A (naming candidates), which is moot. Build-document code identifiers were updated to match (`cmd/certctl`, `cmd/certctl-signer`, `cmd/certctl-agent`, `tools/certctllint`). The name is styled lowercase, kubectl-style, in all positions.
> **Changelog (v0.4):** Final consistency pass. Dropped Redis as a rate-limiting option — rate limiting is now PostgreSQL-backed, preserving the "one binary, Postgres + NATS only" dependency story. Extended F32 so fleet re-issuance explicitly covers SSH CA key compromise (rotate the SSH CA, re-sign host/user certs, redistribute `TrustedUserCAKeys`, publish an updated KRL), making the F43→F32 cross-reference real in both directions. Broadened F26 so HSM/KMS protection covers all CA signing keys, including the chainless SSH CA key. Split the compliance-posture statement by GA so SOC 2 + FIPS attach to the Phase 1 (open-source) GA and FedRAMP Moderate attaches to the managed-tier GA, removing an early over-promise. Added S3-compatible object storage to the dependency list (optional; audit archive only). Added an SSH destination to the agent sample story.
> **Changelog (v0.3):** Added SSH as a first-class credential type, integrated throughout rather than appended — an SSH certificate authority (short-lived host and user certificates with principals, validity, and extensions) plus discovery and lifecycle management of raw SSH keys. SSH discovery lands in Phase 1 (it rides the existing handshake-scan and agent discovery); the SSH CA, agent deployment, KRL revocation, and attestation-gated short-lived user certs land in Phase 2 (they reuse the signing path and the Phase 2 attestation chain). Reflected in the vision, differentiator, problem framing, feature tables (F42–F45), AN-3, the architecture diagram, the data model, system components, performance targets, the implementation plan, risks, and the competitive appendix. SSH is scoped as credential lifecycle, not session brokering — certctl does not proxy or record SSH sessions.
> **Changelog (v0.2):** Removed all calendar timelines (build proceeds at the founder's pace; phase numbers now denote build order only). Standardized on PostgreSQL as the datastore in every deployment mode (SQLite removed). Made NATS JetStream the event store in every mode so the AN-2 truth model is identical across single-node and clustered deployments. Corrected the AN-4 signing-service description in F14. Reconciled CA, connector, and ephemeral-TTL lists across sections. Resolved licensing and telemetry from "open questions" to decided positions (source-available core, no feature gating; telemetry off by default). Relabeled scale figures as cluster-scale design targets vs. single-node validated baselines.

---

## 1. Executive Summary

### Product Vision

A **self-hosted, source-available platform** that manages the full lifecycle of every non-human identity credential — X.509 certificates, SSH host and user certificates, secrets, API keys, tokens, and SPIFFE workload identities — from discovery through issuance, rotation, revocation, and retirement, across hybrid cloud and on-premises infrastructure.

**One sentence:** *certctl is the self-hosted control plane for every credential that isn't a human.*

**Target user:** Platform engineering and security teams at mid-market to enterprise organizations that cannot or will not put credential infrastructure in a vendor SaaS.

**Differentiator:** The only self-hosted, source-available platform that combines (a) CA-agnostic certificate lifecycle management, (b) built-in ACME/EST/SCEP issuance protocols, (c) SPIFFE/SPIRE-compatible workload identity with ephemeral credentials, (d) discovery + lifecycle automation for secrets, API keys, and tokens, and (e) an SSH certificate authority that signs short-lived host and user certificates, paired with discovery and lifecycle management of the raw SSH keys already scattered across the fleet — in one self-hosted binary, with no features gated behind a paid tier. SSH is a first-class credential type, deliberately distinct from the X.509 issuance protocols (ACME/EST/SCEP issue X.509 only): SSH has its own certificate format, a single trusted signing key rather than a chain, and revocation by short lifetimes and Key Revocation Lists.

### Success Definition (targets, no fixed dates)

| Metric | Target |
|---|---|
| GitHub stars | 5,000 |
| Active deployments (opt-in telemetry; reported figure is a lower bound) | 750 |
| Community members (Discord/Slack) | 2,000 |
| Production users on managed/enterprise tier | 10 paying |
| Strategic acquirer inbound conversations | 3+ |

### Strategic Alignment

- **Business objective:** Build toward acquisition by an NHI/IAM/PAM consolidator (CyberArk, Okta, BeyondTrust, Saviynt, HashiCorp/IBM, Wiz/Google). CyberArk's $1.54B Venafi acquisition (2024) is the comp.
- **User problem solved:** NHI sprawl across certs, secrets, and API keys is unmanaged outside of expensive enterprise SaaS; mid-market and regulated industries have no self-hosted alternative.
- **Market timing:** AI agents and workload proliferation are pushing NHI to credential ratios of 50:1 vs. humans. 2025 saw $400M+ in NHI-specific funding. Category is forming; window is now.
- **Competitive advantage:** Self-hosted + source-available + unified scope. No incumbent occupies this position.

### Resource Requirements

- **Team (initial):** Solo founder, technical (founder is full-time). Plan to add 1 senior Go engineer in Phase 2 and 1 developer-relations hire in Phase 3 if revenue/funding supports it.
- **Sequencing:** Phased build in the order described in Sections 4 and 9. No fixed calendar; phases proceed at the founder's pace. The commercial tier follows once the open-source foundation is established.
- **Budget:** Bootstrapped from founder's personal capital through Phase 2; commercial revenue or strategic funding in Phase 3+.
- **External:** Community contributors for connector coverage; advisory network from PKI/IAM industry.

---

## 2. Problem Statement & Opportunity

### Problem Definition

Non-human identities — certificates, SSH keys, secrets, API keys, OAuth tokens, service accounts, workload identities — now outnumber human identities in most enterprises by an estimated 45:1 to 92:1, depending on study. Their management is fragmented across at least four product categories:

1. **Certificate Lifecycle Management (CLM)** — Venafi, Keyfactor, Sectigo, DigiCert ONE. Expensive enterprise SaaS or heavyweight on-prem; no real open-source equivalent at parity.
2. **Secrets Management** — HashiCorp Vault (now IBM), AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, CyberArk Conjur. Operational overhead is high; no unified discovery of what's *not* in the vault.
3. **NHI Discovery & Posture** — Astrix Security, Oasis Security, Entro, Clutch. SaaS-only, discovery-focused, weak on lifecycle automation.
4. **Workload Identity** — SPIRE, cert-manager, Istio Citadel. Purist primitives; require deep operator expertise; no UI, no CA management, no integration with legacy infrastructure.

The result is that the average enterprise runs four-to-six products, none of which cover the full surface, none of which are self-hostable with full functionality, and none of which speak to each other natively. SSH access sits as its own fragmented island on top of all of this: SSH key sprawl is the canonical unmanaged-NHI problem — most environments hold far more keys than people, many of them orphaned and granting standing access that nobody can enumerate — and the comparables that address it (HashiCorp Vault's SSH secrets engine, Smallstep, Teleport) are themselves separate products that do not unify SSH with certificate, secret, and workload-identity lifecycle.

### Quantified Impact

- **Outage cost:** Gartner estimates expired-certificate-driven outages at an average of $300K per incident; high-profile public incidents (Microsoft Teams, Slack, Cisco, Spotify) recur annually.
- **Breach cost:** IBM's 2024 Cost of a Data Breach report attributes $4.88M average to breaches involving compromised credentials.
- **Workload identity gap:** As AI agents proliferate, every new agent is a workload needing an identity. Static API keys (the common shortcut) are the dominant credential compromise vector.

### Opportunity Analysis

- **Market size:** The CLM market alone is ~$1.5B and growing 18% CAGR. Secrets management is ~$2B. NHI security is the fastest-growing adjacent category. Combined TAM in the relevant adjacencies is $8–10B by 2028.
- **Target segment:** Initially, platform/SRE teams at 500–10,000-employee organizations in regulated industries (finance, healthcare, government, defense, critical infrastructure) who cannot send credential metadata to vendor SaaS. Estimated 25,000+ organizations globally.
- **Revenue path:** A fully-featured, self-hosted, source-available edition (no feature gating) drives adoption; revenue comes from commercial and enterprise licenses — including MSP/reseller rights — plus support and a managed cloud offering. Acquisition is the primary exit.
- **Competitive gap:** No competitor today combines self-hosted + source-available + unified scope across certs, SSH, secrets, and workload identity. SPIRE is the closest on workload identity, and Vault's SSH engine, Smallstep, and Teleport are the closest on SSH, but each solves only its own slice and requires assembly.

### Success Criteria

**Primary:**
- Adoption: 5,000 GitHub stars and 750 active deployments.
- Engagement: Median active deployment manages >100 credentials within 90 days of install.
- Revenue: 10 paying customers on managed or enterprise tier.

**Secondary:**
- Community: 2,000-member Discord/Slack; 50+ external contributors.
- Strategic: 3+ inbound acquisition conversations.
- Brand: Recognition in Gartner NHI/CLM coverage; speaking slot at one major conference (RSA, KubeCon, Black Hat).

---

## 3. User Requirements & Stories

### Primary Personas

**P1 — "Maya, the Platform Lead"**
- Director of Platform Engineering at a 2,000-person fintech
- Owns Kubernetes, CI/CD, internal PKI, and developer experience
- Pain: Certs expire and cause outages; engineers store API keys in Slack; no central inventory; Vault is half-implemented
- Goal: One control plane for credential lifecycle that the platform team can self-host and that developers will actually use
- Success: Zero expiration outages; >90% of new services onboarded with automated cert + secret provisioning

**P2 — "David, the Security Engineer"**
- Staff Security Engineer at a healthcare SaaS company
- Owns compliance posture (HITRUST, SOC 2), incident response, and identity governance
- Pain: Cannot answer "where is every cert/secret/key in our environment?"; audit findings recur; SaaS NHI tools are too expensive and cannot ingest on-prem data
- Goal: Continuous discovery and inventory across hybrid environment, with policy enforcement and audit trail
- Success: Audit cycle reduced from 6 weeks to 2; mean-time-to-rotate on incident-triggered credentials drops to <1 hour

### Secondary Personas

**P3 — "Priya, the Application Developer"** — wants to request a cert or secret from a self-service portal, integrate via SDK, and forget about expiration.

**P4 — "Tom, the Compliance Lead"** — wants reports, evidence collection, and policy attestation without engineering involvement.

### User Journey: Current State vs. Future State

**Current state — issuing a new service certificate at a regulated mid-market:**
1. Developer files a Jira ticket
2. Platform team manually generates CSR or uses internal script
3. Submits to CA via web portal (1–3 days)
4. Manually installs on target system
5. Sets a calendar reminder for renewal (~365 days later)
6. Reminder is missed or owner has changed roles → outage

**Future state with certctl:**
1. Developer requests cert via portal, CLI, or auto-provisioned by ACME from their workload
2. certctl routes to appropriate CA (internal/public) per policy
3. Agent installs and configures on target host
4. certctl monitors, auto-renews at threshold, audit log captured
5. Revocation is single-click or policy-triggered

### Core User Stories (Epic-Level)

**EPIC-01: Certificate Lifecycle Management**
- *As a platform engineer, I want continuous discovery of every certificate in my environment so I can eliminate surprise expirations.*
- *As a security engineer, I want to enforce policy on which CA can issue for which domains so unauthorized issuance is blocked.*
- *As a developer, I want to request a cert via ACME and have it installed and renewed automatically so I never think about it.*

**EPIC-02: CA Integration**
- *As a platform engineer, I want to plug in any CA (DigiCert, Sectigo, Let's Encrypt, internal Microsoft ADCS, EJBCA, Smallstep) without code changes.*
- *As a security engineer, I want to broker requests through certctl so the upstream CA never sees direct developer access.*

**EPIC-03: Built-in Issuance Protocols**
- *As a platform engineer, I want certctl to act as an ACME server for internal workloads so cert-manager and other clients work natively.*
- *As a network engineer, I want EST and SCEP endpoints so legacy network devices can enroll.*

**EPIC-04: Workload Identity (SPIFFE)**
- *As a platform engineer, I want a SPIFFE Workload API that issues short-lived X.509-SVID and JWT-SVID so AI agents and microservices can authenticate without static credentials.*
- *As a security engineer, I want ephemeral, short-lived certificates (sub-hour TTL, configurable down to a few minutes for high-risk agentic workloads) so credential theft has near-zero blast radius.*

**EPIC-05: Discovery (Non-Certificate Credentials)**
- *As a security engineer, I want to discover where API keys, tokens, and secrets exist across our environment so I can inventory and prioritize them.*
- *As a platform engineer, I want lightweight network-based discovery for certs (port-range TLS handshake scans) so I don't need agents everywhere to get a baseline.*

**EPIC-06: Secret & API Key Lifecycle**
- *As a developer, I want to issue an API key bound to a workload with a 20-minute TTL so we eliminate long-lived secrets in code.*
- *As a platform engineer, I want rotation automation for vault-managed secrets so I can move from "we store it" to "we rotate it."*

**EPIC-07: Deployment Connectors**
- *As a network engineer, I want to deploy a renewed cert to F5 BIG-IP, FortiGate, Palo Alto, NGINX, IIS, Apache, Tomcat, Kubernetes ingress, and AWS ACM without writing a single script.*

**EPIC-08: Policy & Governance**
- *As a security engineer, I want declarative policy (Rego or similar) over issuance, deployment, and revocation so I can enforce compliance at runtime.*

**EPIC-09: Audit & Compliance**
- *As a compliance lead, I want immutable audit logs of every credential event so I can produce evidence for SOC 2, PCI-DSS, HIPAA, and FedRAMP audits.*

**EPIC-10: Agent Architecture**
- *As a security engineer, I want the in-network agent to perform all key operations locally so private keys never traverse the platform.*

**EPIC-11: SSH Credential Lifecycle**
- *As a platform engineer, I want every SSH host key and `authorized_keys` entry across my fleet discovered and inventoried so I can finally enumerate the standing access that nobody can currently account for.*
- *As a security engineer, I want an SSH certificate authority that signs short-lived host and user certificates so we can retire long-lived raw keys and let most revocation happen by expiry.*
- *As a security engineer, I want SSH user certificates gated by the same attestation chain as our workload identities so SSH access is attested and expiring rather than standing.*

### Sample Story with Acceptance Criteria

**Story:** As a platform engineer, I want to enroll a Linux host for automated certificate management via the certctl agent so the host can request, install, and renew certificates without manual intervention.

**Acceptance criteria:**
- Agent installs via single command (curl-pipe-bash or signed package) on Ubuntu 22.04+, RHEL 8+, Debian 11+, and Amazon Linux 2/2023
- Agent registers to certctl server using a one-time bootstrap token or attestation (cloud metadata, K8s service account token, or TPM)
- Agent uses mTLS to communicate with certctl server; certificate is rotated automatically
- Agent generates keys locally; private keys never leave the host
- Agent supports filesystem, PKCS#11 (HSM), and Windows certificate store as key/cert destinations
- For SSH-managed hosts, the agent can install a host certificate and configure `sshd` to trust the SSH CA, applied additively and validated with rollback so a misconfiguration cannot lock the operator out (F44)
- Operator can issue a cert from the certctl UI/CLI/API targeting that host and the cert is installed within 60 seconds
- Audit log records every agent action with cryptographic integrity

**Definition of done:**
- All supported platforms pass integration tests
- Agent binary is signed (Sigstore/cosign) and reproducible
- Documentation includes install, troubleshooting, and uninstall
- Telemetry (opt-in) reports agent version, OS, and credential count

---

## 4. Functional Requirements

Every feature listed in this section is required. Phase numbers reflect build order, not priority, and carry no fixed dates.

### Phase 1 — Foundation

| ID | Feature | Description |
|---|---|---|
| F1 | Certificate inventory | Central database of every known cert with metadata (subject, SAN, issuer, validity, owner, deployment location) |
| F2 | Network discovery | Lightweight handshake scanner over operator-defined IP/port ranges — TLS handshakes for X.509 and the SSH protocol handshake for SSH host keys; non-invasive; results merged into inventory |
| F3 | Agent-based discovery | certctl agent inventories certs in filesystem, Windows store, PKCS#11, Kubernetes secrets, and SSH material on the host (host keys, user keys, `authorized_keys`, `known_hosts`, and `sshd` trust configuration) |
| F4 | CA-agnostic outbound issuance | Plugin architecture for upstream CAs: DigiCert CertCentral, Sectigo SCM, Let's Encrypt, internal ADCS via DCOM/RPC, EJBCA, Smallstep, AWS Private CA, GCP CAS, Azure Key Vault CA. Plugins are written against the SDK defined in F20 and run sandboxed. Outbound calls are made via the outbox pattern (AN-6) with idempotency keys (AN-5). |
| F5 | Built-in ACME server | RFC 8555-compliant ACME endpoint that brokers to configured upstream CA; supports HTTP-01, DNS-01, TLS-ALPN-01 |
| F6 | Lifecycle automation | Renewal at configurable threshold; revocation; rotation; expiration alerting |
| F7 | Deployment connectors (initial set) | NGINX, Apache, IIS, Kubernetes (cert-manager bridge + direct secret), HAProxy, AWS ACM, Azure Key Vault, GCP Certificate Manager, F5 BIG-IP. Connectors are plugins built against the SDK in F20; outbound delivery uses AN-6 (outbox) and AN-5 (idempotency). |
| F8 | RBAC | Role-based access with project/team scoping; built-in roles plus custom roles |
| F9 | Audit log surfaces | User-facing query, search, filter, and export interfaces over the event-sourced audit log defined in AN-2. UI views, CLI queries, REST endpoints, and signed evidence-bundle export for compliance auditors. The log itself is the source of truth in AN-2; F9 is the surface that exposes it. |
| F10 | REST API | OpenAPI 3.1 spec; complete CRUD plus lifecycle operations. All mutating endpoints accept idempotency keys per AN-5. |
| F11 | CLI | Full feature parity with UI; suitable for CI/CD automation |
| F12 | Web UI | React-based, responsive; dashboards, search, lifecycle workflows |
| F13 | SSO/OIDC (free) | OIDC and SAML 2.0; never gated behind a paid tier |
| F14 | Single-binary distribution | Single static Go binary. **PostgreSQL is the datastore in every deployment mode** — a bundled single-node PostgreSQL for evaluation, and external/operator-managed PostgreSQL for production. **NATS JetStream is the event store in every deployment mode** — embedded in the binary with file-backed storage for single-node/evaluation, and an external NATS cluster for production — so the event-sourced truth model (AN-2) is identical across modes. The signing service (AN-4) runs as a **separate child process with its own address space**, launched and supervised by the single binary in single-node mode and run as a standalone service in production. It is **never run in-process with the control plane**: the address-space boundary defined in AN-4 holds in every deployment mode. |
| F15 | Encrypted control-plane transport | All communication between the control plane and agents occurs over mTLS. No plaintext path exists. TLS 1.3. Modern AEAD cipher suites enforced at build time. Agent client certificates are issued by the platform on bootstrap and rotated automatically before expiry (24-hour TTL default). Applies to gRPC, HTTP, and any future transport. |
| F16 | Crypto-agility and PQC readiness | ML-DSA (Dilithium) and ML-KEM (Kyber) supported as first-class algorithms alongside classical (RSA, ECDSA). Hybrid certificates (classical + PQ) supported per draft standards. Crypto inventory view classifies every credential by algorithm and quantum-vulnerability status. Algorithm choice is policy-driven, not hardcoded. CNSA 2.0 alignment for federal deployments. **Implementation depends on AN-3 — without the single crypto interface boundary, adding new algorithms means touching dozens of call sites rather than one package.** Note: a FIPS-validated build (Section 7) and a PQC-enabled build may be distinct configurations until validated providers cover ML-DSA/ML-KEM; algorithm availability is reported per build. |
| F17 | Certificate Transparency monitoring | Continuously watch CT logs (Google, Cloudflare, DigiCert, Sectigo logs via the standard CT log ecosystem) for any cert issued for the organization's domains. Detect shadow IT, rogue issuance, and compromised internal CAs. Alerts integrated into the same notification surface as expiration alerts. |
| F18 | Drift detection | Agent (F3) reconciles cert/credential state on the host against the declared state in the control plane. Detects manual replacement, deletion, permission changes, and file relocation. Operator chooses alert-only, alert-and-block, or auto-remediate per credential class. |
| F19 | Credential risk scoring | Composite numerical score per credential computed from age, exposure (number of deployment targets per F21's graph), privilege class (what it grants access to), rotation history, owner activity, and inferred sensitivity. Sortable, filterable, exposed in API. The single answer to "what should I rotate first." |
| F20 | Plugin SDK with capability sandboxing | Public SDK and conformance suite for community-contributed CA plugins (F4) and deployment connectors (F7). Plugins run in a WASM sandbox (wazero or extism) with capability-based permissions; a plugin declaring "writes to filesystem only at path X" cannot exceed that grant at runtime. Core team certifies a curated set; community plugins are isolated and labeled. |
| F21 | Credential graph | Inventory is modeled and queryable as a graph, not a list: workloads → identities issued to them → credentials they use → resources those credentials access → other workloads they connect to. Used for blast radius preview (F31), attestation chains (F30), and risk scoring (F19). Exposed via REST and as Cypher-style query for power users. |
| F42 | SSH credential discovery & inventory | Discover and inventory SSH material the same way certs are found: host keys via the SSH-handshake extension of the network scanner (F2), and user keys, `authorized_keys`, `known_hosts`, and `sshd` trust configuration via the agent (F3). Orphaned keys and standing-access grants are flagged, folded into the credential graph (F21), and scored by F19. This is the inventory half of closing the "every non-human identity" claim for SSH; it lands in Phase 1 because it reuses discovery infrastructure that already exists rather than requiring the SSH CA. |

### Phase 2 — Workload Identity & Hardening

| ID | Feature | Description |
|---|---|---|
| F22 | EST server (RFC 7030) | Device enrollment (Cisco, Aruba, IoT) |
| F23 | SCEP server (RFC 8894) | Legacy device enrollment; MDM-compatible |
| F24 | SPIFFE Workload API | Issues X.509-SVID and JWT-SVID over Unix domain socket; compatible with SPIRE-aware applications |
| F25 | Ephemeral credential issuance | Sub-hour TTL certificates (configurable down to a few minutes) for agentic/AI workloads. Identity binding uses the attestation chain in F30 — ephemeral credentials are issued only when a verifiable attestation justifies the request. |
| F26 | HSM integration | PKCS#11, AWS KMS, Azure Key Vault, GCP KMS, TPM, YubiHSM as backends for protecting CA signing keys — X.509 roots and intermediates, and the SSH CA signing key (a single trusted key with no chain). Integrated as pluggable backends behind the crypto interface defined in AN-3, not as side paths through the codebase. |
| F27 | Additional connectors | FortiGate, Palo Alto, Cisco ISE/ASA, Citrix ADC, Imperva, Zscaler |
| F28 | Policy engine | OPA/Rego policy over issuance, deployment, and revocation events |
| F29 | Notification integrations | Slack, Teams, PagerDuty, OpsGenie, generic webhooks, email |
| F30 | Workload attestation chain | Every credential issuance records the attestation chain that justified it: TPM quote, cloud instance identity (AWS IMDSv2, GCP metadata, Azure IMDS), Kubernetes projected service account token, GitHub OIDC, Sigstore Fulcio identity. Attestation is a first-class entity in the graph (F21), queryable and auditable. Required for ephemeral credentials in F25. |
| F31 | Credential compromise workflow | One-action revoke + reissue + rotate workflow for any credential class. Blast radius preview is computed by traversing the credential graph (F21): every workload, deployment, and downstream credential affected. Audit-logged. Available via UI, CLI, and API. |
| F32 | Fleet re-issuance for CA compromise | When an issuing authority has an incident, operators can identify every affected credential via F21 and re-issue at scale within hours. This covers both X.509 and SSH. For X.509: upstream CA incidents (Let's Encrypt mass-revocation, DigiCert misissuance) and internal CA key compromise. For SSH: compromise of the SSH CA signing key — a particularly severe event, because every host trusting that key via `TrustedUserCAKeys` will honor forged user certificates until the key is rotated and trust is redistributed across the fleet. SSH fleet re-issuance therefore includes rotating the SSH CA key, re-signing affected host and user certificates, redistributing the new trusted-CA public key to every `sshd`, and publishing an updated KRL — all driven from the same graph (F21) and the same staged-rollout machinery. Staged rollout with policy guardrails. Reliability of large fleet operations depends on AN-5 (idempotency — no duplicate certs) and AN-6 (outbox — survives mid-operation crashes). Automatic rollback on health-check failure. Full audit trail. |
| F33 | Just-in-time issuance with approval flows | Sensitive credential classes (code signing, intermediate CA, EV, long-lived high-privilege) require human approval. Native approval workflow with Slack/Teams integration, dual control, and time-bounded grants. Approvers are scoped by policy. |
| F34 | Break-glass procedures | Documented and tested offline issuance ceremony for use when the control plane is unavailable. Operator-held escrow keys, signed emergency credential bundles, m-of-n quorum for high-privilege operations. Implementation is a degraded operating mode of the signing service (AN-4): the signing service can run standalone with operator quorum and produce signed audit-bundle output that reconciles with the control plane on recovery. Threat model and runbook shipped with the product. Covers SSH lockout recovery (F44) as well as X.509 issuance. |
| F43 | SSH certificate authority | Signs short-lived OpenSSH host and user certificates with principals, validity windows, and critical options/extensions (e.g. `force-command`, `source-address`). SSH is a first-class credential type, distinct from the X.509 protocols (ACME/EST/SCEP, which issue X.509 only): it has its own certificate format, a single trusted signing key with no chain, and revocation via short lifetimes plus Key Revocation Lists (KRLs). The SSH CA is an implementation behind the AN-3 crypto boundary, signs through the AN-4 signing service, and rides the AN-2 event-sourced issuance path — it reuses the existing certificate machinery rather than standing up a parallel one. KRL maintenance and distribution, and integration with the compromise (F31) and fleet re-issuance (F32) workflows, are part of this feature. |
| F44 | SSH deployment & trust configuration (agent) | The agent installs host certificates and configures `sshd` to present them, distributes the SSH CA public key as a trusted user CA (`TrustedUserCAKeys`), and manages `authorized_keys` and certificate principals. Trust changes are additive-first and never remove existing host or user trust without explicit confirmation; `sshd` configuration is validated and reloaded with automatic rollback on a failed health check, so a misconfiguration cannot lock operators out of a host. SSH lockout recovery is covered by the break-glass procedures in F34. |
| F45 | Attestation-gated short-lived SSH user certs | Short-lived SSH user certificates are issued only against a verifiable attestation from the F30 attestation chain (TPM quote, cloud instance identity, Kubernetes projected SAT, GitHub OIDC, Sigstore Fulcio) — the same gate as ephemeral X.509-SVIDs in F25. This is what converts SSH access from standing raw-key access into attested, expiring access, and is the security payoff of the SSH work. |

### Phase 3 — Secret & Token Lifecycle

| ID | Feature | Description |
|---|---|---|
| F35 | Secret store discovery | Inventory connectors for HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, Kubernetes secrets |
| F36 | API key/token inventory | Discovery via CSP API (AWS IAM access keys, GCP service account keys, Azure SP secrets), GitHub Actions secrets, CI/CD secret stores |
| F37 | Secret rotation engine | Policy-driven rotation for supported backends; rollback safety |
| F38 | Ephemeral API key issuance | Short-lived workload-bound API keys with SDK for Go, Python, Node, Java |
| F39 | Code/CI secret scanning bridge | Integration with trufflehog/gitleaks; findings ingested into certctl inventory |
| F40 | Multi-tenant deployment topology | Activates the managed/SaaS deployment topology by exposing the tenant boundary that was built into the schema in Phase 1 (AN-1): tenant provisioning APIs, per-tenant administrative scopes, cross-tenant operational tooling for the platform operator, and isolation guarantees verified by an independent test suite. This is not "building multi-tenancy" — that exists from Phase 1 — it is operationalizing it for SaaS. |
| F41 | Cross-cluster / multi-region federation | Regional control planes federate for data sovereignty (EU vs. US residency), with shared policy, federated identity, and replicated audit. Designed in from Phase 1's data model; activated as a deployment topology in Phase 3. |

### Out of Scope (v1)

These categories are explicitly not in scope and will not be built:

- Human IAM/identity management — integrate with existing IdP via OIDC/SAML
- PAM session recording and privileged session brokering — adjacent, not core. This scopes the SSH work precisely: certctl issues, discovers, and manages SSH credentials, but it does not proxy, record, or broker SSH sessions the way Teleport does. SSH here is a credential-lifecycle capability, not an access-proxy product.
- Code-level SAST — leverage existing tools
- DLP
- Endpoint security

### Sequencing Rationale

- **Phase 1** establishes the CLM foundation plus the architectural commitments (crypto agility, graph inventory, plugin sandbox) that are nearly impossible to retrofit. Without it, the platform has no anchor user and no path to differentiation.
- **Phase 2** delivers the SPIFFE and ephemeral-credential surface that defines the NHI category position, plus the incident-response capabilities (compromise workflows, fleet re-issuance, break-glass) that separate enterprise-grade infrastructure from open-source toys.
- **Phase 3** expands to non-certificate credentials and federation. This is the largest TAM expansion and depends on a stable Phase 1+2 base; building it earlier dilutes focus.

---

## 5. Technical Requirements

### Architecture Overview

```
                ┌───────────────────────────────────────────────┐
                │             certctl Control Plane             │
                │                                               │
                │  ┌─────────┐   ┌───────────────┐              │
 Web UI ─HTTPS─▶│  │   API   │   │ Policy Engine │              │
 CLI    ─HTTPS─▶│  │ (REST)  │   │  (OPA/Rego)   │              │
                │  └────┬────┘   └───────┬───────┘              │
                │       │                │                      │
                │  ┌────▼────────────────▼────┐                 │
                │  │       Orchestrator       │                 │
                │  └─┬─────┬─────┬──────┬────┬─┘                 │
                │    │     │     │      │    │                   │
                │ ┌──▼┐ ┌──▼┐ ┌─▼──┐ ┌─▼───┐ ┌▼─────────────┐   │
                │ │ACME│ │EST│ │SSH │ │SPIFFE│ │ Plugin Host │   │
                │ │SCEP│ │   │ │ CA │ │ API  │ │(WASM sandbox)│  │
                │ └──┬┘ └─┬─┘ └─┬──┘ └──┬──┘ │ CAs+Connectors│   │
                │    │    │     │       │    └──────┬────────┘   │
                │    └────┴──┬──┴───────┘           │            │
                │            │ gRPC / UDS           │            │
                │   ┌────────▼──────────┐           │            │
                │   │  Signing Service  │◀──────────┘            │
                │   │ (separate process;│ ───────▶ HSM / KMS/TPM │
                │   │  own address space│                        │
                │   │  AN-4 boundary)   │  signs X.509 + SSH     │
                │   └───────────────────┘                        │
                │                                               │
                │  PostgreSQL │ NATS JetStream (event log)│ S3  │
                └──────────┬────────────────────────────────────┘
                           │ mTLS (TLS 1.3) — F15
            ┌──────────────┼──────────────┐
            │              │              │
        ┌───▼────┐    ┌────▼────┐    ┌────▼───┐
        │ Agent  │    │  Agent  │    │ Agent  │
        │(Linux) │    │(Windows)│    │  (K8s) │
        └────────┘    └─────────┘    └────────┘
```

### Architecture Non-Negotiables

These commitments are designed in from day one. Each is either impossible or prohibitively expensive to retrofit. Together they define what "enterprise-ready, security-gap-free" actually means in code, not in marketing.

**The first five are foundational. Without them, every later decision becomes a workaround.**

**AN-1: Multi-tenancy at the storage layer from day one.** Every row in every table carries a `tenant_id`. Every query filters on it. PostgreSQL row-level security policies enforce isolation at the database, not at the application layer. Because PostgreSQL is the datastore in *every* deployment mode (no SQLite path exists), this guarantee is unconditional — it does not weaken on single-node or evaluation deployments. Single-tenant deployments simply run with one tenant. Bolting multi-tenancy onto a single-tenant codebase later is a six-month project that breaks customer data; baking it in from day one costs a week of careful work. This is the difference between a managed-tier offering being a deployment topology vs. a rewrite.

**AN-2: Event-sourced audit, not audit-as-side-effect.** State changes emit immutable events to an append-only event log (NATS JetStream with file storage). Both the relational database state and the audit trail are *derived* from the event log. The event log is the source of truth. NATS JetStream is the event store in every deployment mode — embedded in the binary (file-backed) for single-node and evaluation, and an external cluster for production — so single-node and production run the identical truth model and exercise the identical write path. Forensics, replay, point-in-time queries, and compliance evidence collection are all free byproducts. Two-phase commit between state and audit goes away. When an auditor or incident responder asks "what actually happened on March 14 at 2:47 AM," the answer is in one place.

**AN-3: Cryptography as a single hard interface boundary.** All cryptographic operations route through one package (`internal/crypto`) that defines backend-agnostic interfaces. Backends: software (Go stdlib), PKCS#11, AWS KMS, Azure Key Vault, GCP KMS, TPM, YubiHSM, and post-quantum (ML-DSA, ML-KEM, hybrids). No `crypto/x509`, `crypto/rsa`, or `crypto/ecdsa` calls anywhere else in the codebase, enforced by a custom linter rule in CI. Adding a new algorithm (PQC, future standards) or a new HSM is one package change, not fifty. This is what crypto-agility actually requires. Both X.509 and SSH certificate signing route through this one boundary — the SSH CA is another implementation behind it, not a parallel crypto stack — so SSH inherits crypto-agility, HSM/KMS key protection, and PQC readiness without any additional cryptographic surface to audit.

**AN-4: The signing service is a separate process, treated as sacred.** Private key operations live in their own process with its own address space, communicating with the rest of the platform via gRPC over a Unix domain socket (or mTLS across nodes). The signing service has no HTTP server, no SQL driver, no third-party logging libraries beyond stdlib, and a minimal, fully-audited dependency surface (the gRPC/transport stack it requires is pinned, vendored, and reviewed). Memory is zeroed on key material. It is fuzzed against every protocol parser it touches. In the single-binary distribution it runs as a separate child process with its own address space (never in-process); production deployments run it as a standalone service. This is the one component that, if compromised, ends the company.

**AN-5: Idempotency on every state-changing API.** Every mutating endpoint accepts an `Idempotency-Key` header. The orchestrator records the key with the operation; replays return the original result instead of executing again. Network failures during cert issuance cannot result in two certs (which matters when upstream CAs charge per cert). Concurrent retries from agents cannot create duplicate state. This is table stakes for any distributed system that talks to paid external services, and it has to be baked into the orchestrator from day one — retrofitting it requires changing every caller.

**The next three are also designed in from day one. Skipping any of them creates failure modes that are painful to debug and expensive to fix.**

**AN-6: Outbox pattern for every external call.** Any operation that needs to call out — upstream CA issuance, connector deployment, webhook delivery, email/Slack notification — writes its intent to an `outbox` table in the same database transaction as the state change. A separate worker reads the outbox and makes the call. This survives crashes mid-operation, gives at-least-once delivery semantics with idempotency providing exactly-once effect, and makes retries observable. Without the outbox, you eventually ship a release where a customer's database says "cert issued" but no cert was actually issued, or vice versa.

**AN-7: Backpressure and bulkheads between every subsystem.** Each subsystem (API, orchestrator, discovery, deployment, ACME server, EST server, SPIFFE Workload API, connector pool, CA plugin pool) has its own bounded worker pool with its own queue. Full queues reject fast with structured errors, not slow degradation. A slow F5 connector cannot starve other connectors. A discovery scan cannot exhaust the database connection pool that the API depends on. A burst of ACME requests cannot back up the orchestrator. This isolation is easy to design in and impossible to retrofit once hot paths are entangled.

**AN-8: Memory safety for key material.** Private keys and other secret material live in `[]byte` buffers (never strings, which Go's GC can copy at any time), are `mlock`'d to prevent paging to disk, marked `MADV_DONTDUMP` to exclude from core dumps, and explicitly zeroed (via `runtime.KeepAlive` + manual zero loop, or libraries like `memguard`) when no longer needed. This is the difference between FedRAMP Moderate and FedRAMP High, and the difference between a key staying in RAM for milliseconds vs. potentially indefinitely. Doing this from day one is straightforward; doing it later means auditing every line of code that ever touched a key.

**Operational practices that follow from these commitments:**
- A custom linter (`go vet`-style) runs in CI to enforce: no direct `crypto/*` imports outside `internal/crypto`, no string types in key-handling code paths, no missing `tenant_id` filter in repository queries, no API handler without idempotency-key support on mutations.
- Property-based tests on the policy engine and on every protocol parser (ACME, EST, SCEP, X.509).
- Differential tests against reference implementations: Boulder (Let's Encrypt's ACME server), libest (Cisco's EST reference), known-good SPIFFE implementations.
- Fuzz tests on every untrusted-input parser, run continuously via OSS-Fuzz.
- Conformance test suites published so the community can validate compatibility of forks and plugins.

### System Components

**certctl Control Plane (Go, deployable as one or many processes):**
- API service (HTTP/JSON + gRPC for agents)
- Orchestrator (job scheduling, lifecycle state machine, outbox dispatcher per AN-6)
- Policy engine (embedded OPA)
- Protocol servers and CAs (ACME, EST, SCEP, SPIFFE Workload API, and the SSH certificate authority — host/user signing plus KRL maintenance)
- Plugin Host (WASM sandbox per F20; hosts CA plugins and connectors)
- Web UI (React 18 + Vite + shadcn/ui; served from binary in embedded mode)

**Signing Service (separate process, per AN-4):**
- Sole owner of private key material; no HTTP, no SQL, no third-party logging; minimal, fully-audited transport dependency
- gRPC over Unix domain socket (local) or mTLS (cross-node)
- Backends: software (Go stdlib), PKCS#11, AWS KMS, Azure Key Vault, GCP KMS, TPM, YubiHSM
- Signs both X.509 and SSH certificates; the SSH CA signing key is held and protected here exactly like any other key (HSM/KMS-backed where configured), so SSH issuance inherits the same memory-safety and key-protection guarantees
- Memory safety per AN-8 (mlock, MADV_DONTDUMP, explicit zeroization)
- Runs as a separate child process (own address space) in single-binary mode; deployed standalone in production. Never in-process.

**certctl Agent:**
- Go binary, ~15MB static
- mTLS to control plane with rotating client certificate (F15)
- Workers: discovery, deployment, key operations, SPIFFE Workload API exposure, drift reconciliation (F18), and SSH host-certificate deployment plus `sshd`/`authorized_keys` trust configuration (F44)
- Pluggable key stores: filesystem, Windows CryptoAPI, PKCS#11, cloud KMS

**Data Stores:**
- NATS JetStream — event log; the source of truth per AN-2. Embedded in the binary with file storage for single-node/evaluation; external cluster for production. The truth model is identical across deployment modes.
- PostgreSQL 14+ — derived state and projections, multi-tenant via row-level security per AN-1, in *every* deployment mode. A bundled single-node PostgreSQL is used for evaluation; external/operator-managed PostgreSQL for production. No SQLite path exists.
- S3-compatible object store — long-term audit archive (derived from event log)

### Data Model (Top-Level Entities)

- `Identity` (abstract base: X509Certificate | SSHCertificate | SSHKey | Secret | APIKey | WorkloadIdentity)
- `Owner` (User | Team | Workload | Service)
- `PolicyBinding`
- `Issuer` (X.509 CA, internal authority, or SSH CA — the SSH CA being a single trusted signing key with no chain)
- `DeploymentTarget`
- `Agent`
- `Attestation` (the chain that justified each credential issuance, per F30)
- `Event` (event-sourced state changes per AN-2; both the audit log and the derived database state are projections of this stream)
- `Tenant` (root scope of every other entity, per AN-1)

### API Requirements

- REST: OpenAPI 3.1; resource-oriented; versioned (`/api/v1/`)
- gRPC: agent ↔ server (proto definitions versioned independently)
- Auth: OIDC bearer tokens (UI/CLI), mTLS (agents), API tokens with scopes (CI/CD)
- Rate limiting: PostgreSQL-backed distributed counter (advisory locks or a dedicated counter table); per-token and per-IP. No separate datastore (e.g. Redis) is required — this keeps the dependency surface to PostgreSQL and NATS.
- Error model: RFC 7807 problem+json
- Pagination: cursor-based

### Performance Specifications

These are **architectural design targets for a horizontally-scaled cluster** — the ceiling the architecture is built to reach, not single-node guarantees and not figures claimed as validated at GA. See Scalability below for the validated single-node baseline.

| Metric | Cluster-scale design target |
|---|---|
| API p95 latency (read) | <100ms |
| API p95 latency (write) | <300ms |
| Cert issuance via ACME (cached CA path) | <2s |
| SSH certificate issuance (signing path) | <2s |
| Discovery scan throughput | 10,000 hosts/hour per scanner |
| Concurrent agents (clustered) | 10,000 |
| Credentials managed per cluster | 5,000,000 |
| Cold-start binary | <3s |

### Scalability

The platform defines two tiers explicitly so a reader always knows which number applies to their deployment:

- **Single-node deployment (validated baseline):** one all-in-one node supports up to ~50,000 credentials and ~500 agents. This is the realistic floor an operator gets from a single box and is the figure validated before GA.
- **Horizontally-scaled cluster (design target):** stateless server tier behind L4/L7 LB; PostgreSQL primary + read replicas; NATS cluster. The cluster-scale figures in the Performance table (10,000 agents, 5,000,000 credentials) are *architectural design targets* — the system is designed so they are reachable through horizontal scaling. They are not single-node guarantees.
- **Geographic:** multi-region active-passive for managed offering; active-active deferred to v2.

### Dependencies

- Go 1.22+
- PostgreSQL 14+ (bundled single-node for evaluation; external/operator-managed for production — no SQLite path)
- NATS JetStream 2.10+ (embedded, file-backed, for single-node/evaluation; external cluster for production)
- WASM runtime (wazero, in-process)
- HSM and KMS support is built in (F26); operators choose at runtime which backend to use behind the crypto interface (AN-3)
- Container runtime for agent and connector packaging (Docker/OCI; gVisor for hardened deployments)
- S3-compatible object storage (optional; long-term audit archive only — not required for single-node or evaluation deployments)

### Distribution & Packaging

The single static Go binary is the universal substrate. Every distribution format below is a wrapper around that same artifact; none introduces a separate codebase or build target beyond the binary and its launch flags.

**Control plane — container images (primary channel).** The control plane ships as OCI images built on a distroless or `scratch` base — one static binary, no shell, no package manager, no libc. Target image size is under 20MB. The multi-process signing service (AN-4) runs as a separate child process inside a single container for simple deployments, or as a separate container/pod for isolated deployments; both use the same image launched with different flags. Images are published to **GitHub Container Registry (GHCR) as the primary registry**, tied to GitHub Releases for provenance, with **Docker Hub maintained as a discoverability mirror**. Every image is signed with cosign (Sigstore), ships a CycloneDX SBOM, and is built reproducibly so that air-gapped and regulated buyers can verify and mirror it into a private registry.

**Control plane — orchestration.** Docker Compose is the launch deliverable (Phase 1): a single `docker compose up` brings up the control plane for evaluation and is the path behind the sub-15-minute time-to-first-cert target. A Helm chart and a Kubernetes Operator are a Phase 1 fast-follow into Phase 2, serving the production Kubernetes deployments that constitute most enterprise targets; these deploy the signing service as its own pod with a dedicated security context and network policy, and wire secrets to the operator's external KMS.

**External datastores are a first-class assumption, not an afterthought.** Compose may bring up bundled PostgreSQL and NATS for convenience during evaluation, but the image never assumes it owns its datastore. Pointing the control plane at external, operator-managed PostgreSQL and NATS (and S3-compatible object storage) is a documented, equally-supported configuration from day one. The bundled single-node PostgreSQL and embedded NATS are for evaluation only and are clearly labeled as such; no production guidance ever depends on them. This constraint is baked into configuration and documentation from the first release rather than being introduced once someone tries to run the eval setup in production.

**Agent — native packaging.** The agent runs on hosts that are frequently not containerized — bare-metal load balancers, Windows servers, hosts adjacent to network appliances. It therefore ships in multiple native formats in addition to a container image: a raw static binary, a systemd unit and `.deb`/`.rpm` OS packages for Linux, an MSI installer for Windows, and a container image for the Kubernetes DaemonSet case. Container-only packaging for the agent would exclude exactly the legacy-infrastructure footprint that certificate lifecycle management exists to serve. All agent artifacts are signed, and the binary's SHA-256 is published per release.

---

## 6. User Experience Requirements

### Design Principles

1. **Operator first.** Every workflow must be completable from CLI or API; the UI is a thin layer over the same primitives.
2. **Progressive disclosure.** First-run shows a wizard ("connect a CA, install an agent, issue your first cert"). Advanced controls are discoverable, not in the user's face.
3. **No silent failures.** Every lifecycle event surfaces in audit log and (configurably) in notification channels.
4. **Cohesive across modules.** Cert, secret, and workload identity surfaces share the same patterns, search, and policy primitives.
5. **Accessible.** WCAG 2.1 AA conformance.

### Interface Requirements

- Responsive web UI (desktop primary, tablet supported, mobile read-only acceptable)
- Dark mode and light mode; system-preference default
- Keyboard navigation for all primary workflows
- Inline help and progressive examples in form fields
- Empty states that guide rather than scold

### Usability Targets

- Time-to-first-cert (fresh install → first issued cert): <15 minutes
- Time-to-first-agent (fresh install → first registered agent): <5 minutes
- Net Promoter Score from active users: ≥40

---

## 7. Non-Functional Requirements

### Security

**Transport security:**
- All communication between the certctl control plane and certctl agents occurs over mTLS. No plaintext path exists. No opportunistic-TLS path exists. An agent that cannot establish mTLS to the control plane is treated as offline.
- TLS 1.3. No TLS 1.2 fallback.
- Cipher suites restricted to modern AEAD constructions; legacy suites rejected at build time via a Go TLS config audit.
- Agent client certificates are issued by the platform's internal CA on bootstrap and rotated automatically before expiry (24-hour TTL default).
- Server certificate pinning is enforced by the agent.
- FIPS 140-3 mode is available via build flag using a FIPS-validated cryptographic provider. (See F16: a FIPS-validated build and a PQC-enabled build may be distinct configurations until validated providers cover ML-DSA/ML-KEM.)

**Other security requirements:**
- All other inter-component traffic (UI/CLI to server, server to upstream CA, server to connector targets) is encrypted in transit with appropriate authentication.
- Server binary is signed (cosign/Sigstore); SBOM is published per release.
- Agent binary is signed; SHA-256 is published.
- No hardcoded credentials. All bootstrapping occurs via short-lived tokens or attestation.
- Encryption at rest: PostgreSQL TDE or column-level (libsodium) for private key material when not in HSM.
- Compliance posture at Phase 1 (open-source) GA: SOC 2 Type I readiness and FIPS 140-3 mode (build flag).
- Compliance posture at managed-tier GA (Phase 3): FedRAMP Moderate readiness for the managed offering, in addition to the above. FedRAMP readiness is not claimed at the open-source Phase 1 GA.
- Vulnerability response: 90-day disclosure window; published security policy; CVE assignment via MITRE CNA application.

### Performance

- See Section 5 specifications (cluster-scale design targets) and the single-node validated baseline in Scalability.

### Reliability

- Target availability self-managed: 99.5% (operator-dependent)
- Target availability managed offering: 99.9%
- Backup: PostgreSQL streaming replication + WAL archive; documented restore RPO/RTO
- Disaster recovery: documented runbook; backup restore tested per release
- Monitoring: Prometheus metrics endpoint; OpenTelemetry traces; structured JSON logs

### Scalability

- See Section 5

### Internationalization

- English at GA; community-driven translations post-GA
- All user-facing strings externalized

---

## 8. Success Metrics & Analytics

### Key Performance Indicators

**Adoption (community):**
- GitHub stars (week-over-week growth)
- Active deployments (opt-in anonymous telemetry, off by default — reported figure is a lower bound)
- Docker pulls / package downloads
- Discord/Slack community members and DAU

**Engagement (product):**
- Credentials under management per instance (distribution)
- Lifecycle events per day per instance
- Connector usage distribution
- Feature usage funnel (install → first CA → first agent → first cert → first renewal)

**Business:**
- Free → paid conversion rate
- Managed tier MRR / ARR
- Enterprise and MSP/reseller contracts signed and ACV
- Logo retention and net revenue retention

**Strategic:**
- Acquirer inbound conversation count and stage
- Analyst (Gartner, Forrester) mentions
- Conference talk acceptances

### Analytics Implementation

- Opt-in telemetry (off by default — decided position; see Appendix B) sending coarse-grained, non-PII data: instance count, anonymized instance ID, version, OS, credential count by type bucket
- Because telemetry is off by default, all telemetry-derived metrics (notably active deployments) are explicitly treated as a lower bound, and adoption is triangulated with downloads, image pulls, and community size rather than relying on telemetry alone
- Public dashboard showing aggregate ecosystem health (deployments, credentials managed)
- No tracking of credential metadata, names, or content under any circumstance

### Measurement Cadence

- Weekly: stars, downloads, community size
- Monthly: active deployments, conversion funnel, MRR
- Quarterly: strategic KPIs, roadmap review

---

## 9. Implementation Plan

Phases denote build order only; there are no fixed calendar dates. Build proceeds at the founder's pace. Exit criteria are adoption targets, not deadlines.

### Phase 1 — CLM Foundation + Architectural Bedrock

**Goal:** Ship a self-hosted CLM with ACME server and 8–10 connectors that is genuinely competitive with Smallstep + Vault PKI engine combined, on an architecture (AN-1 through AN-8) that supports every later phase without rework.

**Deliverables:**
- Core data model with tenant scoping from day one (AN-1) + event-sourced audit (AN-2)
- Crypto interface boundary (AN-3) with software and cloud KMS backends; PQC algorithms wired in
- Signing service as a separate process (AN-4)
- REST/gRPC API with idempotency keys on all mutations (AN-5)
- Outbox-based dispatch for every external call (AN-6); bulkheaded subsystems (AN-7); memory-safe key handling (AN-8)
- Custom CI linter enforcing all of the above
- Web UI (React) and CLI
- Agent (Linux, Windows, K8s) over mTLS (F15)
- Built-in ACME server
- CA plugins via WASM SDK (F20): DigiCert, Sectigo, Let's Encrypt, internal ADCS, EJBCA, Smallstep, AWS Private CA, GCP CAS, Azure Key Vault CA
- Connectors via WASM SDK: NGINX, Apache, IIS, Kubernetes, HAProxy, F5 BIG-IP, AWS ACM, Azure Key Vault, GCP Certificate Manager
- CT monitoring (F17), drift detection (F18), credential risk scoring (F19), credential graph (F21)
- SSH credential discovery & inventory: host keys via the SSH-handshake extension of the scanner, and user keys / `authorized_keys` / `sshd` trust via the agent, folded into the credential graph and risk scoring (F42)
- RBAC (F8), OIDC/SAML (F13), audit log surfaces (F9)
- Distribution: signed, SBOM-bearing OCI images on GHCR (Docker Hub mirror); Docker Compose for one-command evaluation; external-datastore configuration (PostgreSQL + NATS) documented and supported alongside the bundled eval datastore
- Documentation site + getting-started in <15 minutes
- Public launch: blog post, HN/Reddit/LinkedIn campaign, target subreddits + dev community

**Exit criteria:** 1,000 GitHub stars; 100 active deployments; 5 design partner customers actively using.

### Phase 2 — Workload Identity & Enterprise Readiness

**Goal:** Establish the NHI/workload identity differentiator and the incident-response surface that separates enterprise-grade infrastructure from open-source toys.

**Deliverables:**
- SPIFFE Workload API server (X.509-SVID, JWT-SVID)
- Ephemeral certificate issuance (F25) gated on workload attestation chain (F30)
- EST and SCEP servers
- HSM/KMS integration as additional backends behind the AN-3 boundary: PKCS#11, AWS KMS, Azure Key Vault, GCP KMS, TPM, YubiHSM
- Additional connectors: FortiGate, Palo Alto, Cisco ASA/ISE, Citrix ADC
- SSH certificate authority: short-lived host and user certificate signing with principals, validity, and extensions, with revocation via KRLs and short lifetimes (F43)
- Agent SSH deployment: host-cert install, `sshd` trust configuration, and `authorized_keys`/principal management with lockout guardrails (F44)
- Attestation-gated short-lived SSH user certificates, riding the same F30 attestation chain as ephemeral SVIDs (F45)
- Policy engine GA
- Credential compromise workflow (F31), fleet re-issuance (F32), JIT approvals (F33), break-glass procedures (F34)
- Helm chart and Kubernetes Operator (signing service as its own pod with dedicated security context and network policy); production deployment guidance for external PostgreSQL, NATS, and KMS
- External pen test
- KubeCon talk submission

**Exit criteria:** 3,000 stars; 400 deployments; first managed-tier pilot customer.

### Phase 3 — Secret & Token Lifecycle

**Goal:** Expand surface to non-certificate credentials; cement NHI category positioning.

**Deliverables:**
- Read-only secret store discovery: Vault, AWS SM, Azure KV, GCP SM, K8s secrets
- API key inventory via CSP APIs (AWS, GCP, Azure, GitHub)
- Rotation engine for supported backends
- Ephemeral API key SDK (Go, Python, Node, Java)
- Multi-tenant mode (managed offering)
- Managed offering GA
- Commercial enterprise tier launch

**Exit criteria:** 5,000+ stars; 750 deployments; 10 paying customers; 3 acquirer conversations.

### Phase 4 — Commercial & Acquisition Track

- Enterprise features: clustering, premium connectors, compliance modules
- Partner program (resellers, MSSPs)
- Strategic conversations with acquisition targets
- Optional: targeted strategic funding round if it accelerates exit

### Resource Allocation

| Phase | Engineering | Design | DevRel | DevOps |
|---|---|---|---|---|
| 1 | 1 founder | Contract (UI) | Founder | Founder |
| 2 | 1 founder + 1 hire | Contract | Founder | Founder |
| 3 | 1 founder + 2 hires | Contract | 1 hire | Contract |
| 4 | + as revenue allows | Hire | + | Hire |

### Build Milestones (sequenced — no fixed dates)

1. **M1:** Internal alpha — single-node, manual CA, basic UI
2. **M2:** Public alpha — ACME server live, 3 CAs, 5 connectors
3. **M3:** Phase 1 GA — full CLM, agent on three OS families
4. **M4:** SPIFFE + ephemeral GA
5. **M5:** Phase 2 complete; HSM integration
6. **M6:** Secret discovery alpha
7. **M7:** Phase 3 complete; managed GA; first paying enterprise

---

## 10. Risk Assessment & Mitigation

### Technical Risks

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Connector breadth becomes maintenance burden | High | Medium | Sandbox community connectors; certify core ten; document plugin API early |
| Scale ceiling exposed under enterprise load | Medium | High | Bench-test toward the 5M-credential design target before claiming it; PostgreSQL sharding plan ready; single-node baseline validated and clearly labeled |
| Agent security flaw → blast radius across deployments | Low | Critical | Defense in depth (mTLS, signed binaries, minimal privileges); external pen test before Phase 2 |
| SSH trust reconfiguration locks operators out of hosts | Medium | High | Trust changes are additive-first and never remove existing host/user trust without explicit confirmation; `sshd` config validated and reloaded with automatic rollback on a failed health check; staged rollout; SSH lockout recovery covered by break-glass (F34) |
| HSM/PKCS#11 integration complexity | Medium | Medium | Pin to 2–3 reference HSMs (SoftHSM, YubiHSM, Thales Luna); broaden post-GA |
| SPIFFE ecosystem fragmentation | Low | Medium | Track SPIFFE spec evolution; participate in CNCF SPIFFE/SPIRE community |
| ACME RFC 8555 edge cases (CT, ARI, etc.) | Medium | Medium | Use battle-tested upstream libraries; pass standard ACME compliance suite |

### Business Risks

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| NHI category dilutes / fails to mature | Low | High | Anchor on CLM (proven category) regardless of NHI narrative; messaging pivots |
| Incumbent (CyberArk, HashiCorp/IBM) ships free tier | Medium | High | Self-hosted + source-available posture is structurally harder for incumbents to match; community moat |
| Solo-founder bandwidth ceiling | High | High | Hire engineer at Phase 2; community contributions for connectors; advisory board for strategy; building at own pace removes schedule pressure but not scope risk |
| Acquirer market cools | Low | High | Build a real business in parallel (managed + license revenue); not dependent on M&A |
| Monetization fails to convert | Medium | High | Revenue wedge is commercial/enterprise licensing (commercial-use rights, MSP/reseller rights), support SLAs, managed offering, and compliance/certification artifacts — *not* gated features; this keeps the evaluator's experience complete while giving paying buyers concrete reasons to license |
| License-instrument criticism | Medium | Low | Transparent licensing policy; legal review; the model (source-available, no feature gating) is decided — only the specific license instrument is open (see Appendix B) |

### Mitigation Strategy

- **Public roadmap:** published roadmap (ordered, not dated) with community input mechanism
- **Design partners:** recruit 3–5 design partners early; iterate based on their feedback before public GA
- **External review:** security audit (SOC 2 readiness firm) before Phase 2; pen test before Phase 3
- **Strategic advisors:** recruit 2–3 advisors from PKI/IAM industry early

---

## Appendix B — Open Questions

1. **License instrument.** *Monetization model is decided:* source-available core with **no feature gating**; revenue from commercial and enterprise licenses (including MSP/reseller rights), support, and a managed offering. The remaining open item is the specific license *instrument* — BSL 1.1 (4-year cap is a known limitation), AGPL, a modified BSL, or a dual-license. Decision needed before public launch.
2. **Telemetry default.** *Resolved:* off by default (privacy-first stance for regulated, self-hosted buyers). All telemetry-derived metrics are treated as a lower bound and triangulated with downloads, image pulls, and community size.
3. **Hosted offering economics.** Per-credential, per-agent, per-cluster, or tiered flat fee? Needs pricing research with design partners.
4. **Foundation vs. company-owned.** Should the project be donated to CNCF or OpenSSF at some point? Affects acquisition narrative — could help or hurt.
5. **Brand architecture.** One brand (certctl) covers everything, or sub-brands for cert/secret/workload modules?
6. **Position vs. SPIRE.** Compatible-with vs. embed-SPIRE-as-library vs. reimplement. Recommend compatible-with (ship our own Workload API server).

---

## Appendix C — Competitive Reference

| Competitor | Category | Strength | Weakness vs. certctl |
|---|---|---|---|
| Venafi (CyberArk) | CLM | Enterprise depth; mature | Closed; expensive; SaaS-first |
| Keyfactor | CLM | EJBCA roots; strong PKI | Heavy; not unified beyond certs |
| Sectigo Certificate Manager | CLM | Affordable; integrated CA | Vendor lock to Sectigo |
| DigiCert ONE | CLM | Modern UX; broad | Closed; SaaS-only |
| HashiCorp Vault (IBM) | Secrets + PKI engine | Dominant secrets manager | PKI engine is primitive; heavy ops; IBM ownership = enterprise pricing creep |
| Smallstep step-ca | Open CA | Developer-loved; Go; ACME | Narrow scope; limited connectors; not a full CLM |
| SPIRE | Workload identity | Pure SPIFFE; CNCF | Primitives only; no UI, no CA mgmt, no discovery |
| cert-manager | K8s certs | Kubernetes-native standard | K8s-only |
| Astrix Security | NHI discovery | SaaS NHI posture | Discovery-only; no lifecycle; SaaS only |
| Oasis Security | NHI discovery | Similar to Astrix | Same |
| Teleport | SSH/access + identity | Strong SSH CA and session access | Access-proxy model; heavier to run; SSH/access-centric rather than a unified credential-lifecycle platform |
| Vault SSH secrets engine | SSH | Issues SSH certs from Vault | A separate primitive bolted onto a secrets manager; no discovery of existing key sprawl; heavy ops |

**certctl's unique position:** the intersection of all of the above — X.509, SSH, secrets, and workload identity — self-hosted, source-available, no feature gating.

---

## Quality Checklist

- [x] Problem clearly defined with evidence
- [x] Solution aligns with user needs and business goals
- [x] Requirements specific and measurable
- [x] Acceptance criteria testable (sample provided; full set in story tracker post-PRD)
- [ ] Technical feasibility validated (pending architectural spike)
- [x] Success metrics defined and trackable
- [x] Risks identified with mitigations
- [ ] Stakeholder alignment confirmed (founder-only at v0.5)

---

*End of PRD v0.5.*
