# The web console — what you can do in the browser

trstctl ships a full web console served by the binary itself — a React 18 + Vite SPA
from an embedded filesystem, on the same port and TLS certificate as the API, nothing
separate to deploy. It sits behind the same `/auth/login` session as every other
surface, and it is a *view* over that served control plane: anything you can do here
you can also do through the [REST API](features/platform-and-api.md), the
[CLI](cli.md), or the [SDKs](features/client-sdks.md). This page maps the navigation,
every real screen, the served endpoints behind each one, and the feature page that
explains the mechanics — and says so plainly where a screen only summarizes, or a
related capability is API-only today.

## Navigation

The sidebar is task-first: Dashboard and Journeys sit above everything else, and a
few quick tasks (for example *Expiring ≤30 days*) deep-link into a pre-filtered
worklist. A module switcher then scopes one band to a single product —
*Certificates & PKI* (certificates, request, profiles, CA hierarchy, protocols),
*Secrets*, *SSH*, *Signing*, and *Fleet* (agents, workloads) — while everything else
stays visible regardless of the active module, because it is trstctl's cross-domain
moat (one identity graph, one blast-radius view, one signed audit stream): Inventory
(identities, owners), Detect & respond (discovery, risk, posture, graph, incidents,
approvals, operations, notifications), and Govern & administer (policy, audit,
privacy, connectors, integrate, API explorer, platform administration, the
assistant). A module's band can still open Audit (this module) for a scoped lens on
that stream. Every nav row is gated by the same RBAC the API enforces, and every
label resolves through the typed i18n catalog (see
[Web internationalization](i18n.md)); a blank preview backs evaluation until the
binary serves real data.

## The surfaces

### Overview dashboard (`/`)

The single pane of glass: KPI tiles (certificates, identities, secrets, agents
online, expiring ≤7 days, high-risk, open incidents, PQC-ready), an issuance trend,
an issuance-rate chart, a renewal/job success-vs-failure trend, algorithm mix, a
90-day expiration timeline, a rotate-first worklist, and a recent audit-activity
stream. Below the KPIs, a non-human-identity inventory summary breaks the fleet down
by served `/api/v1/nhi/inventory` kind (certificates, SSH keys, secrets, API keys,
and more), and a severity-ranked alert center projects credentials needing attention
now from served risk and expiry events (no dedicated alerts endpoint).
Channel and routing-policy authoring, plus channel-test delivery, live on
`/notifications`; scheduled digest delivery is not implied by the preview.

### Journeys (`/journeys`)

Journeys is the guided-onboarding hub: pick a journey (first certificate, respond to
a compromise, manage secrets, and more) and work a step carousel checking served
data — issuers, certificates, discovery sources/runs/findings, profiles, incidents,
agents, secrets, members, audit — to auto-mark observable steps, leaving
command-line steps for you to mark by hand. Each journey links to its full
walkthrough doc.

### Certificate lifecycle command center (`/certificates`)

The certificate inventory is also a CLM dashboard: alongside the tenant-scoped,
cursor-paginated, expiry-filtered table it renders issuer/profile/team/environment
filters with URL-resident state, a Team column, estate-wide expiry/source health,
expiry bands, a 47-day renewal-readiness simulator (does each cert renew comfortably
inside the shrinking CA/Browser-Forum maximum lifetime?), deployment receipts from
the connectors, a tenant CRL distribution panel (full CRL, shard count, delta base,
freshness window), a Certificate Transparency queueing form, and a per-certificate
renewal-history timeline in the detail drawer. See
[Lifecycle & PQC](features/lifecycle-and-pqc.md)
and the [47-day journey](journeys/crypto-agility-pqc.md). Backed by
`/api/v1/certificates`, `/api/v1/certificates/health`, `/api/v1/revocation/crls`,
`/api/v1/revocation/ct-submissions`, `/api/v1/lifecycle/rotation-runs`, and
`/api/v1/connectors/deliveries`.

### Identities & NHI governance (`/identities`)

The identity grid carries the lifecycle actions (issue, deploy, revoke, with the
SURFACE-007 confirm and dual-control guards), and above it an issuance pipeline groups
identities by stage. The dashboard's NHI inventory summary and the risk posture and
orphan-governance panels on Risk and Owners complete the governance lens: counts by
kind, custodian-less credentials, and a shared risk score.
See [Workload identity](features/workload-identity.md) and
[Observability & risk](features/observability-and-risk.md). Backed by
`/api/v1/identities`, `/api/v1/nhi/inventory`, `/api/v1/risk/credentials`, and
`/api/v1/graph`.

### Owners (`/owners`)

Owners is the accountability directory: search and filter the people, teams,
workloads, and services credentials are attributed to; edit, delete, or read the
orphan-governance panel flagging credentials with no living owner. A companion
ownership-attribution table lists each non-human identity against its resolved
owner (or "orphaned") and how the attribution was derived. Backed by
`/api/v1/owners`, `/api/v1/owners/{id}`, and `/api/v1/ownership/attribution`.

### Agents (`/agents`)

Agents lists the in-network fleet that deploys and rotates credentials on your hosts:
issue a one-time enrollment token to register an agent, inspect its reported
endpoint-discovery capabilities (filesystem and PKCS#11 sources, metadata-only, no
private key bytes), offboard it, or revoke one of its certificates with a standard
revocation reason. Backed by `/api/v1/agents`,
`/api/v1/agents/enrollment-tokens`, `/api/v1/agents/{id}/offboard`, and
`/api/v1/agents/{id}/cert-revocations`.

### Workloads (`/workloads`)

Workloads is where short-lived machine identities get issued: SPIFFE/SVID
certificates gated on TPM, cloud, Kubernetes, or GitHub attestation; dynamic/ephemeral
leases with TTL policy and renew/revoke controls; AI-agent broker
identities scoped to allowed actions and a TTL; and attester trust-source
create/rotate/revoke/delete. It also shows served Kubernetes CSR and
trust-bundle-distribution posture, read-only; raw key material never reaches the
browser. Backed by `/api/v1/workloads/attested-issuance`,
`/api/v1/workloads/attester-trust-sources`, `/api/v1/secrets/leases`,
`/api/v1/broker/agent-identities`, `/api/v1/kubernetes/certificate-signing-requests`,
and `/api/v1/kubernetes/trust-bundles`.

### Profiles (`/profiles`)

Profiles are versioned issuance rulebooks: allowed key algorithms (including
ML-DSA/SLH-DSA hybrid PQC), minimum RSA/ECDSA strength, allowed EKUs, maximum
validity, allowed DNS suffixes, and which enrollment protocols may use the profile.
Build one with the guided form or a raw JSON editor, preview the resulting spec, and
browse prior versions — issuance keeps the version it evaluated against, and a diff
view compares any two versions field by field. Backed by `/api/v1/profiles` and
`/api/v1/profiles/{name}/versions/{version}`.

### Discovery (`/discovery`)

The discovery front door: a shadow-inventory summary of unmanaged credentials found
across your environments, and a CT-log & drift panel that counts
certificate-transparency and configuration-drift findings from the served sources,
schedules, and runs. See [Discovery & inventory](features/discovery-and-inventory.md).
Backed by `/api/v1/discovery/sources`, `/schedules`, `/runs`, and `/findings`.

### Posture — crypto-agility & PQC (`/posture`)

CT and drift findings, the drift-remediation decision workflow, a CBOM scan trigger
and cryptographic inventory, and a PQC readiness gauge — readiness percentage plus
quantum-vulnerable/PQC-ready/out-of-policy counts, framed against NIST FIPS
203/204 — derived from the served CBOM `migration_progress`. Queuing or rolling back a
PQC re-issuance run is a licensed API capability (`POST /api/v1/pqc/migrations`) not
yet exposed here as a control. See
[Lifecycle & PQC → PQC](features/lifecycle-and-pqc.md). Backed by
`/api/v1/cbom/assets`, `/api/v1/cbom/scans`, `/api/v1/discovery/ct-monitoring`, and
`/api/v1/discovery/drift-remediation`.

### Risk (`/risk`)

Risk is the ranked-by-urgency list of individual credentials — what to rotate first —
scored on age, rotation history, privilege, exposure, owner, and sensitivity, with a
per-row factor breakdown. Alongside it sit contextual risk priorities and NHI
posture panels for policy compliance, over-privilege, stale, and static credentials,
and exposure. For fleet-wide crypto hygiene (drift, PQC readiness) see Posture
instead. Backed by `/api/v1/risk/credentials`, `/api/v1/risk/contextual-priorities`,
`/api/v1/nhi/policy/compliance`, `/api/v1/nhi/posture/overprivilege`,
`/api/v1/nhi/posture/stale`, `/api/v1/nhi/posture/static-credentials`, and
`/api/v1/nhi/posture/exposure`.

### Secrets workspace (`/secrets`)

An Infisical-style workspace: a folder tree over the served key-value store, a
reference resolver that expands `${secret.path}` chains, an environment diff, a
version-history selector, secret import, and a transit console for encrypt/decrypt/HMAC
against a managed key. See [Secrets](features/secrets.md). Backed by
`/api/v1/secrets/store`, `/api/v1/secrets/store/{name}`, and `/api/v1/transit/*`.

The **Access** tab is the machine-auth console: grant a workload a scoped credential
(standing token or TTL-bound ephemeral key) with a reveal-once display and a
list-and-revoke ledger; inspect the configured auth methods — issuer, audience,
scopes, source — and disable or enable one per tenant (a disabled method is refused
at the login exchange itself); and review the issued-session ledger
(`GET /api/v1/secrets/sessions`), an idempotent, event-sourced revocation record. The
login test exchange completes the create-grant-verify loop in-console.

### Graph & blast radius (`/graph`)

The credential graph as an explorer: pick a node and see its blast radius — every
workload and resource that depends on it — backed by
`/api/v1/graph/blast-radius/{id}`. See [Graph, query & AI](features/graph-query-ai.md).

### Compliance, audit & policy (`/policy`, `/audit`)

Policy renders the policy gate, a compliance evidence-pack dashboard (pick a
framework — PCI-DSS, HIPAA, SOC 2, FedRAMP, FIPS 140, CA/B Forum BR, and more — and
export the signed pack as audit evidence), the
CAP-OBS-02 inventory report, report schedules, and the dry-run workbench. The audit
explorer filters the tamper-evident event stream and exports a signed evidence
bundle. See [Policy & governance](features/policy-and-governance.md)
and [Compliance](compliance.md). Backed by
`/api/v1/compliance/evidence-packs/{framework}`,
`/api/v1/compliance/inventory-report`, `/api/v1/compliance/report-schedules`,
`/api/v1/policy/dry-run`, `/api/v1/policy/versions`, `/api/v1/audit/events`, and
`/api/v1/audit/export`. Email/webhook report dispatch is not served.

### Privacy / data governance (`/privacy`)

The GDPR console over the served privacy stack: file a subject erasure (right to be
forgotten), export a subject's held data, trigger and review retention-enforcement
runs, and browse the personal-data catalog. See
[Privacy data catalog](privacy-data-catalog.md). Backed by
`/api/v1/privacy/subject-erasures`, `/api/v1/privacy/subject-exports`,
`/api/v1/privacy/retention-runs`, and `/api/v1/privacy/catalog`.

### Operations & trust (`/incidents`, `/codesign`, `/ca-hierarchy`)

- **Incidents** — the response console: compromise → blast radius →
  replacement-before-revoke → automated revoke/rotate/right-size playbooks →
  Splunk/Jira/Slack/ServiceNow dispatch → evidence, plus break-glass online m-of-n
  issue (`/api/v1/breakglass/issue`) and offline-quorum reconcile
  (`/api/v1/breakglass/reconcile`).
- **Code signing** — a real signing console (key-backed and keyless/Fulcio),
  submitting only the artifact digest and rendering the signature receipt; private
  keys and artifact bytes never enter the browser (`/api/v1/code-signing/sign`,
  `/api/v1/code-signing/keyless`).
- **CA hierarchy** — the m-of-n key ceremony flow, existing-CA-chain import,
  offline-root import/intermediate-CSR workflow, and HSM/KMS managed-key custody
  (generate, rotate, revoke, zeroize), guarded by RBAC. The issuer catalog has
  schema-driven config forms for built-in and upstream issuer types, sensitive-field
  masking, and per-issuer **Test connection** actions.

See [Incident response & JIT](features/incident-and-jit.md) and
[Code signing & timestamping](features/code-signing-and-timestamping.md).

### Protocols (`/protocols`)

Protocols is the enrollment control room: a live register of ACME, EST, SCEP, CMP,
SPIFFE, SSH CA, and TSA, each backed by a read-only, same-origin probe of the real
responder plus tenant-binding and profile-gate requirements. A DNS-01 provider
catalog and provider-config table (preflight, edit, delete; configs are provisioned
outside the console) support ACME's DNS-01 challenge; an MDM/SCEP panel does the same
for Intune-style SCEP, plus challenge rotation and allow/deny telemetry. A
client-setup section gives copy-paste commands per protocol, with links to SSH Trust
and Code Signing. Backed by `/api/v1/acme/dns-01/providers`,
`/api/v1/acme/dns-01/provider-configs`, `/api/v1/mdm/scep/status`, and
`/api/v1/mdm/scep/policies`.

### SSH trust (`/ssh`)

SSH Trust runs the SSH CA workflow end to end: CA/KRL status (revoked-certificate
count, trusted attestor methods, published authority key), a guarded trust-rollout
recorder, attestation-gated short-lived user-certificate issuance, serial- or
key-based revocation publishing an updated KRL, and host retirement. See
[SSH](features/ssh.md). Backed by `/api/v1/ssh/status`,
`/api/v1/ssh/trust-rollouts`, `/api/v1/ssh/attested-user-certs`,
`/api/v1/ssh/certificates/revoke`, and `/api/v1/ssh/hosts/retire`.

### Integrate hub (`/integrate`)

One place to wire trstctl into a stack: copyable ACME/EST/SCEP enrollment URLs per
issuance profile, the language SDKs (Go, TypeScript, Python, Java), and
infrastructure-as-code integrations — Terraform provider, cert-manager issuer, and
SPIRE upstream authority. Every reference points at a served surface. See
[Enrollment protocols](features/enrollment-protocols.md),
[Client SDKs](features/client-sdks.md), and
[Terraform provider](terraform-provider.md).

### API Explorer (`/integrate/api`)

API Explorer is a live console over the served OpenAPI contract, not a static
viewer: it lists every operation with its permission scope and response schema,
builds a sample request body and matching curl/SDK snippets, and — with a
self-service, 15-minute token scoped to just that operation — runs the request and
shows the real response, including RFC 7807 problem details on failure. Backed by
`GET /api/v1/openapi.json` and `POST /api/v1/access/api-tokens`.

### Operations queue and notifications (`/operations`, `/notifications`)

The operations queue shows issuance, renewal, deployment, and approval work with
type/status filters, attempts, verification badges, cancel controls for
pending/running work, and inline approve/reject for dual-control items. The
Notifications inbox lists all notification rows and dead letters, filters by
type/status, marks unread rows read, requeues failed delivery, and shows the
configured channel families from `GET /api/v1/notification-channels` (email, Slack,
Teams, SMS, SIEM, and more). The page also creates tenant notification channels with
endpoint metadata and secret references, then queues redacted channel tests through
the notification outbox; toasts report success and failure.

### Approvals, self-service & administration

- Request a credential (`/request`) and the approvals inbox (`/approvals`) are the
  self-service pair: submit, then approve as a distinct principal — the inbox blocks
  self-approval of your own request.
- Policy (`/policy`) includes access-change approvals for NHI entitlement changes: a
  PR/ticket/CAB-backed request, evidence refs, and approve/deny by a distinct
  reviewer. The panel stores metadata and evidence references only, never credential
  values.
- Administration is three routes (the old `/platform` grab-bag split; every
  historical `/platform` tab deep link redirects permanently): **Access
  administration** (`/admin/access`) covers members, roles, OIDC mapping, tokens,
  offboarding, and JIT sessions; **System posture** (`/admin/system`) is the
  read-only packaging, tenant, transport, scale, and support disclosure; and
  **Editions & license** (`/admin/editions`) is the one commercial surface — license
  state, edition/feature rows, FIPS posture, and `GET /api/v1/editions` packaging.
  **Connectors** (`/connectors`) is the deployment-connector registry: target setup,
  identity binding, deploy/rollback, and delivery receipts.
- **Wizard** (`/wizard`) is the onboarding carousel: connect an issuer, enable the
  evaluation enrollment profile, issue a first certificate, optionally prove a
  configured connector/upstream-CA/dynamic-secret backend, enroll an agent, then
  complete. Lease credential material is never retained in component state.

### Assistant (`/assistant`)

Assistant is grounded AI over the served control plane, gated by a
runtime-diagnostics disclosure (enabled state, model, egress mode/policy, redaction
boundary, refusal gate, endpoint host): Query answers questions against
certificates, owners, graph, CBOM, and audit-log evidence with citations; RCA does
root-cause analysis the same way; and MCP invokes read-only tools, only when the
server reports the tool set as read-only. Every answer reports whether it is
grounded and sufficient. Backed by `/api/v1/ai/status`, `/api/v1/mcp/tools`, `/api/v1/ai/query`,
`/api/v1/ai/rca`, and `/api/v1/mcp/tools/{tool}`. See
[Graph, query & AI](features/graph-query-ai.md).

## Cross-cutting console capabilities

- Bulk operations: fan an idempotent mutation (renew/revoke/rotate) across selected
  inventory rows and read a per-row result, so a partial failure is visible row by
  row.
- Saved views & export: persist an inventory's columns, sort, and non-sensitive
  filter metadata as a reusable view — never row payloads or auth material — and
  pull it as CSV on demand; scheduled exports are not served.
- CTA empty states: first-run pages use action-shaped empty states that point to the
  next served workflow, such as issuing a certificate or connecting an issuer.
- Command palette: Cmd+K has local commands plus debounced server-side record search
  across certificates, issuers, and identities, and quick actions for served
  workflows.
- Accessibility & theming: keyboard-navigable, screen-reader-labeled,
  reduced-motion aware, light/dark, and RTL-capable; theme preference is the only
  thing the SPA keeps in browser storage.
- VPAT evidence: `docs/accessibility-vpat.md` is the Voluntary Product Accessibility
  Template packet, backed by CI's automated axe gate and a manual audit receipt.

## Reference: route → screen

| Route | Screen |
|---|---|
| `/` | Dashboard |
| `/journeys` | Journeys |
| `/identities` | Identities & NHI |
| `/owners` | Owners |
| `/certificates` | Certificate lifecycle |
| `/request` | Request credential |
| `/profiles` | Profiles |
| `/ca-hierarchy` | CA hierarchy |
| `/protocols` | Protocols |
| `/ssh` | SSH trust |
| `/codesign` | Code signing |
| `/secrets` | Secrets workspace |
| `/agents` | Agents |
| `/workloads` | Workloads |
| `/discovery` | Discovery |
| `/risk` | Risk |
| `/posture` | Posture |
| `/graph` | Graph |
| `/incidents` | Incidents |
| `/approvals` | Approvals |
| `/operations` | Operations |
| `/notifications` | Notifications |
| `/policy` | Policy |
| `/audit` | Audit |
| `/privacy` | Privacy |
| `/connectors` | Connectors |
| `/integrate` | Integrate |
| `/integrate/api` | API Explorer |
| `/admin/access` | Access admin |
| `/admin/system` | System posture |
| `/admin/editions` | Editions |
| `/assistant` | Assistant |
| `/wizard` | Wizard (not in rail) |
| `/platform` | redirects to `/admin/*` |

## Use it

```sh
# The console is served at the control-plane root — open it in a browser:
open https://trstctl.example.com/

# It is the same served control plane the CLI drives:
trstctl-cli certificates list --limit 50
trstctl-cli privacy retention run
```

## Pitfalls & limits

- **The console is a view, not a second backend** — it adds no capability the API
  lacks. If a surface looks read-only for you, that is RBAC, not a missing screen.
- **A few adjacent capabilities are API-only or licensed-only today** — PQC
  migration queue/rollback (`/api/v1/pqc/migrations`, licensed), scheduled digest
  delivery, and email/webhook report dispatch are not served as console workflows
  and are not faked.
- **Auth lives in an HttpOnly cookie**, never in web storage; only the theme
  preference (and non-sensitive saved-view metadata) is persisted client-side.

## See also

[Platform & API](features/platform-and-api.md) ·
[Web internationalization](i18n.md) ·
[All features](features.md) ·
[Getting started](getting-started.md) ·
[Current limitations](limitations.md)
