# The web console — what you can do in the browser

trstctl ships a full web console, **served by the binary** itself: a React 18 + Vite
single-page app delivered from an embedded filesystem on the same port and TLS
certificate as the API (see **[Platform & API → The web UI](features/platform-and-api.md)**).
There is no separate static server and nothing to deploy — if the control plane is
running, the console is at its root URL, behind the same `/auth/login` session as every
other surface.

This page is the map of that console: the navigation, every screen, and — for each
screen — the served endpoints behind it and the feature page that explains the
mechanics. The console is a *view* over the served control plane; anything you can do
here you can also do through the [REST API](features/platform-and-api.md), the
[CLI](cli.md), and the [SDKs](features/client-sdks.md). Where a surface only summarizes
or visualizes (rather than adding capability), this page says so, and where a related
capability is API-only today it is called out rather than implied.

## Navigation is task-first

The sidebar is grouped around the *job* you came to do, not the table you want to read.
The five groups, in order, are:

- **Issue & renew** — set up, request a credential, certificates, identities, profiles,
  CA hierarchy, enrollment protocols, secrets.
- **Discover & inventory** — discovery, agents, workloads.
- **Approve & respond** — the approvals inbox and the incident console.
- **Monitor posture** — risk, the credential graph, posture (CBOM/PQC), and audit.
- **Administer** — audit, policy, **privacy**, **integrate**, connectors, and platform
  administration.

Above the groups sit a few **quick tasks** (for example *Expiring ≤30 days*) that deep-link
straight into a pre-filtered worklist. Every navigation row is gated by the same RBAC the
API enforces, so a viewer never sees an action they cannot take, and every label resolves
through the typed i18n catalog (see **[Web internationalization](i18n.md)**) — there is one
nav row per destination, never two.

A blank, backend-less preview is available for evaluation; the moment the binary serves
real data, the console renders that instead of the demo content.

## The surfaces

### Overview dashboard (`/`)

The single pane of glass: KPI tiles (certificates, identities, secrets, agents online,
expiring ≤7 days, high-risk, open incidents, PQC-ready), an issuance trend, an
issuance-rate chart, renewal/job success-vs-failure trend, algorithm mix, 90-day
expiration timeline, a *rotate-first* worklist drawn from served risk scores, and a
recent audit-activity stream. Below the KPIs, a **non-human-identity inventory** summary
breaks the fleet down by served `/api/v1/nhi/inventory` kind (certificates, SSH keys,
secrets, API keys, OAuth apps, tokens/PATs, service accounts, IAM roles, webhooks,
workload IDs, and agents), and a **severity-ranked alert center** projects the credentials
that need attention now — derived from served risk and certificate-expiry events. (There is
no dedicated alerts endpoint; the center is a projection of events the backend already
serves. Notification *channel* configuration and scheduled digests are not served and are
intentionally absent rather than faked.)

### Certificate lifecycle command center (`/certificates`)

The certificate inventory is also a CLM dashboard. Alongside the tenant-scoped,
cursor-paginated, server-expiry-filtered table it renders issuer/profile/team/environment
filters with URL-resident state, a Team column, **estate-wide expiry/source health**
for issued, imported, and discovery-fed certificates, **expiry bands**, a **47-day
renewal-readiness simulator** (does each cert renew comfortably inside the shrinking
CA/Browser-Forum maximum lifetime?), **deployment receipts** from the connectors, and a
tenant **CRL distribution** panel with the current full CRL, partitioned shard count,
delta base, and freshness window, plus a per-certificate **renewal history** timeline in
the detail drawer. See
**[Lifecycle & PQC](features/lifecycle-and-pqc.md)** and the
**[47-day journey](journeys/crypto-agility-pqc.md)**. Backed by `/api/v1/certificates`,
`/api/v1/certificates/health`, `/api/v1/revocation/crls`,
`/api/v1/lifecycle/rotation-runs`, and `/api/v1/connectors/deliveries`.

### Identities & NHI governance (`/identities`)

The identity grid carries the lifecycle actions (issue, deploy, revoke, with the
SURFACE-007 confirm + dual-control guards), and above it an **issuance pipeline** groups
identities by lifecycle stage. The unified **NHI inventory** summary (on the dashboard)
and the **risk posture** and **orphan-governance** panels (on `/risk` and `/owners`) give
the governance lens: counts by kind, credentials whose human custodian is gone, and a
shared risk score. See **[Workload identity](features/workload-identity.md)** and
**[Observability & risk](features/observability-and-risk.md)**. Backed by
`/api/v1/identities`, `/api/v1/nhi/inventory`, `/api/v1/risk/credentials`, and
`/api/v1/graph`.

### Discovery (`/discovery`)

The discovery front door: a **shadow-inventory** summary of unmanaged credentials found
across your environments, and a **CT-log & drift** panel that counts certificate-
transparency and configuration-drift findings from the served sources, schedules, and
runs. See **[Discovery & inventory](features/discovery-and-inventory.md)**. Backed by
`/api/v1/discovery/sources`, `/schedules`, `/runs`, and `/findings`.

### Posture — crypto-agility & PQC (`/posture`)

CT and drift findings, a **CBOM** scan trigger and cryptographic inventory, a
**PQC readiness gauge** (readiness % plus quantum-vulnerable / PQC-ready / out-of-policy
counts, framed against NIST FIPS 203/204) derived from the served CBOM
`migration_progress`, and **PQC migration orchestration** that queues a migration over the
quantum-vulnerable assets and can roll it back. See
**[Lifecycle & PQC → PQC](features/lifecycle-and-pqc.md)**. Backed by `/api/v1/cbom/assets`,
`/api/v1/cbom/scans`, and `/api/v1/pqc/migrations`.

### Secrets workspace (`/secrets`)

An Infisical-style workspace: a **folder tree** over the served key-value store, a
**reference resolver** that expands `${secret.path}` chains, an **environment diff**
between two environments or two versions, a **version history** selector, **secret import**,
and a **transit console** for encrypt / decrypt / HMAC against a managed key. See
**[Secrets](features/secrets.md)**. Backed by `/api/v1/secrets/store`,
`/api/v1/secrets/store/{name}`, and `/api/v1/transit/*`.

### Graph & blast radius (`/graph`)

The credential graph as an explorer: pick a node and see its **blast radius** — every
workload and resource that depends on it — backed by `/api/v1/graph/blast-radius/{id}`. See
**[Graph, query & AI](features/graph-query-ai.md)**.

### Compliance, audit & policy (`/policy`, `/audit`)

The **policy** page renders the policy gate, a **compliance evidence-pack dashboard**
(pick a framework — PCI-DSS, HIPAA, SOC 2, FedRAMP, CNSA 2.0, FIPS 140,
Common Criteria, CA/B Forum BR, WebTrust, or ETSI — render the signed pack, and
export audit evidence), the CAP-OBS-02 compliance inventory report, audit-export
report schedule definitions, and the dry-run gate. The **audit explorer** filters the
tamper-evident event stream (type presets such as *Policy decisions*, time and sequence
windows) and exports a **signed evidence bundle**. See
**[Policy & governance](features/policy-and-governance.md)** and **[Compliance](compliance.md)**.
Backed by `/api/v1/compliance/evidence-packs/{framework}`,
`/api/v1/compliance/inventory-report`, `/api/v1/compliance/report-schedules`,
`/api/v1/audit/events`, and `/api/v1/audit/export`. (A policy *dry-run preview*
and email/webhook report dispatch are not served and are not faked here.)

### Privacy / data governance (`/privacy`)

The GDPR console over the served privacy stack: file a **subject erasure** (right to be
forgotten), trigger and review **retention-enforcement runs**, and browse the
**personal-data catalog**. See **[Privacy data catalog](privacy-data-catalog.md)**. Backed
by `/api/v1/privacy/subject-erasures`, `/api/v1/privacy/retention-runs`, and
`/api/v1/privacy/catalog`. Data-subject *export* (`POST /api/v1/privacy/subject-exports`)
remains an API call.

### Operations & trust (`/incidents`, `/codesign`, `/ca-hierarchy`)

- **Incidents** — the response console: compromise → served **blast radius** → replacement-
  before-revoke execution → automated revoke/rotate/right-size playbooks →
  Splunk/Jira/Slack/ServiceNow response dispatch → evidence, plus a **break-glass
  reconciliation** panel that reconciles offline-issued, quorum-approved bundles back
  into the event log (`/api/v1/breakglass/reconcile`).
- **Code signing** — a real signing console (key-backed and keyless/Fulcio), submitting only
  the artifact digest and rendering the signature receipt; private keys and artifact bytes
  never enter the browser (`/api/v1/code-signing/sign`, `/api/v1/code-signing/keyless`).
- **CA hierarchy** — the m-of-n key **ceremony** flow, served existing CA chain
  import, **offline-root** import/intermediate CSR/import workflow, and HSM/KMS **managed-key custody**
  (generate, rotate, revoke, zeroize), guarded by RBAC. The issuer catalog includes
  schema-driven config forms for built-in CA and upstream issuer types, sensitive-field
  masking, and per-issuer **Test connection** actions wired to the served issuer
  registry.

See **[Incident response & JIT](features/incident-and-jit.md)** and
**[Code signing & timestamping](features/code-signing-and-timestamping.md)**.

### Operations queue and notifications (`/operations`, `/notifications`)

The operations queue shows issuance, renewal, deployment, and approval work with type and
status filters, attempts, verification badges, cancel controls for pending/running work,
and inline approve/reject actions for dual-control items. The Notifications inbox lists
all notification rows and dead letters, filters by type/status, marks unread rows read,
requeues failed delivery through the served notification API, and shows the configured
channel families returned by `GET /api/v1/notification-channels` (email, Slack, Teams,
SMS, SIEM, and the other supported sinks). Global toasts report success and failure for
these actions.

### Integrate hub (`/integrate`)

One place to wire trstctl into a stack: copyable **ACME / EST / SCEP** enrollment URLs per
issuance profile, the language **SDKs** (Go, TypeScript, Python, Java), and the
infrastructure-as-code integrations — **Terraform provider**, **cert-manager** issuer, and
**SPIRE** upstream authority. Every reference points at a served surface. See
**[Enrollment protocols](features/enrollment-protocols.md)**,
**[Client SDKs](features/client-sdks.md)**, and **[Terraform provider](terraform-provider.md)**.

### Approvals, self-service & administration

- **Request a credential** (`/request`) and the **approvals inbox** (`/approvals`) are the
  self-service pair: submit a request, then approve it as a *distinct* principal — the
  inbox blocks self-approval of your own request.
- **Platform** (`/platform`) administers tenants, members, roles, OIDC mapping, and API
  tokens; **Connectors** (`/connectors`) is the deployment-connector registry.
- **Wizard** (`/wizard`) is the onboarding carousel: connect an issuer, issue the first
  certificate, enroll an agent, then complete. It is re-openable and reduced-motion safe.

## Cross-cutting console capabilities

- **Bulk operations** — fan an idempotent mutation (renew / revoke / rotate) across selected
  inventory rows and read a **per-row result**, so a partial failure is visible row-by-row.
  Idempotency at the orchestrator makes a retried fan-out safe.
- **Saved views & export** — persist an inventory's columns, sort, and non-sensitive filter
  metadata as a reusable view (never row payloads or auth material — see the security-sink
  boundary), and pull the current view as **CSV** on demand. Saved-view scheduled CSV
  exports are not served and are not implied.
- **CTA empty states** — first-run pages use action-shaped empty states that point to the
  next served workflow, such as issuing a certificate or connecting an issuer.
- **Command palette** — Cmd+K has local commands plus debounced server-side record search
  across certificates, issuers, and identities, and quick actions for served workflows.
- **Accessibility & theming** — keyboard-navigable, screen-reader-labeled, reduced-motion
  aware, light/dark themed, and RTL-capable; the theme preference is the only thing the SPA
  is permitted to keep in browser storage.

## Use it

```sh
# The console is served at the control-plane root — open it in a browser:
open https://trstctl.example.com/

# It is the same served control plane the CLI drives:
trstctl-cli certificates list --limit 50
trstctl-cli privacy retention run
```

## Pitfalls & limits

- **The console is a view, not a second backend** — it adds no capability the API lacks.
  If a surface looks read-only for you, that is RBAC, not a missing screen.
- **Some adjacent capabilities are API-only by design today** — data-subject export,
  policy dry-run preview, notification channel configuration, scheduled digests, and
  email/webhook compliance report dispatch are not served as console workflows and are
  not faked.
- **Auth lives in an HttpOnly cookie**, never in web storage; only the theme preference (and
  non-sensitive saved-view metadata) is persisted client-side.

## See also

[Platform & API](features/platform-and-api.md) ·
[Web internationalization](i18n.md) ·
[All features](features.md) ·
[Getting started](getting-started.md) ·
[Current limitations](limitations.md)
