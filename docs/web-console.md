# The web console — what you can do in the browser

This page is for operators and integrators who need an exact map from the browser
to the running control plane. Start with the [product map](product-map.md) if the
workspace names are new.

trstctl serves its React console from the control-plane binary, on the same port and
TLS certificate as the API. There is no second UI service to deploy. The console and
API enforce the same session and tenant boundary, but feature coverage differs
between the browser, [REST API](features/platform-and-api.md), [CLI](cli.md), and
[SDKs](features/client-sdks.md). This page names the served endpoint behind each
screen and calls out summary-only or API-only behavior.

## Navigation

The console is a unified shell: an icon rail of five spaces at the far edge, and a
sidebar scoped to the active space. _Home_ is the cross-space cockpit — Dashboard and
Journeys sit above a few quick tasks (for example _Expiring ≤30 days_) that
deep-link into a pre-filtered worklist. Each space owns every surface of one
operator question:

- _Certificate Lifecycle_ — which certificates need attention, and is renewal safe?
  It owns inventory, request, profiles, CA hierarchy, and enrollment protocols.
- _Machine & Workload Trust_ — which machines can prove who they are, and what
  needs repair? It owns workloads, machine identities, SSH trust, and agents.
- _Secrets & Access_ — which secrets need rotation, repair, or access review? It
  owns the store, dynamic engines, access, sharing, synchronization, and scanning.
- _Software Trust_ — can we prove what was signed, by whom, and with a healthy key?
  It owns software signing and timestamp-verification work.
- _Trust Operations_ — what cross-product risk, ownership, alerting, or system work
  needs attention? Its served overview at `/trust-operations` composes the existing
  risk, incident, ownership, alert-delivery, routing, and worker-health read models.
  Discovery, posture, graph, incidents, jobs, policy, approvals, audit, people,
  alerts, privacy, integrations, and administration remain reachable here.

The mechanism: the URL decides the active space — deep-linking any route lights up
its owning space, and choosing a space in the rail lands on the first route your
session may read. trstctl's cross-domain moat still meets in one place (one
identity graph, one blast-radius view, one signed audit stream): every non-Trust-Operations
space keeps a Change history (this space) row, a scoped lens over the single stream, and
the command palette jumps across spaces from anywhere. A space with no readable
routes disappears from the rail entirely, and route URLs are unchanged from the
pre-spaces console, so old links and bookmarks resolve.
Every nav row is gated by the same RBAC the API enforces, and every
label resolves through the typed i18n catalog (see
the web i18n catalog); a blank preview backs evaluation until the
binary serves real data.

## The surfaces

### Home (`/`)

Home opens with the highest-priority credential work, not a wall of metrics. Each
row names the affected workspace, operational consequence, deadline, current
automation evidence, effective owner, and safest next action. The ranking comes
from served contextual-risk evidence; current asset-specific ownership assignments
override older discovery metadata. When either source cannot be read, Home says
unknown or unavailable instead of showing a false zero.

Five compact workspace health doors then report certificate expiry, machine
identities, stored secrets, recent signing outcomes, and open incidents. Their
counts come from the current served APIs. The 47-day certificate-renewal readiness
panel remains visible. Detailed KPI charts, including the issuance-rate chart, plus
inventory mix, expiry distribution, endpoint verification, and audit activity are
retained under **Explore detailed
metrics** so the first screen answers what to do before it exposes analysis.

Alert channel and routing-policy authoring, test delivery, failures, and history
live on `/notifications` in Trust Operations. A summary on Home is not proof that a
notification was delivered.

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
the connectors, and one guided revocation center under **CRL & CT**. That center makes
an operator choose a managed X.509 identity and RFC 5280 reason, then reads an
effect-free, version-bound server plan before typed confirmation unlocks execution.
The review keeps affected systems, queued CRL/OCSP publication, signed endpoint health,
CRL availability, immutable audit evidence, and recovery guidance in one journey.
Unknown graph or propagation state is labeled unknown; it is never rendered as healthy.
The same workspace also contains the tenant CRL distribution panel (full CRL, shard
count, delta base, freshness window), a Certificate Transparency queueing form, and a
per-certificate renewal-history timeline in the detail drawer. See
[Lifecycle & PQC](features/lifecycle-and-pqc.md)
and the [47-day journey](journeys/crypto-agility-pqc.md). Backed by
`/api/v1/certificates`, `/api/v1/certificates/health`, `/api/v1/revocation/crls`,
`/api/v1/revocation/health`, `/api/v1/revocation/ct-submissions`,
`/api/v1/identities/{id}/transitions/preview`, `/api/v1/identities/{id}/transitions`,
`/api/v1/graph/nodes/{id}/blast-radius`, `/api/v1/lifecycle/rotation-runs`, and
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

### Ownership (`/owners`)

The opening answer is deliberately simple: **which team is accountable for every
identity and credential**. The visible operations cockpit reports known assets,
assets without an effective owner, owner reviews due, and missing contact or
escalation routes. A genuinely empty inventory says that nothing is known yet; it
does not masquerade as complete ownership. **Add owner** creates a durable person,
team, workload, service, or vendor record. It does not silently assign an asset.

The accountability hierarchy then reads like an incident route: business unit →
durable team or service → application and environment → contact and escalation
route → affected assets. The ownership action queue stays visible, explains why
each unowned asset needs work, and supports one-at-a-time or bulk assignment. An
assignment requires a selected durable owner and a plain-language reason. The
browser sends one idempotency-protected command; the server appends one immutable
`ownership.assigned` event and projects the effective owner. For managed identities
and certificates, the native lifecycle owner changes in that same projection, so
admission checks and the browser cannot disagree. Retrying the same command returns
the first result rather than writing a second decision.

The exact machinery remains available in three closed disclosures so a first-time
operator does not have to decode two large tables before learning whether there is
a problem:

- **Owner records, inheritance, and attestations** searches and filters accountable
  records and exposes edit, re-attest, and exact-name-confirmed delete controls. The
  application ID, service, business unit, environment, escalation recipients, and
  provenance show whether the precise application/environment model is current.
- **Coverage gaps and temporary exceptions** separates missing, incomplete,
  never-attested, and stale ownership. Operators fix the owner record first. A
  reasoned exception is available only for urgent work and must expire within 30
  days.
- **Sources, disagreements, and review history** explains the precedence rule and
  shows CMDB imports, conflicts, and the full ownership-attribution table. Exact
  owner IDs win; approved source data may inherit a match; imports never overwrite
  a human attestation; unresolved disagreements wait for review.

Backed by
`/api/v1/owners`, `/api/v1/owners/{id}`, `/api/v1/owners/{id}/attest`,
`/api/v1/identities/{id}/ownership-exceptions`, and
`/api/v1/ownership/attribution`. Bulk and contextual assignments use
`POST /api/v1/ownership/assignments`; the headless equivalent is
`trstctl-cli owners assign -f <decision.json>`.

### Agents (`/agents`)

Agents answers three questions before it exposes fleet machinery: which in-network
workers are online, which presented certificate-bound role evidence, and which
reported both a fresh heartbeat and a version. These are separate claims. An
enrolled row is not automatically called trusted, and a reported version is not
automatically called approved.

The API also keeps **lifecycle** and **presence** separate. `status` is the durable
agent-reported lifecycle/operational state. `presence.state` is a server-evaluated
connection receipt: `online`, `stale`, `unreported`, `offboarded`, or
`clock_skew`. Online means the non-offboarded agent reported within two configured
heartbeat intervals—the same rule used by the fleet alert—not “the status string
happened to say online.” The receipt includes `evaluated_at`, `fresh_until` when a
valid heartbeat exists, and an ELI5 technical reason so API, console, and alerting explain
the same result. An impossible future heartbeat fails closed as clock skew.

The only default action is **Add agent**. It opens a viewport-bounded dialog that
chooses host and/or network-relay capability, mints one bootstrap token, and shows
the install command. The role is signed into the enrolled client certificate; it
cannot change silently. Closing or dismissing the dialog clears the token from page
memory, and the console does not persist it.

Exact work remains in three closed disclosures:

- **Fleet status and safe actions** contains heartbeat and version rows, exact agent
  details, certificate revocation, and offboarding. Revocation takes effect after
  revocation data propagates. Offboarding leaves a tombstone instead of erasing the
  record.
- **Enrollment and trust evidence** shows the roles each agent reported from its
  signed certificate. Missing evidence stays missing; the console never guesses
  that an old agent has host access.
- **Versions, queues, and diagnostics** loads only when opened. It shows the active
  upgrade target and version histogram, rollout rings, pending and claimed agent
  work, verified/rejected receipts, live credential redemptions, and the exact work
  kinds this build lets agents claim. Selected-agent diagnostics also show the
  served endpoint-discovery census, Workload API posture, and enrollment-proxy
  upstream/request evidence. Discovery capabilities come from the running build's
  compiled census (including build-dependent sources) and remain metadata-only;
  the console does not receive private-key bytes.

Backed by `/api/v1/agents`, `/api/v1/agents/enrollment-tokens`,
`/api/v1/agents/upgrade-campaign`, `/api/v1/operations/jobs`,
`/api/v1/agents/{id}/offboard`, and `/api/v1/agents/{id}/cert-revocations`.

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
view compares any two versions field by field. From a historical comparison, **Review
recovery** asks why the earlier rule is needed and opens an effect-free receipt. Only
the confirmation copies that rule into a new active version; history is never edited,
and a concurrent newer version makes the confirmation fail closed. Backed by
`/api/v1/profiles`, `/api/v1/profiles/{name}/versions/{version}`, and the paired
`.../restore/preview` and `.../restore` routes.

### Find unmanaged credentials (`/discovery`)

This screen answers three questions in reading order: what trstctl found, why it
matters, and what you can safely do next. The default view puts a short attention
summary and **Credentials to review** first. Choose **Review finding** to see the
human explanation and claim it into managed inventory; less-common lifecycle actions
and raw evidence stay behind clearly named disclosures.

**Run scan** takes you to the real discovery sources so you can run an existing source
or add the first one. Sources, schedules, and run history remain one tab away. Exact
CT-log monitoring, drift, coverage, fingerprints, source/run IDs, and repository API
paths are available under **Monitoring and exact scan evidence** or **Exact finding
evidence**. They are hidden at first so an operator can make a sound decision without
decoding implementation details, not because the proof is missing. See
[Discovery & inventory](features/discovery-and-inventory.md). Backed by
`/api/v1/discovery/sources`, `/schedules`, `/runs`, `/findings`, `/monitoring`,
`/ct-monitoring`, `/drift`, and `/nhi/posture/shadow`.

### Algorithms and future readiness (`/posture`)

This screen first answers one question: **Which credentials use outdated or
incompatible cryptography?** The default view shows how many credentials were
checked, how many need an upgrade, and a plain-language worklist that explains each
current-policy or future-readiness problem beside the current and target algorithms.
An empty inventory says that nothing has been checked; it never claims that the
estate is safe.

**Plan upgrade** is the only primary action. It opens compatibility, PQC policy,
campaign tracking, and the guarded migration workflow. The Community edition keeps
CBOM discovery, readiness, campaign ownership, evidence, and signed campaign closure
usable. Licensed migration execution separately requires an exact preview, selected
assets, explicit confirmation, progress evidence, and a second confirmation before
rollback.

The complete expert machinery remains on this page under three named disclosures:

- **Algorithm inventory and scan evidence** contains a three-step CBOM workflow:
  choose TLS/file scope, review the server-normalized effect-free plan and exact safety
  limits, then run and inspect durable results. Partial failures keep successful
  observations and show repair-and-retry guidance. The section also contains the policy
  floor, algorithm rollup, exact asset rows, and recommendations.
- **Compatibility, PQC policy, and upgrade planning** contains graph-bound readiness,
  attributed owners, dependency paths, core PQC campaigns, and licensed migration.
- **Certificate, AD CS, authority, and drift evidence** contains CT monitoring,
  AD CS template/database checks, authority agreement, discovery findings, and the
  drift-remediation decision workflow.

The readiness rows use the same digest-bound graph evidence as Risk. Missing graph
placement renders as `Unknown`, never ready, and later topology drift refuses stale
evidence mutation. See [Lifecycle & PQC → PQC](features/lifecycle-and-pqc.md). Backed
by `/api/v1/cbom/assets`, `/api/v1/cbom/scans/preview`, `/api/v1/cbom/scans`,
`/api/v1/graph/crypto-readiness`, `/api/v1/graph/crypto-readiness/actions`,
`/api/v1/graph/crypto-readiness/export`, `/api/v1/pqc/campaigns`,
`/api/v1/pqc/migrations`, `/api/v1/discovery/ct-monitoring`, and
`/api/v1/discovery/drift-remediation`.

### CA migration (`/migration`)

Migration separates a read-only assessment from execution. The three-step form takes
an exact signer-backed CA authority ID, ordered waves, member identities, enrolled
host-agent IDs, and trust-anchor paths; assessment stops on unknown trust stores,
deployment targets, or verification listeners before the review step can start a
run. The server derives the public anchor from the selected authority, so neither a
CA private key nor pasted certificate text enters the browser manifest.

The run table reads the durable event projection and shows every wave's membership,
phase, and signed trust-plus-live verification percentage beside the run's current
gate. Pause blocks publication after already-leased work, resume continues the same
incomplete gate, and rollback restores predecessor leaves newest-first before
removing successor trust. A failed signed gate starts that inverse automatically;
the button remains the operator-initiated path. The buttons do not locally advance anything: only
signature-verified host-agent trust readback and live-listener receipts move a gate.
Backed by `/api/v1/migrations/assess`, `/api/v1/migrations/runs`, and the
`/api/v1/migrations/runs/{id}/{pause,resume,rollback}` mutations.

### What to fix first (`/risk`)

What to fix first opens with one ranked worklist of the credentials that create the
greatest real-world risk. Human-readable reasons explain why each item matters, and
**Review risk** shows the recommended action. Exact IDs, raw reason codes, the
versioned `CAP-POST-05` model contract, score inputs, evidence IDs, generation time,
and projection coverage remain available under **Exact score and evidence**.

The full certificate score projection and NHI posture panels for policy compliance,
over-privilege, stale/static credentials, and exposure stay available under **Score
inputs and supporting projections**. They do not compete with the default decision.
For fleet-wide crypto hygiene (drift, PQC readiness), see Posture. Backed by
`/api/v1/risk/credentials`, `/api/v1/risk/contextual-priorities`,
`/api/v1/nhi/policy/compliance`, `/api/v1/nhi/posture/overprivilege`,
`/api/v1/nhi/posture/stale`, `/api/v1/nhi/posture/static-credentials`, and
`/api/v1/nhi/posture/exposure`.

### Secrets workspaces (`/secrets`, `/secrets/*`)

The Secrets space gives each workspace its own route in the sidebar (S-C2);
historical `/secrets?tab=` deep links redirect permanently. `/secrets` is the
store — an Infisical-style workspace: a folder tree over the served key-value
store, a reference resolver that expands `${secret.path}` chains, an environment
diff, a version-history selector, and an explicit disabled bulk-import disclosure
(the server route returns `501` until atomic event-sourced batch commands exist). See
[Secrets](features/secrets.md). Backed by `/api/v1/secrets/store` and
`/api/v1/secrets/store/{name}`. **Automatic secret sources** (`/secrets/engines`) holds
dynamic leases, CSR-first PKI-as-a-secrets-engine (the default; certificate-only),
an explicit deprecated key-returning mode linked to its Audit receipts, and the
Transit console for safe key-metadata readback, typed key creation/selection/rotation,
and encrypt/decrypt/rewrap/HMAC/sign operations (`/api/v1/transit/*`). Key material
never enters the browser; a decrypted value appears only in the dismissible reveal
panel.
**One-time secret links** (`/secrets/sharing`) covers self-destructing shares and
separate ephemeral API keys. **Find leaked secrets in code** (`/secrets/scanning`)
covers repository and pipeline checks; **Send secrets to systems** (`/secrets/sync`)
shows configured destinations and refuses a delivery when none is configured.
The store's scheduled-rotation panel renders one tick's exact run and deferred-row
receipt. Deferred rows use only the served `approval_pending`,
`command_in_flight`, and `command_claimed` states, including schedule ID, due time,
and optional error. If the tick consumes exactly 50 runs or 500 scans, a localized
continuation notice says which bound was reached and directs the operator to run
again from the durable fair cursor. A typed partial `503` keeps that tick's fresh
receipt visible; a generic or malformed error clears older receipt and limit text
so stale success cannot look current.

**Machine access** (`/secrets/access`) is the machine-auth console: grant a
workload a scoped credential (standing token or TTL-bound ephemeral key) with a
reveal-once display and a list-and-revoke ledger; inspect the configured auth
methods — issuer, audience, scopes, source — and disable or enable one per tenant
(a disabled method is refused at the login exchange itself); and review the
issued-session ledger (`GET /api/v1/secrets/sessions`), an idempotent,
event-sourced revocation record. The login test exchange completes the
create-grant-verify loop in-console.

### What could be affected (`/graph`)

This screen first answers one question: **Which systems depend on a selected
credential?** Choose a credential and select **Explore impact**. The answer lists
only systems reached through relationships trstctl currently knows. It always warns
that missing discovery coverage can make the real impact larger; zero known systems
is not presented as proof of zero impact.

The relationship map, filters, node inventory, exact attributes, read-only query,
and raw edge table remain available under three named disclosures. Each served edge
can include its evidence source and confidence: foreign-key relationships are
authoritative, inventory and discovery observations are observed, name correlation
is inferred, and subject-only trust candidates are unverified. A blast-radius JSON
download keeps the selected node, known affected nodes, reachable nodes, relevant
edges, evidence labels, and coverage warning together.

Selecting an X.509 issuer also shows trust stores and distinct hosts whose discovered
anchor has the exact certificate fingerprint or SPKI public-key identity.
Same-subject/different-key matches remain a separate unverified-candidate count and
never inflate authoritative trust or automation. Backed by `/api/v1/graph`,
`/api/v1/graph/blast-radius/{id}`, `/api/v1/graph/reachable/{id}`,
`/api/v1/graph/query`, and `/api/v1/graph/trust-stores/{id}`. See
[Graph, query & AI](features/graph-query-ai.md).

### Compliance, audit & policy (`/policy`, `/audit`)

**Rules and approvals** opens with the decision an operator needs: whether fail-closed
protection is on, whether a custom rule is active, what changed, and what needs
approval. **Create rule** creates a draft only. Rule versions, safe testing, framework
evidence, reports, and access reviews stay in four closed sections until requested;
this keeps the default screen calm without removing exact evidence. Framework evidence
includes PCI-DSS, HIPAA, SOC 2, FedRAMP, FIPS 140, CA/B Forum BR, and more, with the
signed tenant/window, exact event/object references, and missing prerequisites. It
also shows signed certificate-custody totals and the exact fingerprint/fields for
every incomplete custody row, the CAP-OBS-02 inventory report, report schedules, and
the dry-run workbench.

**Change history** opens with a bounded event window and answers who changed what,
when, and whether the last event shown records a result. It does not call that window
the newest or complete history. **Search activity** opens the filters, event rows, and
exact event detail. Signatures and export, plus collector delivery, remain in two
separate closed sections until requested. This keeps the default page calm without
removing tenant-scoped evidence or operational controls.

The event explorer filters the tamper-evident stream and exports a signed evidence
bundle. Its plain search is case-insensitive across event type, privacy-filtered
actor subject and roles, and event data, so copying the visible actor into the box
returns that actor's matching rows without weakening tenant scope or erasure. The
evidence section names the exact chain head, RFC 3161 kind, authority
time, and whether the full token is present. Its download is the canonical JSON
envelope from the served contract—not a display string—so the compact JWS and
complete external timestamp remain together for offline verification against the
operator's pinned audit JWK set and TSA root. CSV downloads likewise keep their
proof in the final RFC-safe row rather than transient response headers.

The same Change history screen configures tenant-scoped scheduled Splunk HEC and
Microsoft Sentinel feeds inside **Collector delivery**. That section loads only when
opened. Its table shows the durable delivered cursor, exact queued-record
lag, retry attempt/time, terminal error code, and collector request ID. The form
accepts only an operator-allowlisted `env:NAME` credential pointer—never a token
value—and clearly separates public HTTPS from permission-gated private CIDRs. A
save records configuration and a same-transaction outbox intent; the browser never
calls the collector directly. See
[Policy & governance](features/policy-and-governance.md)
and [Compliance](compliance.md). Backed by
`/api/v1/compliance/evidence-packs/{framework}`,
`/api/v1/compliance/inventory-report`, `/api/v1/compliance/report-schedules`,
`/api/v1/policy/dry-run`, `/api/v1/policy/versions`, `/api/v1/audit/events`,
`/api/v1/audit/export`, and `/api/v1/audit/feeds[/{id}]`. Email/webhook compliance
report dispatch is not served; native audit-feed delivery is a separate served
workflow.

### Evidence privacy (`/privacy`)

Answers who can access evidence, how long it stays, and what is removed before
showing exact controls. Reading requires `privacy:read`; changing retention or
erasure evidence requires `privacy:write`; every request remains tenant-scoped.
One **Review policy** action opens the data map. Subject erasure/export, archive
removal attestations, and retention jobs stay in separate closed sections and
load on demand. See [Privacy data catalog](privacy-data-catalog.md). Backed by
`/api/v1/privacy/subject-erasures`, `/api/v1/privacy/subject-exports`,
`/api/v1/privacy/archive-erasure-attestations`,
`/api/v1/privacy/retention-runs`, and `/api/v1/privacy/catalog`.

### Trust Operations and Software Trust (`/trust-operations`, `/incidents`, `/codesign`)

- **Trust Operations overview** — the cross-domain queue names the affected product
  area, deadline, accountability state, and safest next action. Separate health
  links show open incidents, ownership gaps, failed alert deliveries, and worker
  bulkheads. Its route-safety statement is derived from the served channel and
  routing-policy APIs; it never claims that a human received an alert.

- **Incidents** — the response console: compromise → blast radius →
  replacement-before-revoke → automated revoke/rotate/right-size playbooks →
  Splunk/Jira/Slack/ServiceNow dispatch → evidence, plus break-glass online m-of-n
  issue (`/api/v1/breakglass/issue`) and offline-quorum reconcile
  (`/api/v1/breakglass/reconcile`). Its Overview also lists tenant-scoped
  receiver-command quarantines from
  `/api/v1/incidents/outbox-reconciliation-conflicts`: source sequence, old outbox
  row, lanes, agent demands, and SHA-256 command identities are visible, while the
  executable payloads are never returned to the browser.
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
SPIFFE, SSH CA, and TSA, backed by protocol-specific responder probes or authenticated
effect-free qualification plus tenant-binding and profile-gate requirements. The TSA
panel reads the exact in-memory mount, stable-certificate, isolated-signer, audit, and
bulkhead posture; it issues nothing and keeps the stock OpenSSL commands as the real
RFC 3161 wire proof. A DNS-01 provider
catalog and provider-config table (preflight, edit, delete; configs are provisioned
outside the console) support ACME's DNS-01 challenge; an MDM/SCEP panel does the same
for Intune-style SCEP, plus challenge rotation and allow/deny telemetry.

The read-only **ARI posture** panel calls `GET /api/v1/acme/ari/posture` with
`lifecycle:read`. It shows whether renewal information is really published for the
current tenant, each affected certificate's suggested renewal window, and the
durable lifecycle scheduler state that consumed that window. Loading, no affected
certificates, permission denied, API error, and ACME-not-served are distinct states;
the panel never turns an unavailable publisher into a success-looking empty table.

The read-only **Revocation cache by segment** panel calls
`GET /api/v1/revocation/caches` with `certs:read`. It shows each certificate-bound
network relay's segment, issuer fingerprint, CRL/OCSP local path, signed freshness
window, validation time, and served/refused counts. Fresh, stale, empty, API failure,
and never-reported are different states. The response is metadata-only: cached CRL
or OCSP bytes, requests, issuer certificates, upstream URLs, and credentials never
reach the browser.

A client-setup section gives copy-paste commands per protocol, with links to SSH
Trust and Code Signing. Backed by `/api/v1/acme/ari/posture`,
`/api/v1/revocation/caches`,
`/api/v1/acme/dns-01/providers`, `/api/v1/acme/dns-01/provider-configs`,
`/api/v1/mdm/scep/status`, and `/api/v1/mdm/scep/policies`.

### SSH trust (`/ssh`)

SSH Trust runs the SSH CA workflow end to end: CA/KRL status (revoked-certificate
count, trusted attestor methods, published authority key), a guarded trust-rollout
recorder, attestation-gated short-lived user-certificate issuance, serial- or
key-based revocation publishing an updated KRL, and host retirement. See
[SSH](features/ssh.md). Backed by `/api/v1/ssh/status`,
`/api/v1/ssh/trust-rollouts`, `/api/v1/ssh/attested-user-certs`,
`/api/v1/ssh/certificates/revoke`, and `/api/v1/ssh/hosts/retire`.

### Connect other tools (`/integrate`)

Connect other tools first explains the direction of each connection: devices and
services send credential requests to trstctl; trstctl sends credentials, alerts,
and events outward; SDKs, GitOps, and infrastructure code make the setup
repeatable. Its single **Add integration** action is a chooser, not a fake form. It
links to the real destination, alert/webhook, secret-sync, CA, or runnable-API
configuration screen.

The detailed enrollment and developer surfaces remain available in three closed
sections. They preserve copyable ACME/EST/SCEP URLs, the Go, TypeScript, Python,
and Java SDKs, Terraform provider, cert-manager issuer, SPIRE upstream authority,
live GitOps manifest generation, policy dry-run, and drift comparison. GitOps live
state is not fetched until that section opens. The permissions and delivery section
explains API scopes, signed webhooks, plugin capability grants, and outbox-backed
retries with receipts in plain language. Every reference points at a served
surface. See
[Enrollment protocols](features/enrollment-protocols.md),
[Client SDKs](features/client-sdks.md), and
[Terraform provider](terraform-provider.md).

### API playground (`/integrate/api`)

API playground first answers one question: how to try a safe request and understand
the response. Its default screen runs nothing. It explains the three-step path —
start with a read-only operation, create temporary least-privilege access, then read
a plain-language result — and exposes one **Try request** action. Opening the
workspace selects a read-only operation that has no required inputs when the API
lists one. Creating access and sending the request remain separate,
explicit actions.

The full OpenAPI surface remains reachable without putting hundreds of operations
on the first screen. **All contract operations** searches by name, path, summary, or
permission and renders at most 12 matches at once. **Headers, body, and exact
request** preserves every served path, query, and header parameter; JSON body;
recursive validation rule; idempotency header; and the exact normalized preview
with only the bearer secret hidden. **OpenAPI schema and code examples** links to
the served contract and keeps matching curl and SDK snippets copyable. Keyboard
users can focus every scrollable code region. A link containing
`?operation=<operationId>` opens the real workspace on that exact operation without
creating access or sending it.

The runner uses a self-service 15-minute token scoped only to the selected
operation. A write cannot run until its draft validates and the operator confirms
the exact mutation preview; changing any input clears that confirmation. In-flight
requests can be cancelled, expired tokens fail closed in the browser, and a live
token can be revoked immediately. The response starts with a plain-language answer,
then shows the real status and content type. RFC 7807 problem details remain visible,
and **Raw response** retains the exact payload. A denied or unavailable contract
names the problem and recovery action; a successfully loaded empty contract never
invents operations. Backed by `GET /api/v1/openapi.json`,
`POST /api/v1/access/api-tokens`, and `DELETE /api/v1/access/api-tokens/{id}`.

### Jobs and queues, and notifications (`/operations`, `/notifications`)

Jobs and queues answers two questions first: whether background work is moving and
which failed job needs a person. The default view shows only failed, waiting,
running, or approval-blocked work as responsive cards; raw UUIDs and internal outbox
destinations do not crowd the decision path. `Review failed job` moves keyboard
focus to the first failure. Opening that job reveals its exact ID, attempt count,
served failure reason, connector destination, idempotency key, outbox payload ID,
rollback reference, and a link to the matching immutable event log.

Three closed evidence sections keep the page calm without hiding proof. **Worker
pools and queue limits** explains each bounded pool's worker count, current depth,
capacity, saturation, rejections, and panics, then exposes the agent claim ledger,
signed receipts, and live credential-redemption custody. **All jobs and filters**
contains completed work plus type/status filters. **Rotation run records** contains
the exact lifecycle history. The UI does not offer a generic cancel button because
there is no served cancel operation; stopping or rolling back work stays with the
owning workflow rather than pretending a button succeeded.

Approval work is loaded through every cursor page instead of stopping at the first 100. Each approval is visible only when the reviewer has the matching real authority:
`certs:issue` for certificate actions, `secrets:write` for secret actions, or
`keys:approve` for managed-key actions. Reject records an immutable denial of that
exact request and does not retire, revoke, delete, or otherwise mutate the target
resource.

Alerts and delivery answers one question first: which events currently reach which
people or systems. The opening summary reports ready channels, routing rules, and
failed deliveries without claiming that an unavailable read model is empty. It also
shows a compact event-to-destination path and flags rules that reference only missing
or disabled channels. **Add channel** is the one primary action. Its bounded dialog
requires a public HTTPS destination and a credential reference, never a secret value.

Three closed evidence sections keep the default page calm. **Channels and webhooks**
shows every supported family from `GET /api/v1/notification-channels` (email, Slack,
Teams, SMS, SIEM, and more) and whether each is ready. **Routing rules and templates**
maps event severity to ready destinations, records an accountable owner, and queues a
redacted test through durable outbox work. trstctl currently uses one fixed server
alert envelope across channels; this build does not pretend to offer a tenant-editable
template library. The console leaves policy and owner fields empty rather than showing
sample data as if it were configured, and it enables **Save policy** only when every
entered destination matches a ready channel. **Delivery attempts and dead letters** filters the durable inbox,
marks unread rows read, shows retry/error/idempotency/owner/recipient evidence, and
offers requeue only for failed delivery. Toasts report real success and failure.

### Approvals, self-service & administration

- Request a credential (`/request`) and the approvals inbox (`/approvals`) are the
  self-service pair: submit, then approve as a distinct principal — the inbox blocks
  self-approval of your own request. The request wizard reads the tenant owner
  roster and requires an explicit accountable owner; an authentication subject is
  never guessed to be an owner UUID. Submission opens the first-class
  `issuance.request.opened` lifecycle object, so the requester and approver read the
  same event-projected request instead of two independently inferred views.
- **Requests waiting for approval** opens with the complete pending count and the
  next independently reviewable change. It states the reason, consequence,
  requester, and decision expiry before offering one **Review request** action. The
  bounded review shows the server-owned policy result, immutable request ID, bound
  target version and intent digest, evidence references, approval threshold, and
  audit history. Approve and reject record decisions only; neither performs the
  requested issue, rotate, revoke, create, sign, recovery, or delete operation.
  Rejection requires a reason, and self-approval stays disabled with an explicit
  dual-control explanation. The complete generic queue, issuance-request lifecycle,
  and exact-ID ephemeral tool remain available in three closed sections; ticket
  intake and specialized controls are not loaded or rendered until their section is
  opened. Credential values and private keys never enter the review.
- Rules and approvals (`/policy`) includes access-change approvals for NHI entitlement changes: a
  PR/ticket/CAB-backed request, evidence refs, and approve/deny by a distinct
  reviewer. The panel stores metadata and evidence references only, never credential
  values.
- **Platform setup** (`/platform`) is an API-free production-readiness doorway. It
  loads no protected detail and points to the first system check plus the three
  separately scoped administration pages. Historical tab-query deep links still
  redirect to their matching page. **People and roles** (`/admin/access`) covers
  members, roles, OIDC mapping, tokens,
  offboarding, and JIT sessions; **System health** (`/admin/system`) answers
  whether the control plane is securely configured, then keeps exact checks,
  configuration evidence, dependency health, and exceptions available on demand; it is the
  read-only packaging, tenant, transport, scale, and support disclosure; and
  **Plan and license** (`/admin/editions`) answers which signed features are enabled
  and when the license expires, with one **Add license** operator guide. Signature
  verification, the exact feature table, and entitlement evidence start closed.
  Packaging stays nested under entitlement evidence; distribution and active-active
  issuance proof load only when the operator opens the nested architecture section.
  The browser never uploads or stores the license: the guide uses an operator-owned
  `0600` file and restarts the control plane and isolated signer together.
  **Where credentials are installed** (`/connectors`) answers destination coverage
  and verified health first. One **Add destination** action is followed by three
  closed evidence sections for safe target actions, health/retries/rollback, and the
  full connector/plugin capability registry. Expert APIs load only when their section
  opens; identity binding, test, deploy, rollback, delivery receipts, listener proof,
  key custody, circuits, grants, and provenance remain available.
- **Wizard** (`/wizard`) is the onboarding carousel: connect an issuer, enable the
  evaluation enrollment profile, issue a first certificate, optionally prove a
  configured connector/upstream-CA/dynamic-secret backend, enroll an agent, then
  complete. Lease credential material is never retained in component state.

### Product help (`/assistant`)

**Product help** opens with one **Ask a question** action. The opening page explains
what answers can read, how tenant and role permissions limit every record, and how
exact record references let an operator check the result. It does not contact the AI
runtime or load the Model Context Protocol (MCP) tool catalog until the operator opens
the corresponding workspace or detail. A server with Product help disabled therefore
shows a calm overview instead of an unrelated availability error before the user asks
for help.

After **Ask a question**, the default form accepts plain language and reads only
certificates, owners, dependency links, cryptography inventory, and change-history
evidence allowed by the caller's tenant and role. Advanced subject and evidence-scope
controls stay under **Evidence and request details**. **Investigate a cause** keeps the
grounded root-cause workflow, and **Use read-only tools** loads MCP tools only on demand.
If the server reports write-capable MCP tools, the generic subject form remains
disabled; an operation-specific, permission-checked workflow is required instead.

Every answer says whether its evidence is grounded and sufficient and lists its
sources and exact `surface#record` references. **Runtime and privacy details** loads
the served enabled state, model, egress mode, personal-data policy, redaction boundary,
residual refusal gate, and endpoint host. Query, cause investigation, and tool calls
remain fail-closed when the surface is disabled. The route is backed by
`/api/v1/ai/status`, `/api/v1/mcp/tools`, `/api/v1/ai/query`, `/api/v1/ai/rca`, and
`/api/v1/mcp/tools/{tool}`. See [Graph, query & AI](features/graph-query-ai.md).

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

| Route               | Screen                          |
| ------------------- | ------------------------------- |
| `/`                 | Dashboard                       |
| `/trust-operations` | Trust Operations overview       |
| `/journeys`         | Journeys                        |
| `/identities`       | Identities & NHI                |
| `/owners`           | Ownership                       |
| `/certificates`     | Certificate lifecycle           |
| `/request`          | Request credential              |
| `/profiles`         | Profiles                        |
| `/ca-hierarchy`     | CA hierarchy                    |
| `/protocols`        | Protocols                       |
| `/ssh`              | SSH trust                       |
| `/codesign`         | Code signing                    |
| `/secrets`          | Secret store                    |
| `/secrets/engines`  | Automatic secret sources        |
| `/secrets/access`   | Machine access                  |
| `/secrets/sharing`  | One-time secret links           |
| `/secrets/scanning` | Find leaked secrets in code     |
| `/secrets/sync`     | Send secrets to systems         |
| `/agents`           | Agents                          |
| `/workloads`        | Workloads                       |
| `/discovery`        | Find unmanaged credentials      |
| `/risk`             | What to fix first               |
| `/posture`          | Algorithms and future readiness |
| `/graph`            | Graph                           |
| `/incidents`        | Incidents                       |
| `/approvals`        | Requests waiting for approval   |
| `/operations`       | Operations                      |
| `/notifications`    | Alerts and delivery             |
| `/policy`           | Rules and approvals             |
| `/audit`            | Change history                  |
| `/privacy`          | Evidence privacy                |
| `/connectors`       | Where credentials are installed |
| `/integrate`        | Connect other tools             |
| `/integrate/api`    | API playground                  |
| `/admin/access`     | Access admin                    |
| `/admin/system`     | System health                   |
| `/admin/editions`   | Plan and license                |
| `/assistant`        | Product help                    |
| `/wizard`           | Wizard (not in rail)            |
| `/platform`         | Platform setup                  |

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
[All features](features.md) ·
[Getting started](getting-started.md) ·
[Current limitations](limitations.md)
