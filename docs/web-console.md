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

The console is a unified shell: an icon rail of five spaces at the far edge, and a
sidebar scoped to the active space. *Home* is the cross-space plane — Dashboard and
Journeys sit above a few quick tasks (for example *Expiring ≤30 days*) that
deep-link into a pre-filtered worklist. Each space owns every surface of one
concern: *Certificates & PKI* (certificates, request, profiles, CA hierarchy,
protocols, code signing), *Secrets* (the secrets workspace), *Workload & SSH*
(workloads, identities, SSH trust), *Posture & response* (find unmanaged
credentials, algorithms and future readiness, risk, what could be affected, incidents,
operations — the Detect & respond
group), and *Platform* (policy, approvals, audit, owners, privacy under Govern &
administer; agents, connectors, notifications under Infrastructure; integrations
and the API explorer; access, system posture, editions, and the assistant under
Administration).

The mechanism: the URL decides the active space — deep-linking any route lights up
its owning space, and choosing a space in the rail lands on the first route your
session may read. trstctl's cross-domain moat still meets in one place (one
identity graph, one blast-radius view, one signed audit stream): every non-Platform
space keeps a Change history (this space) row, a scoped lens over the single stream, and
the command palette jumps across spaces from anywhere. A space with no readable
routes disappears from the rail entirely, and route URLs are unchanged from the
pre-spaces console, so old links and bookmarks resolve.
Every nav row is gated by the same RBAC the API enforces, and every
label resolves through the typed i18n catalog (see
the web i18n catalog); a blank preview backs evaluation until the
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

### Ownership (`/owners`)

The opening answer is deliberately simple: **which team is accountable for every
identity and credential**. It reports how many known identities and credentials
have an owner record and how many owner records are current. **Assign owner** is the
only primary action. A genuinely empty inventory says that nothing is known yet; it
does not masquerade as complete ownership. Assigning creates an accountable person,
team, workload, service, or vendor record; it does not silently rewrite existing
credential assignments.

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
`/api/v1/ownership/attribution`.

### Agents (`/agents`)

Agents answers three questions before it exposes fleet machinery: which in-network
workers are online, which presented certificate-bound role evidence, and which
reported both a fresh heartbeat and a version. These are separate claims. An
enrolled row is not automatically called trusted, and a reported version is not
automatically called approved.

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
view compares any two versions field by field. Backed by `/api/v1/profiles` and
`/api/v1/profiles/{name}/versions/{version}`.

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

- **Algorithm inventory and scan evidence** contains the CBOM scan trigger, policy
  floor, algorithm rollup, exact asset rows, recommendations, and scan results.
- **Compatibility, PQC policy, and upgrade planning** contains graph-bound readiness,
  attributed owners, dependency paths, core PQC campaigns, and licensed migration.
- **Certificate, AD CS, authority, and drift evidence** contains CT monitoring,
  AD CS template/database checks, authority agreement, discovery findings, and the
  drift-remediation decision workflow.

The readiness rows use the same digest-bound graph evidence as Risk. Missing graph
placement renders as `Unknown`, never ready, and later topology drift refuses stale
evidence mutation. See [Lifecycle & PQC → PQC](features/lifecycle-and-pqc.md). Backed
by `/api/v1/cbom/assets`, `/api/v1/cbom/scans`,
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
an explicit deprecated key-returning mode linked to its Audit receipts, and the transit console for
encrypt/decrypt/HMAC against a managed key (`/api/v1/transit/*`).
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
bundle. The evidence section names the exact chain head, RFC 3161 kind, authority
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
SPIFFE, SSH CA, and TSA, each backed by a read-only, same-origin probe of the real
responder plus tenant-binding and profile-gate requirements. A DNS-01 provider
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
builds a sample request body and matching curl/SDK snippets, and turns every served
path, query, and header parameter plus JSON body into an editable request draft.
Optional query fields stay empty until the operator supplies them. Required values,
UUIDs, RFC3339 timestamps, enums, numbers, booleans, arrays, and recursive JSON
requirements validate before execution; the exact encoded URL, headers, and
normalized body are shown with only the bearer secret hidden.

The runner uses a self-service 15-minute token scoped to just that operation. A
write cannot run until the draft validates and the operator explicitly confirms
the exact preview; changing any input clears that confirmation. In-flight requests
can be cancelled, expired tokens fail closed in the browser, and the current token
can be revoked immediately. The response panel shows real status/content type,
including RFC 7807 problem details. Backed by `GET /api/v1/openapi.json`,
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

Approval work is loaded through every cursor page instead of stopping at the first
100. Each approval is visible only when the reviewer has the matching real authority:
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
- Administration is three routes (the old `/platform` grab-bag split; every
  historical `/platform` tab deep link redirects permanently): **Access
  administration** (`/admin/access`) covers members, roles, OIDC mapping, tokens,
  offboarding, and JIT sessions; **System posture** (`/admin/system`) is the
  read-only packaging, tenant, transport, scale, and support disclosure; and
  **Editions & license** (`/admin/editions`) is the one commercial surface — license
  state, edition/feature rows, FIPS posture, and `GET /api/v1/editions` packaging.
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
| `/owners` | Ownership |
| `/certificates` | Certificate lifecycle |
| `/request` | Request credential |
| `/profiles` | Profiles |
| `/ca-hierarchy` | CA hierarchy |
| `/protocols` | Protocols |
| `/ssh` | SSH trust |
| `/codesign` | Code signing |
| `/secrets` | Secret store |
| `/secrets/engines` | Automatic secret sources |
| `/secrets/access` | Machine access |
| `/secrets/sharing` | One-time secret links |
| `/secrets/scanning` | Find leaked secrets in code |
| `/secrets/sync` | Send secrets to systems |
| `/agents` | Agents |
| `/workloads` | Workloads |
| `/discovery` | Find unmanaged credentials |
| `/risk` | What to fix first |
| `/posture` | Algorithms and future readiness |
| `/graph` | Graph |
| `/incidents` | Incidents |
| `/approvals` | Requests waiting for approval |
| `/operations` | Operations |
| `/notifications` | Alerts and delivery |
| `/policy` | Rules and approvals |
| `/audit` | Change history |
| `/privacy` | Privacy |
| `/connectors` | Where credentials are installed |
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
[All features](features.md) ·
[Getting started](getting-started.md) ·
[Current limitations](limitations.md)
