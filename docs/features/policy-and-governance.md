# Policy & governance — decide what's allowed, prove what happened

## What it is

Governance decides *whether* an action may happen, *who* may do it, *which runtime
attributes narrow that permission*, *who gets told*, and *what record is kept*.
trstctl's governance is six capabilities: a **policy engine** that allows or
denies each operation, **RBAC** that enforces who can do what, an **ABAC deny overlay**
that blocks requests using environment, time, actor, and resource attributes,
**notifications** that alert the right people, a **tamper-evident audit log** that
records everything, and **compliance reporting** that turns that record into signed
evidence for auditors.

The mental model: the rulebook, the ID checkpoint, the pager, the flight recorder, and
the auditor's evidence pack — controls that turn a powerful tool into one a regulated
enterprise can run.

## Why it exists

A credential platform is, by definition, powerful — it can mint and revoke the
identities holding your infrastructure together. That power needs guardrails: a way
to encode "never issue a 10-year cert," ensure only authorized people issue, know
immediately when something important happens, and keep an unforgeable record for the
inevitable audit. Without these, the platform is a liability; with them, it's what
*proves* your machine-identity hygiene to a customer's security team.

## How it works

### The policy engine (F28)

Every `issue`, `deploy`, and `revoke` passes through an embedded **[OPA](../glossary.md)
/ Rego** policy gate before it executes. The Rego module compiles once at startup — a
module that fails to compile is a hard startup error, so the system never runs without
an enforceable policy. Each decision sees structured input (`action`, `profile`, `actor`,
`tenant_id`, attributes) and is fail-closed: an evaluation error, ambiguous result, or
overloaded pool all return *deny*. Evaluation runs in its own bounded lane, so overload
is rejected fast instead of starving issuance, and every decision is recorded as an
immutable `policy.decision` event. The default policy denies everything except
revocation and permits issuance/deployment only when a profile is bound.

**Status:** served on the issuance path when `ca.policy.enabled`: the gate runs on every
issue/deploy/revoke transition, the RA scope split (`certs:request` ≠ `certs:issue`)
stops a requester from self-issuing, and `ca.policy.require_approval` requires a distinct
approver — self-approval is rejected.

### RBAC (F8)

Role-based access control decides *who* may do *what*. Permissions are
`<resource>:<verb>` strings (`certs:issue`, `audit:read`); five built-in roles ship —
`admin`, `operator`, `viewer`, `auditor`, and `ra-officer` (which can request but not
self-issue, the registration-authority separation). Grants are scoped to a
tenant, and a scope check hard-blocks cross-tenant access at the database layer, so one
tenant can never read another's. The API's `guard` middleware checks the required
permission on every route, returns `403 application/problem+json` on failure, and stamps
the acting principal into the immutable event record for audit attribution.

**Status:** enforced on every served route.

### Ownership attribution

Every non-human identity needs an accountable owner, not a discovery note that
says "owner: unknown." `GET /api/v1/ownership/attribution` (`nhi:read`) resolves managed
and discovered NHIs to a registered owner, team, or vendor, and marks anything
unresolved as `orphaned` rather than counted as accountability. See
[Discovery & inventory](discovery-and-inventory.md) for the resolution mechanics, owner
kinds, and evidence-ref shape; the same data is available via
`trstctl-cli owners attribution` and the Owners console.

Ownership attribution is also deployment authority. Owner create/update carries
`application_id`, `service`, `business_unit`, `environment`, and an ordered
escalation chain in `owner.*` v2 events. `POST /api/v1/owners/{id}/attest` records
the authenticated principal and a digest of the exact application/environment
model. A deployment event carries either that still-current proof or one active,
reasoned, attributed exception from
`/api/v1/identities/{id}/ownership-exceptions`; it is rejected with `409` when
neither exists. The configurable cadence scheduler requests re-attestation once
per stale verification edge and writes the owner/escalation notification intent
through the outbox in the same tenant transaction.

**Status:** served for managed identities plus discovery-fed NHIs.

### NHI policy compliance

`GET /api/v1/nhi/policy/compliance` (`nhi:read`) evaluates governed non-human
identities — managed and discovery-fed — against policy facts in the unified NHI
inventory: rotation cadence, allowed scopes/geographies, expiry/maximum TTL, and
business purpose.

The response is a posture view, not the raw source record: counts for compliant and
violating NHIs, per-control violation totals, severity, risk score, disallowed
scopes/geographies, recommendation text, and evidence refs such as `inventory:<id>` and
`discovery.finding:<id>`. Raw credential values are never returned. A row isn't counted
as compliant because it exists — it becomes governed only once it carries a rotation/TTL
policy, a scope or geography envelope, an expiry, or business-purpose metadata.

The same read path is available as `trstctl-cli nhi policy compliance`; the Risk console
shows the highest-severity violations beside over-privilege, stale, and
static-credential posture.

**Status:** served for metadata-backed policy compliance over managed and discovered
NHIs; authoring and activating the live Rego module is the deployment-time workflow
under the policy engine above.

### Automated NHI decommissioning

`POST /api/v1/nhi/decommission` (`identities:write`) accepts governance signals
from owner departure, vendor termination, or inactivity review and resolves them
against tenant-local managed NHI identities. The matcher understands direct
`identity_id`, `owner_id`, owner name/email, vendor name, and metadata-only
activity fields such as `last_seen_at` and `last_used_at`. Matched identities are
decommissioned through the normal lifecycle state machine: active issued,
deployed, or renewing identities are revoked with the RFC 5280
`cessationOfOperation` reason by default, and already-revoked identities are
retired. The response is an evidence pack with the signal type, action, previous
state, final state, and evidence refs for each item.

The same workflow is exposed as `trstctl-cli nhi decommission -f
nhi-decommission.json --force` and in the Identities console. It deliberately
does not treat full tenant deletion or member/API-token offboarding as NHI
decommissioning; those remain separate admin flows.

**Status:** served for managed NHI identities selected by departure, vendor-term,
and inactivity signals, using event-sourced revoke/retire transitions.

### Access-change approvals

Access-change approvals answer "who approved this non-human identity change, and which
change record justified it?" `POST /api/v1/access/requests` (`access:write`) opens a
tenant-scoped request: action (`grant`, `modify`, `revoke`, `rotate`, `deploy`, or
`break_glass`), NHI identifier and kind, resource, entitlement, PR/ticket/CAB reference,
reason, risk, evidence refs, and required approval count. trstctl infers the change
system from GitHub, GitLab, Bitbucket, ServiceNow, or Jira references; unknown systems
stay external, not a supported integration.

Decisions are recorded with `POST /api/v1/access/requests/{id}/decisions`
(`access:write`): the approver must differ from the requester, a second decision by the
same approver is rejected, and the request reaches `approved` only at quorum (any
denial moves it to `denied`). Create and decide are idempotent, so a retried
`Idempotency-Key` returns the original result rather than duplicating an approval. The
read side is projected from `access.change_request.created` and
`access.change_request.decided` events, available at `GET /api/v1/access/requests` and
`GET /api/v1/access/requests/{id}` (`access:read`).

```bash
trstctl-cli access requests create -f access-request.json
trstctl-cli access requests list --status pending
trstctl-cli access requests get <request-id>
trstctl-cli access requests decide <request-id> -f access-decision.json
```

The Policy console shows recent requests, their PR/ticket/CAB evidence, approval count,
and approve/deny actions, never displaying credential material.

**Status:** served for PR/ticket/CAB-backed access-change requests with distinct-approver
enforcement, idempotency, event projection, API, CLI, and console coverage.

### ABAC deny overlay

Attribute-based access control (ABAC) narrows a permission RBAC already granted. It's
one-way: ABAC can deny, but never grants a route or certificate action the caller
didn't hold through RBAC. RBAC answers "is this caller allowed in principle?";
ABAC answers "is this exact request allowed right now?"

Enable it with `auth.abac.enabled` and a Rego module that declares
`package trstctl.abac`. The module evaluates after RBAC on every guarded API route with
request attributes (`input.permission`, `input.resource.request.method`,
`input.resource.request.path`, optional project, actor roles, configured `input.env`,
and time fields such as `input.now_hour_utc`); on the served issue/deploy/revoke
lifecycle route it also adds identity attributes such as `identity.id`, `identity.kind`,
`identity.status`, `owner_id`, `transition.to`, `input.resource.env`, and
`input.resource.tags.service`.

ABAC fails closed: a non-compiling module stops startup, an evaluation error denies with
`403`, a saturated policy worker lane returns `503`, and every decision is recorded as an
immutable `policy.abac.decision` event. A practical change-window overlay — deny
`certs:issue` in `prod` outside a configured window — is shown in full under
[Use it](#use-it).

**Status:** served after RBAC on every guarded route when `auth.abac.enabled`, plus
identity-attribute evaluation on issue/deploy/revoke.

### The audit log (F9)

Buyer receipt for CAP-POL-06 Tamper-evident / signed audit log: the served audit
surface is `GET /api/v1/audit/events` for tenant-scoped replay and `GET
/api/v1/audit/export` for a signed offline evidence bundle.

The console names this surface **Change history** and starts with a bounded event
summary rather than raw event machinery. It does not call that window the newest or
complete history. **Search activity** opens filters, rows, and
event detail. The plain search is case-insensitive across event type,
privacy-filtered actor subject and roles, and event data. Hash-chain status and signed or ingestible exports live under
**Signatures and evidence export**; scheduled SIEM feeds live under **Collector
delivery**. All three sections preserve the same served endpoints and tenant scope,
and explicit query links open the search layer automatically.

The audit log is a hash-chained, tamper-evident record where each entry's hash links
to the previous one (`hash_i = SHA256(hash_{i-1} || record_i)`; all hashing goes through
the single crypto path). Altering, dropping, or reordering any record breaks the chain,
and `VerifyChain` names the first broken link — offline. Every change is recorded as an
immutable event, and the audit log is a rebuilt view of that history, not a separate
write store, so it can't drift from what actually happened; it's tenant-isolated at the
database layer. You can export a JOSE-signed evidence bundle an auditor verifies without
touching the live system, and retention checkpoints keep the chain verifiable even after
old segments are archived.

**Status:** served — `GET /api/v1/audit/events` and `GET /api/v1/audit/export`.

Both endpoints accept `tool` in addition to `feature_id`, `action`, event type,
text and time filters. The tool predicate is server-owned and applied before the
result limit. For example, `tool=workloads_machines` includes attestation and
workload issuance, not just events containing the word “ssh.” Unknown tools fail
with HTTP 400. Every export encoding preserves the same scope and retained-prefix
chain. See [the CLI filter examples](../cli.md#verify-audit-exports-offline).

### Notifications (F29)

When something matters — a certificate nearing expiry, a CT-log anomaly — trstctl alerts
the right channel using reliable, journaled delivery: the alert intent is written in the
same transaction as the triggering change so a crash can't drop it, and a dispatcher
fans it to every configured channel, retrying at-least-once on failure.
Channels (full list under [Reference](#reference)) each satisfy one small interface and
pass a conformance check; channel secrets (webhook URLs, routing keys, API tokens) are
held in wipeable memory where the provider allows it and never logged.
HTTP-based channels default to the shared SSRF-safe client and accept only public HTTPS
endpoints, so an operator callback can't turn the control plane into a request to
loopback, RFC1918, or cloud-metadata addresses.

The `/notifications` console names this journey **Alerts and delivery**. Its opening
summary says whether any ready channel and routing rule actually connect an event to a
person or system, and it separates failed-delivery evidence from configuration. One
**Add channel** action opens a bounded form; channel coverage, routing, and delivery
attempts remain in three closed detail sections until needed. The server applies one
fixed alert envelope across channel providers. There is no tenant-editable template
library in this build, and the console states that limitation instead of presenting a
false template editor. The console does not prefill invented channel or owner values,
and it keeps routing-policy save disabled until the server has reviewed the exact
unsaved draft and every entered destination is a ready channel. **Review exact route**
does not save the rule, write an event, queue a message, or contact a provider. It
returns the normalized scope and channel set, a stable request fingerprint, missing
channel blockers, the later execution effects, the recovery steps, and the checks an
operator can use after saving. Editing any field invalidates that review, so an old
green result cannot authorize a changed rule. Save also rechecks current server-side
channel readiness, closing the gap where a channel is disabled after review.

**Status:** served. When the lifecycle alert window is set, the leader scheduler writes
`notification.expiry` outbox work, stamps the certificate alerted, and includes the
owner/contact plus active approver recipients. Tenants manage channels at
`/api/v1/notification-channels` (create, read, replace, delete); rows store endpoint
metadata and credential references only, redact those in responses, and rebuild from
`notification.channel.*` events. The outbox dispatcher resolves enabled tenant-authored
channels at delivery time; process-configured channels remain supported for bootstrap.
Severity and threshold-day metadata route through the
severity-to-channel routing matrix instead of fanning every alert to every channel;
`EffectiveAlertChannels` resolves the policy-specific set at dispatch time, and a
per-(subject, threshold, channel) dedup ledger stops the same threshold from firing
twice on the same channel. Operators can list channel families, queue redacted tests at
`/api/v1/notification-channels/{id}/test`, work the inbox (list, get, mark read), and
requeue failed dispatches from `/api/v1/notifications/{id}/requeue`. Every successful
fan-out records a `notification.delivery.recorded` event before the outbox row is acknowledged,
so a retry after failure skips channels already rebuilt from the event log; channel
tests replay through `notification.test.queued` events. Operators can review an exact
routing-policy draft at `POST /api/v1/notification-routing-policies/preview`, manage
the saved rules at `/api/v1/notification-routing-policies`, and inspect the effective
saved hierarchy with `GET /api/v1/notification-routing-preview`. Recovery is explicit:
replace or delete a bad policy, then requeue only the failed delivery. Retrying is safe
because completed channel receipts are preserved and skipped.

### Compliance reporting (F62)

Compliance reporting turns the audit log and the [CBOM](observability-and-risk.md) into
signed, reproducible evidence packs covering all 15 supported frameworks (full list
under [Reference](#reference)). A v2 pack binds its claims to one tenant and one
inclusive 90-day evidence window. Every evidenced control names exact immutable event
references (ID, tenant-local sequence, type, time, and audit-chain digest) or exact
tenant graph objects. Every prerequisite must resolve inside that boundary; missing,
stale, malformed, or wrong-tenant evidence is a visible *gap*. CNSA 2.0's PQC control,
for example, passes only when post-quantum assets exist and quantum-vulnerable ones do
not. Reports are signed through the single crypto path, but a valid signature proves
authenticity of the bounded manifest, not certification or auditor sufficiency.

Each pack states residuals honestly. `fips-140` marks POST evidenced only when the
running module is active and its fail-closed self-test passes; build provenance,
crypto-boundary artifacts, CMVP certificate, and deployment configuration stay gaps
without exact evidence. `common-criteria` can evidence attributable policy/change and
credential-lifecycle facts, while its security target and lab evaluation remain gaps.
`cabf-br` requires exact profile, CA issuance/revocation, custody, and ceremony events;
CP/CPS publication and independent public-trust audit remain external. `soc2` requires
current inventory plus complete ownership and review for CC6, policy/lifecycle/
monitoring events for CC7, and active-policy/approved-change/lifecycle evidence for
CC8; scope, management assertion, sampling, and the independent CPA report remain
residuals.

**Status:** served — evidence-pack export, inventory/schedule surface, and NHI
compliance mapping below are all live REST/CLI/console routes. `GET
/api/v1/compliance/inventory-report` enumerates served frameworks, report types, backing
routes, evidence references, schedule rows, and inventory counts across certificates,
CBOM assets, and discovery/report schedules; `POST`/`GET
/api/v1/compliance/report-schedules` record and list idempotent, event-sourced
schedules, with compliance-report delivery limited to `audit_export` until a served
report runner exists. This limitation does not apply to the separate native audit
feed: `PUT /api/v1/audit/feeds/{id}` and `GET /api/v1/audit/feeds` configure and
observe durable Splunk HEC or Microsoft Sentinel batches. `GET
/api/v1/compliance/nhi-report` builds a separate mapping (NIST SP 800-53 Rev. 5, NIST
CSF 2.0, PCI DSS 4.0, DORA, ISO/IEC 27001:2022 Annex A, FedRAMP, CMMC 2.0, eIDAS, NIS2)
from served NHI posture only — never documentation or unsupported claims — with finding
counts and residual attestations for legal scope, control applicability, and auditor
sampling.

The same surface runs NHI access certification campaigns: a reviewer starts a campaign
with non-secret NHI/resource/entitlement items, then records each item decision as
`certified`, `revoked`, or `exception` — event-sourced, with routes and events listed
under [Reference](#reference). The request body accepts identifiers and evidence refs
only; inline secrets and credential values are rejected.

### Privacy and data-subject controls (F79)

Privacy controls are first-class governance surfaces, not hidden compliance helpers.
`POST /api/v1/privacy/subject-erasures` records a tenant-scoped subject erasure, emits
`privacy.subject.erased`, and projects pseudonymized or cleared personal data while
keeping audit evidence verifiable. `POST /api/v1/privacy/retention-runs` records a
non-audit PII retention pass, emits `privacy.retention.enforced`, and applies configured
retention windows to operational metadata. `POST /api/v1/privacy/subject-exports`
answers access/portability requests as a read-only export that does not mutate state or
carry an `Idempotency-Key`. `GET /api/v1/privacy/catalog` exposes the maintained
personal-data catalog so operators can see what fields are subject to erasure and
retention.

Erasure binds the authenticated caller, exact route, subject, and reason to its
`Idempotency-Key`. A tenant-scoped durable operation record retains the canonical
event identity and response after the generic response cache expires or the live
event moves to the signed audit archive. That record is independent PostgreSQL
backup state, so projection rebuild and snapshot restore do not erase retry
authority.

When erasure changes bytes in the hot event history, the control plane also emits
`history.tenant_data_rewrite.continuity`. This is system-signed generation evidence,
not a second operator API event: its canonical JWS binds the tenant, old/new
generation and configuration identities, invariant/mapping/content roots, audit-chain
heads, retention seed, and the disclosure that older external archives, exports, or
backups may still retain the source bytes.

The CLI exposes the same controls through `privacy erasures erase`, `privacy erasures
list`, `privacy retention run`, `privacy retention list`, `privacy export`, and `privacy
catalog`; the web console's `/privacy` screen covers erasure, retention enforcement,
retention evidence, and the catalog. See [Privacy data catalog](../privacy-data-catalog.md)
for the row-level map and erasure/retention behavior.

### In the console

The `/policy` screen is named **Rules and approvals**. Its opening answer says whether
the fail-closed protection gate is on, whether a custom rule is active, how many rule
versions are recorded, and how many access requests need approval. It never reports a
healthy state when either opening API cannot be verified. The only opening action,
**Create rule**, saves a reviewed draft; it does not activate that draft.

Exact machinery remains available in four closed sections: rule versions and change
history, safe rule testing, framework evidence and reports, and approval/access
reviews. Opening framework evidence loads any of the 15 supported frameworks (list
under [Reference](#reference)), its signed tenant and coverage window, exact
per-control references, and missing prerequisites. The signed manifest also counts
certificate custody by origin, storage, and exportability and lists every incomplete
certificate with its missing fields; the screen shows those exact gaps instead of
hiding them in a percentage. The reporting section also contains the compliance
inventory report, audit-export schedules, and NHI compliance mapping. The safe-test
section calls `POST /api/v1/policy/dry-run` to compile a candidate lifecycle or ABAC
Rego module against tenant input, returns allow/deny/error plus a bounded trace, and
appends `policy.dry_run.evaluated` without raw values. The change-history section
serves lifecycle rule listing, activation, and rollback through
`/api/v1/policy/versions`; activation remains a separate recorded action after the
candidate compiles. The approvals section contains NHI access-certification campaigns
and access-change decisions. The `/audit`
screen is a filterable audit explorer (type presets such as *Policy decisions*, time and
sequence windows) that downloads a signed evidence bundle and manages scheduled
Splunk HEC/Sentinel delivery with cursor, record lag, retry, failure, and collector
receipt state; the `/privacy` screen renders
the served data-subject controls and catalog. See [The web console](../web-console.md).

## Use it

The audit log is served — query it and export evidence:

```sh
# query the tamper-evident log
trstctl-cli audit events --type policy.decision --since 2026-01-01T00:00:00Z --limit 100

# download a signed evidence bundle for a date range
trstctl-cli audit export --since 2026-01-01T00:00:00Z --until 2026-06-01T00:00:00Z

# review, configure, and observe a native collector feed (body shown in docs/cli.md)
trstctl-cli audit feeds preview <feed-uuid> -f audit-feed.json
trstctl-cli --idempotency-key audit-feed-production audit feeds set <feed-uuid> -f audit-feed.json
trstctl-cli audit feeds list

# export a signed SOC 2 evidence pack
trstctl-cli compliance evidence-pack soc2

# read compliance inventory coverage
trstctl-cli compliance inventory-report

# read NHI compliance mappings
trstctl-cli compliance nhi-report

# dry-run a candidate Rego module, then author/activate a lifecycle policy version
trstctl-cli policy dry-run --body policy-dry-run.json
trstctl-cli --idempotency-key policy-author-42 policy versions create -f lifecycle-policy-version.json
printf '{"reason":"CAB approved"}' | trstctl-cli --idempotency-key policy-activate-42 policy versions activate <version-id> -f -

# record a report-schedule definition
cat > soc2-schedule.json <<'JSON'
{"framework":"soc2","name":"weekly-soc2-pack","interval_seconds":604800,"delivery":"audit_export"}
JSON
trstctl-cli --idempotency-key weekly-soc2 compliance report-schedules create -f soc2-schedule.json

# start and decide an NHI access certification campaign
trstctl-cli access reviews start -f nhi-review.json
trstctl-cli access reviews decide <campaign-id> <item-id> -f nhi-review-decision.json

# file and review data-subject privacy controls
trstctl-cli privacy erasures erase -f subject-erasure.json
trstctl-cli privacy retention run
trstctl-cli privacy catalog
```

Routes for every command above are in [Reference](#reference); all mutations need an
`Idempotency-Key`. Evidence packs support all 15 frameworks (path values in
[Reference](#reference)) and return a signed export plus `public_key_der` so an auditor
can verify the manifest offline. RBAC is enforced automatically. A default-deny policy
looks like this in Rego:

```text
package trstctl.policy
default allow = false
allow { input.action == "revoke" }
allow { input.action == "issue"; input.profile != "" }
```

Turn on the ABAC deny overlay when a decision depends on current deployment state or
resource tags:

```yaml
auth:
  abac:
    enabled: true
    environment:
      change_window: "false"
    module: |
      package trstctl.abac
      default deny := false
      deny if {
        input.permission == "certs:issue"
        input.resource.env == "prod"
        input.env.change_window != "true"
      }
```

## Pitfalls & limits

- Read the status line in each section above: every capability here is served, but
  several are gated behind a config flag (`ca.policy.enabled`, `ca.policy.require_approval`,
  `auth.abac.enabled`); [Reference](#reference) gives the exact flag and route.
- Policy fails closed. If your Rego is wrong or the engine is overloaded, operations
  are denied, not allowed. Test policy changes before rollout.
- Compliance reporting, privacy controls, NHI campaigns, and access-change approvals
  evidence controls; they do not certify you. Campaigns prove a reviewer attested to
  listed access at a point in time; approvals prove who approved a scoped NHI change
  against a PR/ticket/CAB reference; privacy evidence proves the product executed the
  configured controls. External auditors decide whether your whole program meets
  a framework — see also [Audit & compliance](../compliance.md).
- Notifications are at-least-once, so design channel handlers to tolerate a duplicate.

## Reference

- **Policy:** `Engine.Evaluate(Input{Action, Profile, Actor, TenantID, Attrs})`;
  actions `issue`, `deploy`, `revoke`; fail-closed; `policy.decision` events; dry-run
  and versioning at `POST /api/v1/policy/dry-run`, `POST|GET /api/v1/policy/versions`,
  `POST /api/v1/policy/versions/{id}/activate`, and
  `POST /api/v1/policy/versions/{id}/rollback`.
- **ABAC deny overlay:** `package trstctl.abac`; `input.permission`,
  `input.resource.*`, `input.env.*`, `input.now_hour_utc`; deny-only; fail-closed;
  `policy.abac.decision` events.
- **RBAC:** permissions `<resource>:<verb>`; roles `admin`, `operator`, `viewer`,
  `auditor`, `ra-officer`; `guard` middleware.
- **Audit (served):** `GET /api/v1/audit/events` (`type`, `since`, `until`, `as_of`, `q`,
  `limit`), `GET /api/v1/audit/export`, `GET /api/v1/audit/feeds`, and `PUT
  /api/v1/audit/feeds/{id}`; `Seal`/`VerifyChain`. Feed configuration, queued exact
  batches, delivery receipts, and terminal failures are immutable events; the
  external call occurs only from the `audit.feed.*` outbox worker.
- **Compliance reporting (served):** `GET /api/v1/compliance/evidence-packs/{framework}`,
  `GET /api/v1/compliance/inventory-report`, `GET /api/v1/compliance/nhi-report`,
  `POST|GET /api/v1/compliance/report-schedules`; report-schedule delivery is
  `audit_export` only.
- **Access-change approvals (served):** `POST|GET /api/v1/access/requests[/{id}]`, and
  `POST /api/v1/access/requests/{id}/decisions`; CLI: `access requests create|list|get|decide`.
- **Notifications:** email, Slack, Teams, SMS, SIEM, PagerDuty, OpsGenie, webhook
  (HMAC-signed); HTTP targets are public HTTPS by default; channel routes are
  `POST|GET /api/v1/notification-channels`,
  `GET|PUT|DELETE /api/v1/notification-channels/{id}`, and
  `POST /api/v1/notification-channels/{id}/test`; routing-policy routes are
  `POST /api/v1/notification-routing-policies/preview`,
  `POST|GET /api/v1/notification-routing-policies`,
  `GET|PUT|DELETE /api/v1/notification-routing-policies/{id}`, and
  `GET /api/v1/notification-routing-preview`; inbox routes are
  `GET /api/v1/notifications[/{id}]`, `POST /api/v1/notifications/{id}/read`, and
  `POST /api/v1/notifications/{id}/requeue`.
- **Compliance frameworks (15, evidence packs):** PCI-DSS (`pci-dss`), HIPAA
  (`hipaa`), SOC 2 (`soc2`), NIST SP 800-53 (`nist-800-53`), NIST CSF 2.0
  (`nist-csf-2.0`), FedRAMP (`fedramp`), CMMC 2.0 (`cmmc-2.0`), CNSA 2.0
  (`cnsa-2.0`), FIPS 140 (`fips-140`), Common Criteria (`common-criteria`),
  CA/Browser Forum Baseline Requirements (`cabf-br`), WebTrust (`webtrust`), ETSI
  (`etsi`), eIDAS (`eidas`), and NIS2 (`nis2`).
- **NHI access reviews:** `POST|GET /api/v1/access/reviews[/{id}]`, `POST
  /api/v1/access/reviews/{id}/items/{item_id}/decision`; decisions `certified`,
  `revoked`, `exception`; events `nhi.access_review.campaign.started` and
  `nhi.access_review.item.decided`.
- **Privacy controls:** `POST|GET /api/v1/privacy/subject-erasures`,
  `POST|GET /api/v1/privacy/retention-runs`, `POST /api/v1/privacy/subject-exports`,
  `GET /api/v1/privacy/catalog`; operator-command events `privacy.subject.erased` and
  `privacy.retention.enforced`, plus system-signed generation evidence
  `history.tenant_data_rewrite.continuity` when hot history bytes change.

## See also

[Platform & API](platform-and-api.md) (where RBAC is enforced) ·
[Workload identity](workload-identity.md) (the policy gate in action) ·
[Observability & risk](observability-and-risk.md) (the CBOM behind compliance) ·
[Audit & compliance](../compliance.md) · [Product threat model](../security/threat-model.md) ·
glossary: [event sourcing](../glossary.md), [bulkhead](../glossary.md),
[idempotency](../glossary.md)

**Covers:** F28, F29, F62, F79, F8, F9
