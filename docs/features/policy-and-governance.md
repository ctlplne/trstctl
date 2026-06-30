# Policy & governance — decide what's allowed, prove what happened

## What it is

Governance is the layer that decides *whether* an action may happen, *who* may do it,
*which runtime attributes narrow that permission*, *who gets told*, and *what record is
kept*. trstctl's governance is six capabilities: a **policy engine** that allows or
denies each operation, **RBAC** that enforces who can do what, an **ABAC deny overlay**
that blocks requests using environment, time, actor, and resource attributes,
**notifications** that alert the right people, a **tamper-evident audit log** that
records everything, and **compliance reporting** that turns that record into signed
evidence for auditors.

The mental model: this is the rulebook, the ID checkpoint, the pager, the flight
recorder, and the auditor's evidence pack — the controls that turn a powerful tool into
one a regulated enterprise can actually run.

## Why it exists

A credential platform is, by definition, powerful — it can mint and revoke the identities
that hold your infrastructure together. That power needs guardrails: a way to encode
"never issue a 10-year cert," a way to ensure only authorized people issue, a way to know
immediately when something important happens, and an unforgeable record for the inevitable
audit. Without these, the platform is a liability; with them, it's the thing that *proves*
your machine-identity hygiene to a customer's security team.

## How it works

### The policy engine (F28)

Every `issue`, `deploy`, and `revoke` passes through an embedded **[OPA](../glossary.md)
/ Rego** policy gate before it executes. The Rego module is compiled once at startup — a
module that doesn't compile is a hard startup error, so the system never runs without an
enforceable policy. Each decision sees structured input (`action`, `profile`, `actor`,
`tenant_id`, attributes) and is **fail-closed**: any evaluation error, ambiguous result,
or overloaded pool returns *deny*. Evaluation runs in its own bounded lane — overload is
rejected fast instead of starving issuance — and every decision is recorded as an
immutable `policy.decision` event in the tamper-evident log. The default policy is
safe-by-default: deny everything except revocation, and permit issuance/deployment only
when a profile is bound.

### RBAC (F8)

Role-based access control decides *who* may do *what*. Permissions are
`<resource>:<verb>` strings (`certs:issue`, `audit:read`); five built-in roles ship —
`admin`, `operator`, `viewer`, `auditor`, and `ra-officer` (which can request but **not**
self-issue certificates, the registration-authority separation). A principal's grants are
scoped to a tenant, and a scope check **hard-blocks cross-tenant access** — each tenant's
data is isolated at the database layer, so one tenant can never read another's. The
API's `guard` middleware evaluates the required permission on every route and returns
`403 application/problem+json` on failure; the acting principal is stamped into the
immutable event record for audit attribution.

**Status: enforced** on every served route.

### Ownership attribution (CAP-GOV-01)

Ownership attribution answers a simple governance question for every non-human
identity: who is accountable for it right now? `GET
/api/v1/ownership/attribution` (`nhi:read`) reads the tenant-scoped unified NHI
inventory and joins it to projected owner records. Managed credentials resolve by
`owner_id`; discovered credentials can resolve metadata-only owner, team, or
vendor names to registered owner records. Anything unresolved is returned as
`orphaned`, so a discovery note that merely says "owner: unknown" never counts as
served accountability.

Owner kinds include `user`, `team`, `workload`, `service`, and `vendor`. The
response includes a per-NHI attribution status, attribution source, evidence refs
such as `owner_id:<uuid>` or `metadata.owner:<name>`, and a summary that counts
attributed, orphaned, human/user, team, and vendor coverage. The same surface is
available in the CLI as `trstctl-cli owners attribution`, and the Owners console
shows the attribution table beside the owner registry.

**Status: served** for managed identities plus discovery-fed NHIs from the served
inventory path, including user, team, vendor, and orphaned coverage.

### NHI policy compliance (CAP-GOV-03)

`GET /api/v1/nhi/policy/compliance` (`nhi:read`) evaluates governed non-human
identities against explicit policy facts in the unified NHI inventory. It covers
managed identities and discovery-fed NHIs, and checks the table-stakes controls buyers
expect: rotation cadence, allowed scopes, allowed geographies, expiry / maximum TTL,
and business purpose.

The response is a policy posture view, not the raw source record. It returns counts for
compliant and violating NHIs, per-control violation totals, severity, risk score,
disallowed scopes/geographies, recommendation text, and evidence refs such as
`inventory:<id>`, `discovery.finding:<id>`, and `metadata:allowed_scopes`. Raw
credential values and raw discovery/source metadata are not returned. Rows without
policy metadata are not counted as compliant just because they exist; a row becomes
governed when it carries policy-required evidence, a rotation/TTL policy, an allowed
scope or geography envelope, an expiry, or business-purpose metadata.

The same read path is available as `trstctl-cli nhi policy compliance`, and the Risk
console shows the highest-severity CAP-GOV-03 violations beside over-privilege, stale,
and static-credential posture.

**Status: served** for metadata-backed NHI policy compliance over managed and
discovered NHIs. Authoring and activating the global live Rego module remains the
deployment-time policy workflow described under the core policy engine.

### Automated NHI decommissioning (CAP-GOV-04)

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

**Status: served** for managed NHI identities selected by departure, vendor-term,
and inactivity signals, using event-sourced revoke/retire transitions.

### Access-change approvals (CAP-GOV-05)

Access-change approvals answer "who approved this non-human identity change, and which
change record justified it?" `POST /api/v1/access/requests` (`access:write`) opens a
tenant-scoped request for an NHI entitlement change. The request records the action
(`grant`, `modify`, `revoke`, `rotate`, `deploy`, or `break_glass`), NHI identifier and
kind, resource, entitlement, PR/ticket/CAB reference, reason, risk, evidence refs, and
required approval count. trstctl infers the change system from common GitHub, GitLab,
Bitbucket, ServiceNow, and Jira references; unknown systems remain external instead of
being counted as a supported integration.

Decisions are recorded with `POST /api/v1/access/requests/{id}/decisions`
(`access:write`). The acting subject, or an explicit approver subject, must be different
from the requester. A second decision by the same approver is rejected. Approval moves the
request to `approved` only when quorum is reached; any denial moves it to `denied`.
Create and decide are idempotent mutations, so a retried request with the same
`Idempotency-Key` returns the original result instead of duplicating an approval. The read
side is projected from `access.change_request.created` and
`access.change_request.decided` events and is available through
`GET /api/v1/access/requests` and `GET /api/v1/access/requests/{id}` (`access:read`).

The same workflow is exposed as:

```bash
trstctl-cli access requests create -f access-request.json
trstctl-cli access requests list --status pending
trstctl-cli access requests get <request-id>
trstctl-cli access requests decide <request-id> -f access-decision.json
```

The Policy console shows recent access-change requests, their PR/ticket/CAB evidence,
approval count, and approve/deny actions. It does not ask for or display credential
material; the workflow stores only metadata and evidence references.

**Status: served** for PR/ticket/CAB-backed NHI access-change requests with distinct
approver enforcement, idempotency, event projection, API, CLI, and Policy-console
coverage.

### ABAC deny overlay

Attribute-based access control (ABAC) narrows a permission that RBAC already granted.
The model is deliberately one-way: ABAC can **deny**, but it can never grant a route or
certificate action the caller did not already hold through RBAC. This keeps the mental
model simple: RBAC answers "is this caller allowed in principle?", then ABAC answers
"is this exact request allowed right now?"

Enable it with `auth.abac.enabled` and a Rego module that declares
`package trstctl.abac`. The module evaluates after RBAC on every guarded API route with
request attributes (`input.permission`, `input.resource.request.method`,
`input.resource.request.path`, optional project, actor roles, configured
`input.env`, and time fields such as `input.now_hour_utc`). On the served
issue/deploy/revoke lifecycle route, trstctl also adds identity resource attributes:
`identity.id`, `identity.kind`, `identity.name`, `identity.status`, `owner_id`,
`transition.to`, and flattened identity attributes such as `input.resource.env` or
`input.resource.tags.service`.

ABAC fails closed. A non-compiling ABAC module stops startup; an evaluation error
denies with `403`; a saturated policy worker lane returns `503`; and every decision is
recorded as an immutable `policy.abac.decision` event. A practical change-window
overlay looks like this:

```text
package trstctl.abac

default deny := false
default reason := ""

deny if {
  input.permission == "certs:issue"
  input.resource.env == "prod"
  input.env.change_window != "true"
}

reason := "prod certificates may issue only during a change window" if {
  input.permission == "certs:issue"
  input.resource.env == "prod"
  input.env.change_window != "true"
}
```

### The audit log (F9)

The audit log is a **hash-chained, tamper-evident** record where each entry's hash links
to the previous one (`hash_i = SHA256(hash_{i-1} || record_i)`; all hashing goes through
the single crypto path). Altering, dropping, or reordering any record breaks the chain,
and `VerifyChain` names the first broken link — offline. Every change is recorded as an
immutable event, and the audit log is a **rebuilt view of that history**, not a separate
write store, so it can't drift from what actually happened; it's tenant-isolated at the
database layer. You can export a JOSE-signed evidence bundle an auditor verifies without
touching the live system, and retention checkpoints keep the chain verifiable even after
old segments are archived.

**Status: served** — `GET /api/v1/audit/events` and `GET /api/v1/audit/export`.

### Notifications (F29)

When something matters — a certificate nearing expiry, a CT-log anomaly — trstctl alerts
the right channel. Alerts use **reliable, journaled delivery**: the alert intent is
written in the same transaction as the triggering change — so a crash can't drop it — and
a separate dispatcher fans it out to every configured channel, retrying at-least-once if
one fails. Channels include email (SMTP), Slack, Microsoft Teams, SMS gateway delivery,
SIEM collector delivery, PagerDuty, OpsGenie, and HMAC-signed generic webhooks; each
satisfies one small interface and passes a conformance check, and channel secrets
(webhook URLs, routing keys, API tokens) are held in wipeable memory where the provider
API allows it and never logged. HTTP-based channels default to the shared SSRF-safe
client and accept only public HTTPS endpoints, so an operator-provided callback cannot
turn the control plane into a request to loopback, RFC1918, or cloud metadata addresses.

**Status: partially served.** Expiry alerts are served by the running binary when an
operator configures notification channels under `notifications.*` and sets the lifecycle
alert window: the leader scheduler writes `notification.expiry` outbox work, stamps the
certificate as alerted, and includes the owner id/contact plus active approver recipients
from the tenant-member read model. The outbox dispatcher uses severity and threshold-day
metadata with the severity-to-channel routing matrix instead of fanning every alert to
every channel. `EffectiveAlertChannels` resolves the policy-specific channel set at
dispatch time. A per-(subject, threshold, channel) dedup ledger prevents the same expiry
threshold for the same credential from being sent to the same channel again. Operators can
list the supported/configured channel families at `/api/v1/notification-channels`,
list/get the tenant-scoped notification inbox, inspect the owner/approver escalation
fields, mark rows read at `/api/v1/notifications/{id}/read`, and requeue failed
notification dispatches from `/api/v1/notifications/{id}/requeue` with idempotency keys.
Tenant-facing channel CRUD and test delivery remain deployment-time configuration rather
than served API.

### Compliance reporting (F62)

Compliance reporting turns the audit log and the [CBOM](observability-and-risk.md) into
signed, reproducible **evidence packs** for PCI-DSS, HIPAA, SOC 2, NIST SP
800-53, NIST CSF 2.0, FedRAMP, CMMC 2.0, CNSA 2.0, FIPS 140, Common Criteria,
CA/Browser Forum Baseline Requirements, WebTrust, ETSI, eIDAS, and NIS2.
For each framework it marks controls *evidenced* or *gap* based on real audit records and
crypto posture (e.g. CNSA 2.0's PQC control passes only when post-quantum assets exist and
quantum-vulnerable ones don't). Crucially, it separates **what the product evidences**
from **what the operator must still attest** (physical security, personnel) — an honest
boundary, not an over-claim. Reports are signed through the single crypto path.
The `fips-140` pack records the FIPS-capable build artifact gate, `--fips`
fail-closed power-on self-test, single crypto boundary, and CI evidence while
keeping the NIST CMVP certificate and approved deployment configuration as
external residuals. The Platform posture (`GET /api/v1/editions` and `/platform`)
serves the same live module state, build target, CI gate, and residual for operators
who need the key-management view rather than a signed audit pack. The
`common-criteria` pack maps TOE/security-target evidence
for API, signer, tenant isolation, RBAC, audit, and crypto-boundary controls while
keeping the lab evaluation report, certificate, protection profile, and evaluated
configuration guide as external residuals.
The `cabf-br` pack turns the same served route into CA/Browser Forum Baseline
Requirements evidence: profile lint/zlint posture, CA issuance/revocation audit
evidence, signer isolation, and HSM-capable key management are product-evidenced,
while CP/CPS publication, domain-validation/CAA procedures, CA/Browser Forum policy
operation, and independent public-trust audit remain operator/auditor residuals.
WebTrust and ETSI packs add broader CA-audit posture controls while keeping
practitioner opinion, qualified trust-service status, and external conformity
assessment as explicit operator/auditor residuals.
The `soc2` pack maps logical-access evidence for non-human credentials,
security-event monitoring evidence, and change-management evidence to CC6/CC7/CC8
style trust-services criteria from tenant RBAC, NHI posture, signed audit
events, and the event-sourced change trail. It keeps trust-services category
scope, management assertion, operating-effectiveness sampling, subservice
organization carve-outs, and the independent CPA SOC 2 examination report as
operator/auditor residuals.

CAP-OBS-02 adds the inventory/reporting layer around those packs. `GET
/api/v1/compliance/inventory-report` returns a tenant-scoped report that
enumerates the served frameworks, supported report types, backing routes, evidence
references, report-schedule rows, and inventory counts from certificates, CBOM
assets, discovery schedules, and report schedules. `POST
/api/v1/compliance/report-schedules` records an idempotent,
event-sourced schedule definition, and `GET /api/v1/compliance/report-schedules`
lists the tenant's definitions. Delivery is deliberately limited to
`audit_export`; email, webhook, and ticket dispatch are not claimed until a
served runner exists.

CAP-CMP-04, CAP-CMP-05, and CAP-CMP-06 add compliance mappings for external table-stakes
frameworks. `GET /api/v1/compliance/evidence-packs/{framework}` serves signed
framework packs for PCI DSS, HIPAA, SOC 2, NIST SP 800-53, NIST CSF 2.0,
FedRAMP, CMMC 2.0, CNSA 2.0, FIPS 140, Common Criteria, CA/B Forum BR,
WebTrust, ETSI, eIDAS, and NIS2. `GET /api/v1/compliance/nhi-report` builds an
audit-ready, tenant-scoped mapping for NIST SP 800-53 Rev. 5, NIST CSF 2.0, PCI
DSS 4.0, DORA, ISO/IEC 27001:2022 Annex A, FedRAMP, CMMC 2.0, eIDAS, and NIS2.
The reports are generated from the served NHI inventory, NHI over-privilege
posture, stale/orphan/dormant posture, static credential posture, CBOM posture,
and audit export routes; they never treat documentation or unsupported claims as
evidence. The output lists every mapped framework/control, the served evidence
refs behind it, posture finding counts, supported report types including
`nhi_compliance_mapping`, and residual attestations for legal scope, governance
policy, control applicability, authorization packages, and auditor sampling.

The same served governance surface now includes **NHI access certification campaigns**
(CAP-GOV-02). A reviewer starts a campaign with non-secret NHI/resource/entitlement
items and evidence references, then records each item decision as `certified`,
`revoked`, or `exception`. Campaign state is event-sourced: `POST
/api/v1/access/reviews` emits `nhi.access_review.campaign.started`, each `POST
/api/v1/access/reviews/{id}/items/{item_id}/decision` emits
`nhi.access_review.item.decided`, and the read model recomputes pending/certified/
revoked/exception counts from those events. The request body accepts identifiers and
evidence refs only; inline secrets, tokens, passwords, and credential values are rejected.

### In the console

The `/policy` screen renders a **compliance evidence-pack dashboard** - pick a framework
(PCI-DSS, HIPAA, SOC 2, NIST SP 800-53, NIST CSF 2.0, FedRAMP, CMMC 2.0,
CNSA 2.0, FIPS 140, Common Criteria, CA/B Forum BR, WebTrust, ETSI, eIDAS, or
NIS2), render the signed pack, and export audit
evidence - plus the CAP-OBS-02 **compliance inventory report** and audit-export
schedule-definition form. It also renders the CAP-CMP-06 **NHI compliance
mapping** for NIST, PCI DSS, DORA, ISO 27001, FedRAMP, CMMC, eIDAS, and NIS2
evidence, plus an **NHI access
certification** panel for starting campaigns and recording reviewer decisions. The
policy authoring workbench calls `POST /api/v1/policy/dry-run` to compile a
candidate lifecycle or ABAC Rego module, force the authenticated tenant into the
input, return allow/deny/error plus a bounded trace, and append
`policy.dry_run.evaluated` without raw module/input values. The `/audit` screen is
a filterable **audit explorer** (type presets such as *Policy decisions*, time and
sequence windows) that downloads a signed evidence bundle. Live policy activation
remains config/deploy-time and is not counted as a served policy-management UI. See
[The web console](../web-console.md).

## Use it

The audit log is served — query it and export evidence:

```sh
# query the tamper-evident log
trstctl-cli audit events --type policy.decision --since 2026-01-01T00:00:00Z --limit 100

# download a signed evidence bundle for a date range
trstctl-cli audit export --since 2026-01-01T00:00:00Z --until 2026-06-01T00:00:00Z

# export a signed SOC 2 evidence pack with audit, access, and change evidence
trstctl-cli compliance evidence-pack soc2

# read CAP-OBS-02 inventory/reporting coverage
trstctl-cli compliance inventory-report

# read CAP-CMP-06 NHI compliance mappings for NIST/PCI/DORA/ISO evidence
trstctl-cli compliance nhi-report

# dry-run a candidate Rego module against tenant-scoped JSON input
trstctl-cli policy dry-run --body policy-dry-run.json

# record an audit-export report schedule definition
cat > soc2-schedule.json <<'JSON'
{"framework":"soc2","name":"weekly-soc2-pack","report_type":"framework_evidence_pack","interval_seconds":604800,"delivery":"audit_export","recipient_ref":"audit-archive"}
JSON
trstctl-cli --idempotency-key weekly-soc2 compliance report-schedules create -f soc2-schedule.json
trstctl-cli compliance report-schedules list

# start an NHI access certification campaign from metadata/evidence refs
trstctl-cli access reviews start -f nhi-review.json

# record an item decision
trstctl-cli access reviews decide <campaign-id> <item-id> -f nhi-review-decision.json
```

Those map to `GET /api/v1/audit/events`, `GET /api/v1/audit/export`,
`GET /api/v1/compliance/evidence-packs/{framework}`,
`GET /api/v1/compliance/inventory-report`,
`GET /api/v1/compliance/nhi-report`, `POST
/api/v1/compliance/report-schedules`, and `GET
/api/v1/compliance/report-schedules`. NHI certification campaigns map to
`POST /api/v1/access/reviews`, `GET /api/v1/access/reviews`, `GET
/api/v1/access/reviews/{id}`, and `POST
/api/v1/access/reviews/{id}/items/{item_id}/decision`; policy dry-run maps to
`POST /api/v1/policy/dry-run`. All mutations require an `Idempotency-Key`.
Evidence packs support `pci-dss`, `hipaa`, `soc2`, `nist-800-53`,
`nist-csf-2.0`, `fedramp`, `cmmc-2.0`, `cnsa-2.0`, `fips-140`,
`common-criteria`, `cabf-br`, `webtrust`, `etsi`, `eidas`, and `nis2`; the response
contains a signed export plus `public_key_der` so an auditor can verify the
manifest offline. RBAC is enforced on every route automatically. A default-deny
policy looks like this in Rego:

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
      default reason := ""
      deny if {
        input.permission == "certs:issue"
        input.resource.env == "prod"
        input.env.change_window != "true"
      }
      reason := "prod certificates may issue only during a change window" if {
        deny
      }
```

## Pitfalls & limits

- **Served vs library:** RBAC (F8) is enforced, the ABAC deny overlay is served, and
  the audit log (F9), framework evidence-pack export, compliance inventory report,
  and audit-export report schedule definitions (F62/CAP-OBS-02) are served. The
  **policy engine (F28) and the RA/dual-control gate are now served on the issuance
  path**: with `ca.policy.enabled` the default-deny OPA/Rego gate runs
  on every served issue/deploy/revoke transition (fail-closed), the RA scope split
  (`certs:request` ≠ `certs:issue`) is enforced so a requester cannot self-issue, and
  with `ca.policy.require_approval` a privileged action needs a **distinct** approver
  (self-approval rejected). With `auth.abac.enabled`, the ABAC deny overlay runs after
  RBAC on guarded API routes and with identity tags on issue/deploy/revoke.
  Notifications (F29) now have served expiry-alert dispatch
  through operator-wired channels, but a dedicated notification *authoring* config API
  is still the remaining integration step — see [Current limitations](../limitations.md).
- **Policy fails closed.** If your Rego is wrong or the engine is overloaded, operations
  are denied, not allowed — by design. Test policy changes before rollout.
- **Compliance reporting, NHI campaigns, and access-change approvals evidence controls;
  they do not certify you.** Campaign decisions prove a reviewer attested to listed
  machine access at a point in time. Access-change approvals prove who approved a scoped
  NHI entitlement change against a PR/ticket/CAB reference. External auditors still decide
  whether your whole program meets a framework — see also
  [Audit & compliance](../compliance.md).
- **Notifications are at-least-once**, so design channel handlers to tolerate a duplicate.

## Reference

- **Policy:** `Engine.Evaluate(Input{Action, Profile, Actor, TenantID, Attrs})`;
  actions `issue`, `deploy`, `revoke`; fail-closed; `policy.decision` events.
- **ABAC deny overlay:** `package trstctl.abac`; `input.permission`,
  `input.resource.*`, `input.env.*`, `input.now_hour_utc`; deny-only; fail-closed;
  `policy.abac.decision` events.
- **RBAC:** permissions `<resource>:<verb>`; roles `admin`, `operator`, `viewer`,
  `auditor`, `ra-officer`; `guard` middleware.
- **Audit (served):** `GET /api/v1/audit/events` (`type`, `since`, `until`, `as_of`, `q`,
  `limit`), `GET /api/v1/audit/export`; `Seal`/`VerifyChain`.
- **Compliance reporting (served):** `GET /api/v1/compliance/evidence-packs/{framework}`,
  `GET /api/v1/compliance/inventory-report`, `POST
  /api/v1/compliance/report-schedules`, and `GET
  /api/v1/compliance/report-schedules`; report-schedule delivery is `audit_export`
  only.
- **Access-change approvals (served):** `POST /api/v1/access/requests`, `GET
  /api/v1/access/requests`, `GET /api/v1/access/requests/{id}`, and `POST
  /api/v1/access/requests/{id}/decisions`; CLI commands `access requests create`,
  `access requests list`, `access requests get`, and `access requests decide`.
- **Notifications:** email, Slack, Teams, SMS, SIEM, PagerDuty, OpsGenie, webhook
  (HMAC-signed); HTTP targets are public HTTPS by default; catalog/inbox routes are
  `GET /api/v1/notification-channels`, `GET /api/v1/notifications`,
  `GET /api/v1/notifications/{id}`, `POST /api/v1/notifications/{id}/read`, and
  `POST /api/v1/notifications/{id}/requeue`.
- **Compliance frameworks:** PCI-DSS, HIPAA, SOC 2, FedRAMP, CNSA 2.0.
- **NHI access reviews:** `POST /api/v1/access/reviews`, `GET /api/v1/access/reviews`,
  `GET /api/v1/access/reviews/{id}`, `POST
  /api/v1/access/reviews/{id}/items/{item_id}/decision`; decisions `certified`,
  `revoked`, `exception`; events `nhi.access_review.campaign.started` and
  `nhi.access_review.item.decided`.

## See also

[Platform & API](platform-and-api.md) (where RBAC is enforced) ·
[Workload identity](workload-identity.md) (the policy gate in action) ·
[Observability & risk](observability-and-risk.md) (the CBOM behind compliance) ·
[Audit & compliance](../compliance.md) · [Product threat model](../security/threat-model.md) ·
glossary: [event sourcing](../glossary.md), [bulkhead](../glossary.md),
[idempotency](../glossary.md)

**Covers:** F28, F29, F62, F8, F9
