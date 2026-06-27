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
one fails. Channels include Slack, Microsoft Teams, email (SMTP), PagerDuty, OpsGenie, and
HMAC-signed generic webhooks; each satisfies one small interface and passes a conformance
check, and channel secrets (webhook URLs, routing keys) are held in wipeable memory and
never logged. HTTP-based channels default to the shared SSRF-safe client and accept only
public HTTPS endpoints, so an operator-provided callback cannot turn the control plane
into a request to loopback, RFC1918, or cloud metadata addresses.

**Status: partially served.** Expiry alerts are served by the running binary when an
operator wires notification channels into the process and sets the lifecycle alert
window: the leader scheduler writes `notification.expiry` outbox work, stamps the
certificate as alerted, and the outbox dispatcher fans the alert to Slack, Teams, email,
PagerDuty, OpsGenie, and webhook channel implementations. Tenant-facing channel CRUD,
test delivery, and delivery-receipt APIs are still not mounted.

### Compliance reporting (F62)

Compliance reporting turns the audit log and the [CBOM](observability-and-risk.md) into
signed, reproducible **evidence packs** for PCI-DSS, HIPAA, SOC 2, FedRAMP, and CNSA 2.0.
For each framework it marks controls *evidenced* or *gap* based on real audit records and
crypto posture (e.g. CNSA 2.0's PQC control passes only when post-quantum assets exist and
quantum-vulnerable ones don't). Crucially, it separates **what the product evidences**
from **what the operator must still attest** (physical security, personnel) — an honest
boundary, not an over-claim. Reports are signed through the single crypto path.

### In the console

The `/policy` screen renders a **compliance evidence-pack dashboard** — pick a framework
(PCI-DSS, HIPAA, SOC 2, FedRAMP, CNSA 2.0), render the signed pack, and export audit
evidence — and the `/audit` screen is a filterable **audit explorer** (type presets such as
*Policy decisions*, time and sequence windows) that downloads a signed evidence bundle. A
policy *dry-run preview* and *scheduled* reports are not served and are not faked in the
console. See [The web console](../web-console.md).

## Use it

The audit log is served — query it and export evidence:

```sh
# query the tamper-evident log
trstctl-cli audit events --type policy.decision --since 2026-01-01T00:00:00Z --limit 100

# download a signed evidence bundle for a date range
trstctl-cli audit export --since 2026-01-01T00:00:00Z --until 2026-06-01T00:00:00Z

# export a signed SOC 2 evidence pack with CBOM/FIPS posture
trstctl-cli compliance evidence-pack soc2
```

Those map to `GET /api/v1/audit/events`, `GET /api/v1/audit/export`, and
`GET /api/v1/compliance/evidence-packs/{framework}`. Evidence packs support
`pci-dss`, `hipaa`, `soc2`, `fedramp`, and `cnsa-2.0`; the response contains a
signed export plus `public_key_der` so an auditor can verify the manifest offline.
RBAC is enforced on every route automatically. A default-deny policy looks like
this in Rego:

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
  the audit log (F9) plus framework evidence-pack export (F62) are served. The
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
- **Compliance reporting evidences controls; it does not certify you.** It's explicit
  about what you still must attest — see also [Audit & compliance](../compliance.md).
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
- **Notifications:** Slack, Teams, email, PagerDuty, OpsGenie, webhook (HMAC-signed);
  HTTP targets are public HTTPS by default.
- **Compliance frameworks:** PCI-DSS, HIPAA, SOC 2, FedRAMP, CNSA 2.0.

## See also

[Platform & API](platform-and-api.md) (where RBAC is enforced) ·
[Workload identity](workload-identity.md) (the policy gate in action) ·
[Observability & risk](observability-and-risk.md) (the CBOM behind compliance) ·
[Audit & compliance](../compliance.md) · [Product threat model](../security/threat-model.md) ·
glossary: [event sourcing](../glossary.md), [bulkhead](../glossary.md),
[idempotency](../glossary.md)

**Covers:** F28, F29, F62, F8, F9
