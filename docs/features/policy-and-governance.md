# Policy & governance — decide what's allowed, prove what happened

## What it is

Governance is the layer that decides *whether* an action may happen, *who* may do it,
*who gets told*, and *what record is kept*. trstctl's governance is five capabilities:
a **policy engine** that allows or denies each operation, **RBAC** that enforces who can
do what, **notifications** that alert the right people, a **tamper-evident audit log**
that records everything, and **compliance reporting** that turns that record into signed
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
or overloaded pool returns *deny*. Evaluation runs on a [bulkhead](../glossary.md)
(**AN-7**) so a policy storm can't starve issuance, and every decision is recorded as a
`policy.decision` event (**AN-2**). The default policy is safe-by-default: deny everything
except revocation, and permit issuance/deployment only when a profile is bound.

*Code:* `internal/policy` (`Engine`, `Input`, `Decision`, `BaseModule`).

### RBAC (F8)

Role-based access control decides *who* may do *what*. Permissions are
`<resource>:<verb>` strings (`certs:issue`, `audit:read`); five built-in roles ship —
`admin`, `operator`, `viewer`, `auditor`, and `ra-officer` (which can request but **not**
self-issue certificates, the registration-authority separation). A principal's grants are
scoped to a tenant, and a scope check **hard-blocks cross-tenant access** (**AN-1**). The
API's `guard` middleware evaluates the required permission on every route and returns
`403 application/problem+json` on failure; the acting principal is stamped into the event
context for audit attribution (**AN-2**).

*Code:* `internal/authz` (`Permission`, `Role`, `Principal.Can`, `BuiltinRoles`),
enforced by `guard` in `internal/api`. **Status: enforced** on every served route.

### The audit log (F9)

The audit log is a **hash-chained, tamper-evident** record where each entry's hash links
to the previous one (`hash_i = SHA256(hash_{i-1} || record_i)`, via `internal/crypto`,
**AN-3**). Altering, dropping, or reordering any record breaks the chain, and
`VerifyChain` names the first broken link — offline. It is a **projection of the event
log** (**AN-2**), not a separate write store, so it can't drift from what actually
happened, and it's tenant-scoped (**AN-1**). You can export a JOSE-signed evidence bundle
an auditor verifies without touching the live system, and retention checkpoints keep the
chain verifiable even after old segments are archived.

*Code:* `internal/audit` (`Service`, `Seal`, `VerifyChain`, `Export`), `internal/auditsink`.
**Status: served** — `GET /api/v1/audit/events` and `GET /api/v1/audit/export`.

### Notifications (F29)

When something matters — a certificate nearing expiry, a CT-log anomaly — trstctl alerts
the right channel. Alerts are **outbox-driven** (**AN-6**): the alert intent is written in
the same transaction as the triggering change, and a separate dispatcher fans it out to
every configured channel, retrying at-least-once if one fails. Channels include Slack,
Microsoft Teams, email (SMTP), PagerDuty, OpsGenie, and HMAC-signed generic webhooks; each
satisfies one small interface and passes a conformance check, and channel secrets (webhook
URLs, routing keys) are never logged (**AN-8**). HTTP-based channels default to the shared
SSRF-safe client and accept only public HTTPS endpoints, so an operator-provided callback
cannot turn the control plane into a request to loopback, RFC1918, or cloud metadata
addresses.

*Code:* `internal/notify` (`Dispatcher`, `Notifier`, channels under `internal/notify/*`).

### Compliance reporting (F62)

Compliance reporting turns the audit log and the [CBOM](observability-and-risk.md) into
signed, reproducible **evidence packs** for PCI-DSS, HIPAA, SOC 2, FedRAMP, and CNSA 2.0.
For each framework it marks controls *evidenced* or *gap* based on real audit records and
crypto posture (e.g. CNSA 2.0's PQC control passes only when post-quantum assets exist and
quantum-vulnerable ones don't). Crucially, it separates **what the product evidences**
from **what the operator must still attest** (physical security, personnel) — an honest
boundary, not an over-claim. Reports are signed via `internal/crypto` (**AN-3**).

*Code:* `internal/compliance` (`Reporter`, `Generate`, frameworks `PCIDSS/HIPAA/SOC2/FedRAMP/CNSA2`).

## Use it

The audit log is served — query it and export evidence:

```sh
# query the tamper-evident log
trstctl-cli audit events --type policy.decision --since 2026-01-01T00:00:00Z --limit 100

# download a signed evidence bundle for a date range
trstctl-cli audit export --since 2026-01-01T00:00:00Z --until 2026-06-01T00:00:00Z
```

Those map to `GET /api/v1/audit/events` and `GET /api/v1/audit/export`. RBAC is enforced
on every route automatically. A default-deny policy looks like this in Rego:

```text
package trstctl.policy
default allow = false
allow { input.action == "revoke" }
allow { input.action == "issue"; input.profile != "" }
```

## Pitfalls & limits

- **Served vs library:** RBAC (F8) is enforced and the audit log (F9) is served. The
  **policy engine (F28) and the RA/dual-control gate are now served on the issuance
  path** (EXC-WIRE-03): with `ca.policy.enabled` the default-deny OPA/Rego gate runs
  on every served issue/deploy/revoke transition (fail-closed), the RA scope split
  (`certs:request` ≠ `certs:issue`) is enforced so a requester cannot self-issue, and
  with `ca.policy.require_approval` a privileged action needs a **distinct** approver
  (self-approval rejected). Notifications (F29) and compliance reporting (F62) remain
  library-complete and tested; a dedicated policy/notification *authoring* config API
  is the remaining integration step — see [Current limitations](../limitations.md).
- **Policy fails closed.** If your Rego is wrong or the engine is overloaded, operations
  are denied, not allowed — by design. Test policy changes before rollout.
- **Compliance reporting evidences controls; it does not certify you.** It's explicit
  about what you still must attest — see also [Audit & compliance](../compliance.md).
- **Notifications are at-least-once**, so design channel handlers to tolerate a duplicate.

## Reference

- **Policy:** `Engine.Evaluate(Input{Action, Profile, Actor, TenantID, Attrs})`;
  actions `issue`, `deploy`, `revoke`; fail-closed; `policy.decision` events.
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
