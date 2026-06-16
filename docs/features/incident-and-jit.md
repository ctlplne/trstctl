# Incident response & just-in-time access — contain compromise, gate access

## What it is

Sometimes a credential leaks, a [CA](../glossary.md) is compromised, or someone needs
emergency access right now. This page covers the four workflows trstctl provides for
those moments: a **credential-compromise workflow** that re-issues and revokes a leaked
credential and everything downstream of it; **fleet re-issuance** to replace every
certificate from a compromised CA; **just-in-time (JIT) issuance** that grants access
only after approval; and **break-glass** emergency signing for when the control plane
itself is down.

The mental model: this is the fire department and the keymaster combined. The compromise
workflow and fleet re-issuance are the fire response (contain and rebuild without leaving
anyone locked out); JIT is the keymaster who only hands out a key after a second person
signs off; break-glass is the sealed emergency key behind glass that takes two officers
to use.

## Why it exists

The worst time to invent a process is during an incident. A leaked key needs to be
replaced *and* every credential that depends on it rotated, in the right order, without
creating an outage. A compromised CA can mean thousands of certificates to re-issue —
impossible by hand, dangerous without health checks. And standing, always-on access is
itself a risk: JIT replaces "everyone has access all the time" with "access is granted,
approved, and expires." Each workflow is built to be safe under pressure: ordered,
audited, idempotent, and reversible.

## How it works

### Credential compromise workflow (F31)

When one credential is compromised, the danger is everything it can reach. The workflow
starts with `Preview` — a read-only walk of the credential's **blast radius** in the
[graph](graph-query-ai.md) showing exactly what's affected. Then `Remediate` runs the
fix idempotently (**AN-5**): for the credential and each downstream one it does
**reissue → revoke → rotate**, in that order, so a workload always has a valid credential
at every step (the "never left without a credential" invariant). Every step is audited
(`incident.started`, `incident.step.ok/failed`, `incident.completed/partial`, **AN-2**)
and the actual revoke/reissue rides the [outbox](../glossary.md) (**AN-6**).

*Code:* `internal/incident` (`Workflow`, `Preview`, `Remediate`).

### Fleet re-issuance for CA compromise (F32)

If a *CA* is compromised, every certificate it signed must be replaced. trstctl finds
them all via the graph, rotates the CA key first (so new certificates sign under a fresh
key), then re-issues in **health-checked batches**: after each stage it runs a health
check, and if that fails it **rolls back** that stage and halts rather than charging
ahead into an outage (**AN-7** bounded batches). It's **resumable** — a progress store
records completed credentials so an interrupted run picks up where it left off without
re-issuing anything (**AN-5/AN-6**). For an SSH CA it re-establishes trust and publishes
an updated KRL *after* confirmed-healthy re-issuance.

*Code:* `internal/fleet` (`Fleet`, `ReissueFleet`, `ProgressStore`).

### Just-in-time issuance with approval (F33)

JIT turns issuance into an approval workflow. A request enters `awaiting-approval` and
notifies approvers (Slack/Teams) — nothing is issued yet. Approvals are **dual-control**
by default (2 required, configurable for m-of-n), **self-approval is blocked**, approvers
can be policy-scoped, and the request is **time-bounded** (it expires if not approved in
time). One denial is terminal. When the quorum is met, trstctl issues and transitions to
`issued`. Approve/deny are idempotent on terminal states (**AN-5**), and every step is
audited (`approval.requested/approved/denied/issued/expired/refused`, **AN-2**).

*Code:* `internal/approval` (`Manager`, `RequestIssuance`, `Approve`, `Deny`).

### Break-glass procedures (F34)

If the control plane is unreachable during an incident, you still need to be able to
issue an emergency certificate — but safely. Break-glass is a degraded **offline** signing
ceremony gated by an **m-of-n operator quorum**: a sub-quorum request fails closed. The
escrow signing key is a handle into the isolated signer (**AN-4/AN-8**), never in-process
with the control plane. The result is a **self-verifying signed bundle** — anyone can
verify it offline (signature + chain to the CA), and a tampered bundle is rejected. On
recovery, `Reconcile` replays the bundles into the audit log as `breakglass.issued`
events (**AN-2**); a bundle that fails verification stops the batch, so a forged emergency
issuance can't be silently absorbed.

*Code:* `internal/breakglass` (`Service`, `IssueOffline`, `Verify`, `Reconcile`).

## Use it

These workflows are Go-library services today (see status below). The shapes:

```go
// Compromise: preview the blast radius, then remediate idempotently
report := incident.Preview("cert:abc123")            // read-only: what's affected
_, err := incident.Remediate(ctx, "cert:abc123", "idem-key-xyz")

// JIT: request, then two distinct approvers (dual control) → auto-issue
approval.RequestIssuance(ctx, approval.RequestSpec{ID: "req-001",
    Resource: "cert:db-tls", Requester: "alice", RequiredApprovals: 2})
approval.Approve(ctx, "tenant1", "req-001", "bob")
approval.Approve(ctx, "tenant1", "req-001", "carol")  // quorum met → issues
```

Blast-radius preview reads the same [credential graph](graph-query-ai.md) you can query
directly; JIT notifications use the [notification integrations](policy-and-governance.md).

## Pitfalls & limits

- **Serving status:** all four workflows are library-complete and tested, but are **not
  yet wired** into a served API/CLI surface — they run through their Go APIs today. Track
  this in [Current limitations](../limitations.md).
- **Order matters in remediation.** The reissue-before-revoke ordering is deliberate;
  don't shortcut it, or you risk an outage mid-incident.
- **JIT needs real approvers configured** and a notifier wired, or requests will sit in
  `awaiting-approval` until they expire.
- **Break-glass is a last resort.** It trades the control plane's guarantees for offline
  availability; reconcile the bundles promptly so the audit log is complete.

## Reference

- **Compromise:** `Workflow.Preview`, `Workflow.Remediate` (reissue→revoke→rotate).
- **Fleet:** `Fleet.ReissueFleet(issuerID, runID)` — staged, health-checked, resumable.
- **JIT:** `RequestIssuance`, `Approve`, `Deny`; default `RequiredApprovals: 2`,
  self-approval blocked.
- **Break-glass:** `IssueOffline` (quorum-gated), `Verify`, `Reconcile`.
- **Events:** `incident.*`, `fleet.*`, `approval.*`, `breakglass.issued`.

## See also

[Graph, query & AI](graph-query-ai.md) (blast radius) ·
[Issuance & certificate authorities](issuance-and-cas.md) (revocation, CA rotation) ·
[Policy & governance](policy-and-governance.md) (approver policy, notifications) ·
[Incident-response runbook](../runbooks/incident-response.md) ·
glossary: [revocation](../glossary.md), [rotation](../glossary.md), [CA](../glossary.md)

**Covers:** F31, F32, F33, F34
