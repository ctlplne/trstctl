# Incident response & just-in-time access — contain compromise, gate access

## What it is

Sometimes a credential leaks, a [CA](../glossary.md) is compromised, or someone needs
emergency access right now. This page covers the four workflows trstctl provides for
those moments: a **credential-compromise workflow** that re-issues and revokes a leaked
credential and everything downstream of it; **fleet re-issuance** to replace every
certificate from a compromised CA; **just-in-time (JIT) issuance** that grants access
only after approval; **JIT privileged access sessions** for Postgres and SSH; and
**break-glass** emergency signing for when the control plane itself is down.

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

When one credential identity is compromised, the danger is everything it can reach. The
served workflow starts with a read-only **blast-radius snapshot** from the
[graph](graph-query-ai.md), then executes the containment path idempotently — every
state-changing request takes an `Idempotency-Key`, so a retry never applies the change
twice: it creates a replacement identity, issues it, deploys it through the connector
outbox, and only then revokes the compromised identity. The result is recorded as an
immutable `incident.execution.recorded` evidence pack — with the replacement id,
revocation queue status, connector delivery receipt, failed-target list, rollback
references, and a sealed audit bundle — and its outbound deliveries are journaled first
so a crash can't drop them.

### Fleet re-issuance for CA compromise (F32)

If a *CA* is compromised, every certificate it signed must be replaced. trstctl finds
them all via the graph, rotates the CA key first (so new certificates sign under a fresh
key), then re-issues in **health-checked batches**: after each stage it runs a health
check, and if that fails it **rolls back** that stage and halts rather than charging
ahead into an outage — batches run in a bounded lane that rejects overload fast rather
than starving other work. It's **resumable** — a progress store records completed
credentials so an interrupted run picks up where it left off without re-issuing anything,
because re-issuance is idempotent and outbound work is journaled first so a crash can't
drop or duplicate it. For an SSH CA it re-establishes trust and publishes an updated KRL
*after* confirmed-healthy re-issuance.

### Just-in-time issuance with approval (F33)

JIT turns issuance into an approval workflow. A request enters `awaiting-approval` and
notifies approvers (Slack/Teams) — nothing is issued yet. Approvals are **dual-control**
by default (2 required, configurable for m-of-n), **self-approval is blocked**, approvers
can be policy-scoped, and the request is **time-bounded** (it expires if not approved in
time). One denial is terminal. When the quorum is met, trstctl issues and transitions to
`issued`. Approve/deny take an `Idempotency-Key` and are no-ops once a request is
terminal, so a retry never double-acts, and every step is recorded as an immutable event
(`approval.requested/approved/denied/issued/expired/refused`).

For privileged-access management, the same JIT model opens short-lived sessions instead
of standing database or shell access. `POST /api/v1/access/sessions` verifies an
attestation, grants a scoped Postgres login role or signs an OpenSSH user certificate
for a configured SSH target, returns the one-time credential to the caller, and records a
tenant-scoped session row. The session expires automatically: Postgres roles are revoked
by the background expiry worker, and SSH access ends at the certificate `valid_before`
time. The event trail is filterable by `pam.session.started` and
`pam.session.expired`; credential material is not written into those events.

**Status:** the core identity approval gate is served through
`POST /api/v1/identities/{id}/approvals`, ephemeral/JIT credential issuance is served
when configured through `POST /api/v1/ephemeral` plus
`POST /api/v1/ephemeral/{request_id}/approvals`, and PAM-lite sessions are served
through `POST /api/v1/access/sessions`, `GET /api/v1/access/sessions`, and
`GET /api/v1/access/sessions/{id}`. The ephemeral path verifies the attestation first,
writes the approval request and outbox notification intent in the same tenant
transaction, blocks requester self-approval, then mints a short-TTL credential only
after a distinct approver records approval. CLI parity is `trstctl-cli ephemeral issue`
and `trstctl-cli ephemeral approve`; PAM sessions use `trstctl-cli access sessions open`,
`trstctl-cli access sessions list`, and `trstctl-cli access sessions get`.

### Break-glass procedures (F34)

If the control plane is unreachable during an incident, you still need to be able to
issue an emergency certificate — but safely. Break-glass is a degraded **offline** signing
ceremony gated by an **m-of-n operator quorum**: a sub-quorum request fails closed. The
escrow signing key is a handle into the separate, isolated signing service, never in the
control-plane process, and it lives in wipeable memory that is zeroed after use. The
result is a **self-verifying signed bundle** — anyone can verify it offline (signature +
chain to the CA), and a tampered bundle is rejected. On recovery,
`POST /api/v1/breakglass/reconcile` verifies those bundles against deployment-pinned
break-glass verifier material and replays them into the hash-chained audit log as
immutable `breakglass.issued` events. A bundle that fails verification stops the batch,
so a forged emergency issuance can't be silently absorbed. The served route does **not**
issue emergency certificates online; offline m-of-n issuance remains the operator
ceremony.

### In the console

The `/incidents` screen is the response console: a served **blast-radius** preview for the
compromised identity, replacement-before-revoke execution with the resulting evidence, and a
**break-glass reconciliation** panel that folds offline-issued, quorum-approved bundles back
into the event log (`/api/v1/breakglass/reconcile`). The self-service approvals inbox at
`/approvals` blocks self-approval of your own request. See
[The web console](../web-console.md).

## Use it

Credential compromise is served through REST, CLI, and the console:

```bash
trstctl incidents executions execute -f incident.json
trstctl incidents executions list --identity_id 11111111-1111-1111-1111-111111111111
trstctl incidents executions get 22222222-2222-2222-2222-222222222222
```

```json
{
  "identity_id": "11111111-1111-1111-1111-111111111111",
  "reason": "private key export detected",
  "replacement_name": "payments-api-incident-replacement",
  "connector": "nginx",
  "target": "edge/prod/payments",
  "delivery_rollback_ref": "restore previous fullchain"
}
```

Break-glass reconciliation is API-served after recovery:

```bash
curl -X POST "https://trstctl.example.com/api/v1/breakglass/reconcile" \
  -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  -H "Idempotency-Key: incident-2026-06-25-bg-reconcile" \
  -H "Content-Type: application/json" \
  -d '{"bundles":[{"request_id":"bg-001","subject":"recovery.svc.example.test","cert_der":"...base64...","reason":"regional outage","approvals":["op1","op2"],"issued_at":"2026-06-25T17:00:00Z","signature":"...base64..."}]}'
```

The caller needs `certs:issue`; audit readers can then confirm the result with
`GET /api/v1/audit/events?type=breakglass.issued`.

Open a short-lived Postgres session:

```bash
curl -fksS -X POST "https://trstctl.example.com/api/v1/access/sessions" \
  -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  -H "Idempotency-Key: incident-2026-06-25-pg-readonly" \
  -H "Content-Type: application/json" \
  -d '{"target_type":"postgres","target_id":"pg-main","role":"readonly","reason":"production incident 42","method":"k8s_sat","payload_base64":"...","ttl_seconds":900}'
```

The response includes the session id, expiry, and a one-time Postgres DSN. Store it
only in the process that will use it. After `expires_at`, the background worker revokes
the generated database role and records `pam.session.expired`.

Open a short-lived SSH session:

```bash
ssh-keygen -t ed25519 -N "" -f /tmp/pam_id
curl -fksS -X POST "https://trstctl.example.com/api/v1/access/sessions" \
  -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  -H "Idempotency-Key: incident-2026-06-25-ssh" \
  -H "Content-Type: application/json" \
  -d '{"target_type":"ssh","target_id":"ssh-edge","role":"user","reason":"production incident 42","method":"k8s_sat","payload_base64":"...","ssh_public_key":"'"$(cat /tmp/pam_id.pub)"'","ssh_principal":"alice","ttl_seconds":900}'
```

Write the returned `ssh.certificate` value to `/tmp/pam_id-cert.pub` and connect with
the matching private key. The target host must trust the trstctl SSH CA through its
`TrustedUserCAKeys` configuration.

The lower-level library shapes remain useful for tests and future batch workflows:

```go
// Compromise library: preview the blast radius, then remediate idempotently
report := incident.Preview("cert:abc123")            // read-only: what's affected
_, err := incident.Remediate(ctx, "cert:abc123", "idem-key-xyz")

// JIT: request, then two distinct approvers (dual control) → auto-issue
approval.RequestIssuance(ctx, approval.RequestSpec{ID: "req-001",
    Resource: "cert:db-tls", Requester: "alice", RequiredApprovals: 2})
approval.Approve(ctx, "tenant1", "req-001", "bob")
approval.Approve(ctx, "tenant1", "req-001", "carol")  // quorum met → issues
```

Blast-radius preview reads the same [credential graph](graph-query-ai.md) you can query
directly; incident execution also appears in `/incidents` in the console. JIT
notifications use the [notification integrations](policy-and-governance.md).

## Pitfalls & limits

- **Serving status:** credential-compromise execution (F31) is served through
  `/api/v1/incidents/executions`, `trstctl incidents executions *`, and `/incidents`.
  JIT issuance is served. Break-glass reconciliation is served at
  `/api/v1/breakglass/reconcile`, while online emergency issuance and fleet reissue
  still expose their current library/operator limits until their own served surfaces
  land.
- **Order matters in remediation.** The reissue-before-revoke ordering is deliberate;
  don't shortcut it, or you risk an outage mid-incident.
- **JIT needs real approvers configured** and a notifier wired, or requests will sit in
  `awaiting-approval` until they expire.
- **PAM sessions need configured targets and attestors.** Postgres targets need an
  administrative DSN that can create and drop scoped roles. SSH targets need hosts that
  trust the trstctl SSH CA; trstctl does not weaken host `sshd` trust on your behalf.
- **Break-glass is a last resort.** It trades the control plane's guarantees for offline
  availability; reconcile the bundles promptly so the audit log is complete.

## Reference

- **Compromise:** `/api/v1/incidents/executions`, `incident.execution.recorded`,
  `Workflow.Preview`, `Workflow.Remediate` (replacement→deploy→revoke).
- **Fleet:** `Fleet.ReissueFleet(issuerID, runID)` — staged, health-checked, resumable.
- **JIT:** `RequestIssuance`, `Approve`, `Deny`; default `RequiredApprovals: 2`,
  self-approval blocked.
- **PAM-lite:** `/api/v1/access/sessions`; Postgres scoped login roles; OpenSSH user
  certificates; `pam.session.started`, `pam.session.expired`.
- **Break-glass:** `IssueOffline` (offline quorum ceremony), `Verify`,
  `POST /api/v1/breakglass/reconcile`.
- **Events:** `incident.*`, `fleet.*`, `approval.*`, `pam.session.*`,
  `breakglass.issued`.

## See also

[Graph, query & AI](graph-query-ai.md) (blast radius) ·
[Issuance & certificate authorities](issuance-and-cas.md) (revocation, CA rotation) ·
[Policy & governance](policy-and-governance.md) (approver policy, notifications) ·
[Incident-response runbook](../runbooks/incident-response.md) ·
glossary: [revocation](../glossary.md), [rotation](../glossary.md), [CA](../glossary.md)

**Covers:** F31, F32, F33, F34
