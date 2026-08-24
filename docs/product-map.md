# Product map: Home plus five workspaces

This page is for anyone opening trstctl for the first time. It gives you the
smallest useful mental model before the certificate, secret, workload, or
signing details appear.

**Outcome:** you will know where a task belongs, what each status means, and where
to look when evidence is missing. **Prerequisite:** none. This page changes no
system state.

## The 30-second explanation

A **non-human identity (NHI)** is the identity a machine uses to prove who it is.
Its proof may be an X.509 certificate, SSH certificate, secret, API key, token, or
SPIFFE workload identity. **Certificate lifecycle management (CLM)** is the part
that discovers, issues, deploys, renews, revokes, and retires certificates.

trstctl keeps those credential types in one control plane because an incident does
not respect product boundaries. One leaked build key can affect a certificate, a
deployment secret, and several workloads. The console separates daily work into
five focused workspaces, while Home, ownership, alerts, risk, and audit connect the
whole estate.

```text
                                 Home
          what needs attention, by when, who owns it, what to do next
                                   │
     ┌──────────────┬──────────────┼────────────┬──────────────┐
     │              │              │            │              │
 Certificates   Machines &      Secrets &    Software      Trust
    (CLM)       workloads        access       signing     operations
     └──────────────┴──────────────┼────────────┴──────────────┘
                                   │
             one identity graph · one event history · one audit trail
```

The workspaces are views over shared evidence. They are not separate products,
databases, signers, or policy systems.

## Start with Home

Home answers six questions about each urgent item:

1. What needs attention?
2. Which workspace owns the work?
3. What happens if nobody acts?
4. When is the deadline?
5. Is automation proven, and who is accountable?
6. What is the safest next action?

Home also gives you one health door into every workspace. A zero means the served
check returned zero. **Unavailable** or **unknown** means trstctl could not prove a
number; it does not mean zero or healthy.

## Pick the workspace by question

### Certificate Lifecycle — `/certificates`

**Question:** Which certificates need attention, and is renewal safe?

**Owns:** certificate inventory, expiry, renewal, deployment receipts, certificate
authorities (CAs), profiles, ACME/EST/SCEP/CMP enrollment, and revocation.

### Machine & Workload Trust — `/workloads`

**Question:** Which machines can prove who they are, and what needs repair?

**Owns:** SPIFFE identities, workloads, machine credentials, SSH trust, attestation,
agents, and stale-agent work.

### Secrets & Access — `/secrets`

**Question:** Which secrets need rotation, repair, or access review?

**Owns:** stored and dynamic secrets, leases, sharing, synchronization, repository
scanning, delivery, and access evidence.

### Software Trust — `/codesign`

**Question:** Can we prove what was signed, by whom, and with a healthy key?

**Owns:** code-signing operations, approvals, timestamps, verification outcomes,
and signing-custody evidence the running build serves.

### Trust Operations — `/trust-operations`

**Question:** What cross-product risk, incident, ownership, alert, or system work
needs attention?

**Owns:** risk, discovery, graph, incidents, ownership, Alert Center, policies,
approvals, audit, connectors, queues, privacy, and administration.

Routes from older console versions remain stable. Opening a deep link selects its
current workspace automatically. The complete route-to-workspace map is in
[The web console](web-console.md).

## Pick the shortest path for your role

### First-time evaluator

1. Follow [Getting started](getting-started.md) for a blank installation and first
   certificate, or use the [demo browser walkthrough](demo-click-through.html) for
   populated read-only evidence.
2. Open Home and read the highest-priority row from left to right.
3. Open each workspace health door. Confirm that missing evidence says unavailable
   or unknown instead of healthy.
4. Read [Current limitations](limitations.md) before treating any capability as
   deployment-ready for your environment.

**Success proof:** the health endpoint returns `{"status":"ok"}`, the browser signs
in through local single sign-on (SSO), and the UI shows served blank or demo data.
If it fails, start with [Troubleshooting](troubleshooting.md).

### Daily operator

Start on Home. Open the workspace named on the top row, inspect the consequence and
current owner, then review the exact evidence before changing the credential. Use
[the operator journey index](#common-jobs) when the task crosses workspaces.

### On-call responder

Keep [Respond to a compromise](journeys/respond-to-compromise.md) and the
[incident-response runbook](runbooks/incident-response.md) open. Preserve evidence,
scope the blast radius, replace before revoke when availability requires it, and
verify delivery after the change.

### Auditor

Start with [Audit and compliance](compliance.md), then inspect the
[architecture invariants](design/architecture-invariants.md),
[key-custody boundary](custody.md), [privacy data catalog](privacy-data-catalog.md),
and [current limitations](limitations.md). A committed control description is not
the same thing as an independent audit receipt.

### API and CLI integrator

Follow [Build on the API, CLI, and SDKs](journeys/build-on-the-api.md). Read the
served OpenAPI 3.1 document first, use a stable `Idempotency-Key` for every retryable
mutation, and test against a non-production tenant.

## Common jobs

| I need to… | Start here | Proof before I stop |
| --- | --- | --- |
| prevent an expiry outage | [Automate TLS across your fleet](journeys/automate-fleet-tls.md) | renewed certificate, deployment receipt, endpoint verification, and alert history agree |
| give a Kubernetes workload an identity | [Kubernetes workload identity](journeys/kubernetes-workload-identity.md) | attestation, short-lived identity, trust bundle, and workload readback agree |
| rotate an application secret | [Manage application secrets](journeys/manage-secrets.md) | new version delivered, consumer verified, old version retired, and audit event present |
| establish SSH trust | [SSH access at scale](journeys/ssh-at-scale.md) | host/user trust installed, bounded certificate issued, revocation path tested |
| contain a leaked credential | [Respond to a compromise](journeys/respond-to-compromise.md) | blast radius saved, replacement verified, compromised credential revoked, evidence sealed |
| onboard a team | [Onboard a team as a tenant](journeys/onboard-a-team.md) | tenant isolation, roles, ownership, routes, and audit access proven |
| prepare production operations | [Run in production](journeys/run-in-production.md) | external data stores, TLS, backup/restore, monitoring, capacity, rollback, and support path rehearsed |

## Read status words literally

| Status | Meaning | What it does **not** mean |
| --- | --- | --- |
| **Needs attention** | Current served evidence found a specific deadline, failure, or policy concern. | Every possible system was scanned. |
| **Healthy** | The named check ran and passed for the evidence in scope. | The whole estate is risk-free. |
| **Unknown** | The required evidence is missing or cannot support a conclusion. | Healthy or zero. |
| **Unavailable** | The UI could not read the named served source. | No records exist. |
| **Not configured** | An optional integration or rule has no active configuration. | The integration was tested and passed. |

## One control plane, shared safety rails

All workspaces use the same tenant boundary, append-only event history, audit
projection, policy engine, ownership model, Alert Center, identity graph, and
isolated signing process. Every mutation needs an idempotency key so a retry does
not repeat the operation. Every external effect is dispatched through the outbox
so a crash cannot silently lose the intent. See
[Architecture invariants](design/architecture-invariants.md) for the exact rules
and [Current limitations](limitations.md) for what this build does not yet prove.

Next: [install and issue your first certificate](getting-started.md), or
[tour the seeded demo](demo-click-through.html).
