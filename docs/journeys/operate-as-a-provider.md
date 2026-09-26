# Operate as a managed-service provider

<!-- trstctl:journey-census:start -->
!!! success "Served path — wiring census 81/81"

    The Definition-of-Done census reports **81/81 required capabilities served**: **12 of 81 census rows launch the shipped binary** and **69 of 81 are proved through the production-assembled handler**.
    Production-assembled means production `buildRunDeps` output driving the assembled `Server.Handler` in-process, with a hand-built `Deps` rejected; only the process launch differs.
    This journey uses no separately proof-gated capability row; it stays on core served surfaces.
    Core surfaces guarded by route and journey tests: `provider_plane`, `license_verification`, `tenant_rls`, `audit_export`.
    This badge is generated from `wiring-census.json`; `make journey-census-check` fails closed if the census or this page drifts.
<!-- trstctl:journey-census:end -->

## Goal

You run trstctl for several customers and want to manage them from one provider
plane without ever letting one customer's operator, data, or issuer reach another
customer. At the end of this journey you hold a licensed deployment, a provider
operator who signed in through your identity provider, two customer tenants that
only delegated operators can touch, one customer-scoped certificate lifecycle with
its metering evidence, and proof that the plane refuses what it must refuse. This
is for the operations lead of an MSP, an internal platform team selling a hosted
service to business units, or an evaluator checking those claims.

## Before you start

- An Enterprise Provider license from the vendor, installed the way
  [Plan and license](../editions.md) describes: a `0600` file supplied to both
  the control plane and the isolated signer with its bound deployment ID and
  environment. The provider plane is absent from an unlicensed build. After
  license expiry, a 30-day grace period preserves full functionality; afterward commercial
  features become read-only.
- A provider-operator identity source pinned offline
  ([configuration](../configuration.md), `TRSTCTL_PROVIDER_OIDC_*` or the SAML
  service provider). Operators are identified by your identity provider; the
  plane maps a signed role claim to *provider admin* or *provider operator* and
  requires a signed MFA proof for every mutation.
- The partner lab ships both in its licensed profile
  (`deploy/demo/lab/README.md`), with a local identity provider whose operator
  sign-in page is `http://127.0.0.1:19081/provider/sign-in`.

## Steps

### 1. Confirm the entitlement

Open **Plan and license** (`/admin/editions`). The opening card must read
*Provider* with an *Active* state, and **Signature verification** must show the
offline signature verified against the vendor key and the deployment binding your
operator configured. Community means no Provider entitlement is active; check
the license configuration on both processes. An invalid signature or deployment
binding fails startup. Grace retains full functionality for 30 days after expiry.
Read-only refuses mutations while retaining delegated reads.

### 2. Sign in as a provider operator

Open the console's **Provider** page (`/provider`). It offers the sign-in methods
your deployment pinned: SAML redirects to your identity provider; OIDC accepts the
bearer your identity provider issued to the operator (the lab's local provider shows
it once on its sign-in page). The token is held in memory only. Signing out clears the Provider query cache, so the next operator cannot inherit customer or workforce records. A refused customer action preserves the current sign-in and form so you can fix delegation or MFA and retry; an expired or invalid credential returns to sign-in with a recovery message and an empty token field. Use a fresh operator token or SAML when offered. If sign-in is still refused, ask your Provider administrator to check your access. The message does not expose credential or directory details; successful sign-in clears it, and intentional sign-out does not show it. `GET
/provider/v1/auth/session` answers who you are and which role and MFA state the
plane derived from the signed claims. It also reports the current effective
controls from the license, role, MFA, customer delegation, and attached services.
The console hides actions that are not allowed, never treats a suspend grant as an
offboard grant, and shows quotas as a read-only summary unless quota changes are
allowed. Missing or unreadable authority leaves controls unavailable; **Check
again** retries that read without discarding a valid sign-in. The server repeats
its checks for every action, even when the button was available a moment ago.

### 3. Bootstrap delegation once

Authority over customers is never granted through the API by someone who does not
already hold it. On the control-plane host, mint the first grants with the local
command and a stable idempotency key, naming each customer by the slug you will
provision in the next step (the command prints the tenant id it derived; a grant
over an existing tenant id also works):

```bash
trstctl provider-grant -operator op-1 -customer acme-robotics \
  -operations read,provision,suspend,resume -granted-by platform-admin \
  -idempotency-key acme-robotics-op-1-v1
```

An identical retry returns the same authority event; reusing the key with a
different grant is refused. Every grant names one customer and the operations it
covers; there is no wildcard customer. Pass the subject your identity provider
signs (`sub`). When Provider SCIM is enabled, provision that employee first with
the signed subject as their SCIM `externalId`. The command resolves the subject
to the directory operator ID used by authentication and prints that effective ID.
It also accepts the SCIM `userName` or canonical directory ID. Missing or inactive
employees cannot receive new grants; an unreadable directory fails closed.
Without SCIM, an unknown subject can still receive the initial bootstrap grant.

Use `-revoke` with the same operator reference, customer and operations and a new
idempotency key to remove authority. Revocation also works for an inactive
directory identity. After correcting an older subject-based grant, use a new key
and check `/provider/v1/auth/session` with that employee's token to confirm the
intended customer authority.

Retrying an old grant after revocation returns its original event without
restoring access. Restoring access requires an explicitly authorized new grant
with a new idempotency key. The same ordering applies to operator deprovisioning
and customer suspension: replay cannot undo a later decision. After a crash,
the control plane recovers missing authority updates from retained events in
sequence and commits the recovered state together with its completion records.
If that history is unavailable, recovery fails rather than inventing authority.

### 4. Provision two customers

From the Provider page (or `POST /provider/v1/tenants` with an `Idempotency-Key`),
provision two customers with distinct slugs. A refused request stays bound to
its `Idempotency-Key` (the replay carries `Idempotent-Replayed: true`), so after
fixing a delegation retry with a new key. Each becomes an isolated tenant with
its own row-level-security boundary, quota, health view, ownership, delegation
list, issuer selection, and alert routing. `GET /provider/v1/tenants` returns
only the customers delegated to the signed-in operator; the full roster is the
provider's commercial information and is never listed to an operator who is not
delegated to all of it.

### 5. Run one customer-scoped lifecycle

Acting for one customer, issue a certificate for a real endpoint, deploy it
through that customer's connector, verify it on the wire, and renew it: the same
journey as [Keep your existing CA](preserve-existing-ca.md), inside the customer's
boundary. The customer's endpoint is served by the customer's own agent, enrolled
with a token minted in the customer tenant, never by the provider's agent; in the
partner lab that is the customer listener on port 10449
(`deploy/demo/lab/README.md`). Then pull the customer's metering (`/provider/v1/tenants/{id}/quota` and
the provider evidence endpoints) as invoice evidence; the verification keys for
that evidence are published at `/provider/v1/evidence/verification-keys`.

Changing the invoice customer or period clears the displayed health and evidence.
Pull the newly selected period before downloading it; a response from an earlier
selection cannot populate the new customer or mark its signature as verified.

### Pause and resume a customer

An administrator with that customer's `suspend` grant can choose **Suspend** in
Customers. To restore a suspended customer, an administrator needs the separate
`resume` grant and chooses **Resume**, then confirms. Refreshing the customer row
shows the resulting state; Recent activity records `provider.tenant_resume` with
the customer and operator. A suspend grant alone cannot reactivate a customer,
and an offboarded customer cannot be resumed.

Vault/OpenBao-compatible credential routes enforce the same customer restriction,
including secret reads, PKI issuance, transit operations and cached mutation
responses. They return HTTP 403 for a missing or restricted customer and HTTP 503
when current service authority cannot be checked, using the Vault `errors` array.
An active mutation holds the customer's lifecycle lock through its response, so a
conflicting suspension or offboarding request must retry after that work finishes.

Removing the Provider license or starting a core-only build does not clear a
persisted customer restriction. Suspended customers, unfinished offboarding,
and legacy offboarded customers remain denied. Restore Provider administration
and use the authorized Resume or offboarding recovery flow; do not delete the
registry row to regain access. Core-only read-model rebuild preserves this
registry, and disaster recovery must restore it from the full PostgreSQL backup.

Automation uses `POST /provider/v1/tenants/{id}/resume` with its own
`Idempotency-Key`. A successful request returns204; its identical retry replays
that result without another state change. A new request for a customer that is
not suspended returns409 `customer_state_conflict` after authorization.

### Offboard a customer

Offboarding deletes the customer's PostgreSQL read state and revokes its Provider
delegations. It is not a dry run and cannot be undone with Resume. The append-only
event log and audit archives follow their own retention policy; see the
[Tenant offboarding boundary](../limitations.md#tenant-offboarding-boundary).

Before deleting a customer, export the history and metering evidence you need,
complete the intended certificate revocation and workload retirement, and verify
the external results. Offboarding does not revoke certificates at upstream CAs
or remove credentials already installed on external workloads. Complete those
lifecycle actions while the customer still has service access.

An administrator needs current MFA, a writable Provider entitlement, and that
customer's separate `offboard` delegation. Emergency-access approvals do not authorize deletion.
A `read`, `suspend`, or `break-glass` grant alone is insufficient.

In **Customers**, choose **Offboard** and read the confirmation before accepting.
Accepting submits the deletion immediately; the dialog is a confirmation, not a
server-generated preview or an additional approval workflow. Automation sends
`POST /provider/v1/tenants/{id}/offboard` with `{}` and an `Idempotency-Key`.
Keep that key and the request reference for recovery. HTTP 204 records completed
deletion; in **Recent activity**, check for **Deletion verified**. If work is still
running or the response is lost, follow the recovery steps below instead of
assuming that the customer was deleted.

### Recover an interrupted offboarding request

A suspension or offboard attempt can return HTTP 503 `customer_work_in_progress` while
an admitted API mutation or delivery is still running. That refusal preserves
the customer's current state. Wait for the work to finish, respect the
`Retry-After` response header, and retry with the same `Idempotency-Key`.
A busy response does not mean suspension or deletion has been accepted.

If the lifecycle request loses its database connection, a retained suspension
event does not prove that the customer is suspended. The final state change and
its replay both exclude admitted work and check unresolved remote attempts.
Retry the same request after work finishes; do not treat a missing response or a
retained event alone as successful suspension or erasure.

Control-plane deliveries retain a separate durable token for each receiver
invocation. The refusal identifies the outbox row, destination and unresolved
attempt count. The original invocation clears its token only after completed
delivery or a proven refusal before receiver I/O. Losing the worker process,
database session, response or lease does not prove that the remote system stopped;
neither does a successful later retry. Retention and backup/restore preserve that
uncertainty. Older unfinished deliveries and multi-attempt successes without
per-attempt evidence remain unknown after upgrade. Do not remove these records
or treat repeated HTTP503 responses as permission to force deletion. An unknown
remote outcome needs receiver-specific reconciliation; generic retry alone cannot
establish it.

A successful control-plane connector deployment records the completing invocation
in its delivery event. Recovery can replay that event to release the same hold
without sending the deployment again. The receipt and hold release commit together;
a failed projection leaves the hold in place. Earlier uncertain invocations and
historical receipts without this evidence still require reconciliation.

ServiceNow payload validation and missing local environment credentials fail
before its HTTP request starts. These failures retain the normal queue retry
count and safe error class while releasing only that invocation's lifecycle
hold. A transport error or unsuccessful receiver response remains unresolved.

Work already handed to an agent remains in progress until each issued attempt
has a verified terminal receipt. A lost connection, expired lease, reclaimed job,
or successful later retry cannot prove that an earlier executor has stopped.
Queue retention preserves unresolved attempts. Restore reporting from the agent
and retain the original job and attempt identities; do not delete queue or
receipt rows to force suspension or erasure. The claim transaction retains each
attempt's original recipient. A valid late terminal report from that recipient
records completion of that executor without changing a newer claim, applying
stale target observations, or granting more access. The receipt is audited as
`agent.job.receipt.reconciled`; its acknowledgement does not mean the current job or
target state was updated. Upgrade preserves known holders, including expired
leases not yet reclaimed, but cannot infer recipients already lost from legacy
history. If the original binding or report is unavailable, remote completion
remains unresolved and the lifecycle request stays refused.

For a legacy customer already marked suspended or offboarded while work remained,
an agent with a valid, unrevoked certificate for the retained tenant registration
can submit only its original signed terminal receipt. Work claims, lease
extensions, credential access and live target updates stay refused. Deleted
tenants, revoked agents and unavailable service authority cannot use this path;
receipt recovery does not restore customer access.

ACME accounts, orders, authorizations and certificate-serving state belong to one
retained tenant registration. Suspension refuses the complete request, including
account and order creation, until service resumes. After erasure, registering a
new customer with the same tenant UUID does not restore the old ACME accounts or
orders. Clients must register again under the new customer's configured policy.
Restart recovery and the operator's validation/renewal views use only the current
registration. An old in-flight request cannot append ACME state or enter issuance
or revocation using the replacement registration's authority. Historical events
remain available under the applicable audit and privacy policy.

Startup recovery may reconstruct a suspended customer's already-recorded queue
intents so a restart does not lose work needed after an authorized resume. The
workers still refuse delivery while service is suspended. Recovery skips erased
customers and intents from an older registration of the same tenant UUID. If a
lifecycle operation is currently exclusive, recovery stops without advancing past
that event; retry startup after the operation finishes. Recovering an intent is
not evidence that its external action ran.

The agent saves each terminal observation in encrypted `pending-reports` state
beside its identity key before sending it. Preserve that directory and its sealing
key with the agent identity. It permits only one process to use the directory and
recovers the pending report before claiming more work, including after restart.
Disabling job claiming still permits reporting an existing result. A refusal or
unavailable control plane retains the observation and blocks further claims.
Corrupt state, a missing sealing key, or a changed server trust, agent identity or
tenant registration causes an explicit refusal; do not delete the state to bypass it.

A late report receives a receipt acknowledgement, not a renewed claim. The agent
can clear its saved report, but this does not authorize execution or rollback.
The recorded terminal facts cannot be overwritten by a conflicting outcome,
evidence digest, detail digest, or custody statement for the same attempt. A
fresh signature over the same facts remains retryable after a reporting outage.
The first reconciled event has a stable ID for that tenant, job and attempt.
Recovery checks retained history even after the broker's duplicate window has
expired, and restores the original statement, signature and signer together if
the database write failed. A conflicting report is refused and audited as
`agent.job.receipt.conflict`; a retry does not create another completion event.
These signed records cannot be rewritten without invalidating their evidence.
Subject erasure that would alter the signed payload is explicitly refused.

Each reporting window permits at most six sends within 30 seconds after temporary
transport, timeout or capacity failures, with a 10-second limit per RPC and
jittered backoff. Those retries send identical signed bytes. A later window uses
the current authenticated identity and signing time to attest the original job,
attempt, outcome, evidence and custody; it does not rerun the external action or
weaken the server's signed-receipt time window. Normal certificate renewal retains
the registration binding. Legacy certificates without that binding retain only
their exact leaf identity and cannot silently recover across renewal.

This protects a successfully persisted terminal observation. A crash between the
external action and that local write, or loss of the agent disk, can still leave
completion unknown; the remote-work hold remains. Windows process restart and
power-loss durability still require native qualification. A stored report or an
accepted late receipt does not establish the target's current health.

For a registered customer, core reserves the exact deletion command before the
Provider request is appended. This durable receiver binds the registration and
original actor; it denies service even without the Provider attachment. It does
not itself erase customer data. If the subsequent append or projection fails,
service may already be denied while the Provider roster still shows its earlier
state. Retry the original offboard command with its `Idempotency-Key`, signed in
as the original operator with current authorization. Do not remove the core
receiver or use Resume to cancel a prepared deletion.

A lost response does not prove that deletion finished. In Recent activity,
**Continue offboarding** resumes the original request after you sign in again,
even if the customer has already left the roster. It does not authorize deletion
of a later customer that reuses the same ID.

The original operator's deletion request and outcome remain visible after the
operation revokes customer grants. This exception exposes only that operator's
own operation evidence; it does not restore access to customer data or another
operator's undelegated activity. Continuation still requires current
authentication, MFA, an administrator role and a writable Provider entitlement.
The server reports whether continuation is currently allowed.

For API recovery, take `request_event_id` from the request's activity item and
send `POST /provider/v1/tenants/{id}/offboard` with
`{"request_event_id":"REQUEST_EVENT_ID"}` and an `Idempotency-Key` for this HTTP
attempt. Retrying the same attempt uses that key again. A newly authenticated
attempt may use a new key while retaining the same request reference. The
reference is not a credential: a different operator, customer or event type is
refused. An empty object starts a new authorization rather than a continuation.

`offboard_state` distinguishes `pending`, `failed` and `completed`.
`provider.tenant_erasure.completed` is recorded only after the deletion command
verifies completion; the earlier request or erase event alone is insufficient.
The console then shows **Deletion verified**. A failed request needs review and
a separately authorized new offboard action. Recent activity defaults to 100 items
and accepts `limit` up to 250; retain the request reference for older operations.
No operator credential is saved in browser storage for this recovery.

An older retained registration can still authorize offboarding. If a customer's
database row cannot be bound to its retained registration, the server returns409
`customer_state_conflict` before starting deletion and preserves customer data.
Restore and verify the actual registration history and its read model before a
new attempt. Rebuilding the read model can recover a lost registration position
when the original event is retained; it cannot replace missing source history.
Do not create a new registration merely to bypass this refusal.

### Request and approve emergency access

Emergency access requires a requester and two distinct approvers. All three
must authenticate with MFA and hold the customer's `break-glass` operation;
ordinary `read` authority is insufficient. The requester cannot approve their
own request. The Provider console does not yet offer this workflow; use the
Provider API with each person's own short-lived operator credential.

The requester sends `POST /provider/v1/breakglass` with
`{"tenant_id":"CUSTOMER_ID","reason":"Incident diagnosis","ttl":"15m"}`.
Each approver sends `POST /provider/v1/breakglass/{grant_id}/consent` with
`{"tenant_id":"CUSTOMER_ID","approve":true}`. Do not supply a `subject`:
the server derives the approver from the verified identity. Each mutation needs
its own `Idempotency-Key`. Approval and denial both require current MFA,
customer delegation, and a writable license. `approve:false` denies the request
and stops it from being used, even after the first approval.

After both approvals, only the requester can send
`POST /provider/v1/breakglass/{grant_id}/results` to obtain the customer snapshot.
The server rechecks the requester's MFA, delegation, and grant expiry, and
records access before returning customer data. A single approval opens no access.
An identical successful retry returns the saved snapshot only while the requester
still has access and the grant remains active; it does not read a new snapshot or
record another use. A retry after access is revoked or the grant expires returns
403. A recorded refusal stays bound to its key; after fixing a refused request,
use a new idempotency key. These emergency approvals do not grant lifecycle
operations such as suspend or offboard.

### 6. Prove the refusals

- Revoke or let a delegation expire, then repeat a read or mutation for that
  customer: the plane answers *forbidden* and the audit trail records the refusal
  before any store write.
- Name the other customer's tenant from an operator not delegated to it: the
  answer is the same refusal with no hint that the tenant exists.
- An operator whose grant lacks `offboard` cannot offboard, including one who
  holds emergency-access approval. The server rechecks current lifecycle
  authority before starting a new deletion. Do not use an authorized offboard
  request as a harmless permission probe: it deletes the customer.
- A license bound to a different deployment ID fails startup. An expired license
  retains its existing authority during the 30-day grace period and drops the plane to read-only afterward; neither state
  widens access.

## What you have now

A licensed provider deployment with identity-provider-backed operators, customers
that only delegated operators can touch, one proven customer lifecycle with
metering evidence, and audited refusals at every boundary. Suspending, resuming,
and offboarding follow the same delegation rules; SCIM provisioning of your
workforce is available at `/provider/scim/v2` when enabled.

## See also

- [Plan and license](../editions.md) — entitlement, the vendor key, delegation rules
- [Configuration](../configuration.md) — `TRSTCTL_PROVIDER_*` settings
- [Onboard a team as a tenant](onboard-a-team.md) — what each customer tenant gets
- [Current limitations](../limitations.md)
