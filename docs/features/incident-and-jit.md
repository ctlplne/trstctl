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

This is deliberately stricter than probectl's guarded-remediation pattern. probectl
proposes and records remediation; trstctl's remediation actually executes issue,
deploy, and revoke work after a human operator trigger. The served routes are part of Core and require no commercial license. All
deployments require RBAC (`incidents:write` and `certs:issue` for replacement
issuance), policy approval where configured, and idempotency before anything mutates.

The same incident surface can open a **ServiceNow / ITSM workflow** after the
operator has enough evidence. `POST /api/v1/itsm/servicenow/tickets` records an
immutable `itsm.ticket.requested` event, then enqueues `itsm.servicenow` in the
outbox in the same tenant-scoped transaction. The outbox worker resolves
`token_ref` only when it is ready to call the ServiceNow Table API; the token value is
never stored in the event log, outbox payload, UI, or audit response. The request is
idempotent like every other mutation: replaying the same `Idempotency-Key` returns the
same queued receipt instead of creating a second ticket request.
The `instance_url`, `token_ref`, and `allow_private_endpoint` values must match an
operator-approved ServiceNow binding in configuration; the route fails closed rather
than sending a configured token to a caller-chosen URL. Private ServiceNow bindings
also require `private_egress_cidrs` in operator configuration and the caller must
hold the dedicated `egress:private` permission.

Detection is served on the Discovery side, not hidden inside remediation. A
`credential_compromise` source accepts metadata-only ITDR, honeytoken,
secret-scanner, IdP, SaaS, or threat-intel signals and emits
`compromised_credential` findings tagged `CAP-ITDR-02` and OWASP NHI2. Those
findings carry credential references and evidence refs only; the raw stolen token
or secret body never enters the control plane. Operators can use those findings as
the evidence that justifies the incident execution path above.

OAuth consent abuse is served through the same Discovery spine. An `oauth_grant`
source still emits ordinary `oauth_grant` inventory findings for CAP-OAUTH-01, and
it emits an additional `oauth_grant_abuse` finding tagged `CAP-ITDR-03` only when
the grant export has concrete abuse evidence such as provider threat signals,
dangerous wildcard / `.default` scopes, `offline_access` plus high-privilege admin
consent, explicitly unverified publisher evidence, ownerless privileged third-party
admin consent, or suspicious redirect URIs. The finding stores evidence references
and source event ids, not OAuth client secrets, access tokens, or refresh tokens.

Supported tables are `incident`, `change_request`, and `sc_task`. Production
endpoints should be HTTPS; `allow_private_endpoint` is accepted only when the
configured binding explicitly permits that private/eval endpoint and grants the
destination CIDR.

For a broader response packet, `POST
/api/v1/incidents/response-integrations/dispatch` records
`response.integration.dispatched` and fans out one tenant-scoped outbox row per
destination: Splunk HEC (`response.splunk`), Jira issue creation
(`response.jira`), Slack/operator notification (`notification.response`), and
ServiceNow Table API (`itsm.servicenow`). Each destination carries only endpoint
metadata plus `token_ref`; token bytes are resolved by the worker at delivery time
and wiped after the outbound request. ServiceNow destinations reuse the same
operator-approved binding check as direct ITSM ticket creation. Splunk and Jira
`token_ref` values must be listed by the operator in
`TRSTCTL_OUTBOUND_ENV_CREDENTIAL_REFS`; their private destinations additionally
require both `egress:private` and a destination CIDR grant on the dispatch request.
This is a served dispatch and evidence path, not a promise that trstctl manages the customer's Splunk
correlation searches, Jira automation rules, Slack app installation, or bidirectional
ServiceNow state sync.

### Fleet re-issuance for CA compromise (F32)

If an X.509 CA is compromised, every active identity issued by its catalog entry must be
replaced, and every exact trust consumer must be visible before the first estate effect.
trstctl freezes the compromised issuer, signer-backed replacement authority, exact
certificate/SPKI `TRUSTS` stores and hosts, ordered cohorts, exact enrolled agents,
deployment-target revisions, predecessor certificate/revocation authority, and rollback
paths into one H2 plan. Subject-only trust matches remain visible as candidates but never
authorize work. The plan's digest and H3 projection commit before H2 can enqueue its first
agent action.

Each cohort installs the replacement authority, waits for the host agent's lease-bound
signed trust readback, mints a successor from a host-generated CSR, deploys it, and waits
for the signed live-listener transcript. Only that proof releases revocation of that
member's exact predecessor; every revocation receipt must land before the next cohort
starts. A failed trust/live gate automatically restores only the current unrevoked cohort
and removes its replacement trust. Completed earlier cohorts are not rolled back after
their predecessors have been revoked. Every action is idempotent, journaled in the same
transaction as the H2 event projection, and executed in the bounded fleet lane.

**Status:** compromised-issuer fleet re-issuance is served through
`POST /api/v1/incidents/fleet-reissuance-runs`, with list/get evidence at
`GET /api/v1/incidents/fleet-reissuance-runs{,/{id}}`, pause/resume/rollback evidence
at `POST /api/v1/incidents/fleet-reissuance-runs/{id}/{pause,resume,rollback}`, and a
signed evidence export at
`GET /api/v1/incidents/fleet-reissuance-runs/{id}/evidence`. Start accepts
`issuer_id`, `replacement_authority_id`, `mode`, `reason`, `rollback_ref`, and ordered
`cohorts`; each member supplies `identity_id`, the exact enrolled `agent_id`, and a
public `trust_anchor_path`. `live` is the production response. `game_day` additionally
requires `incidents:game-day`, and H2 refuses any member whose frozen owner/target
environment is not explicitly non-production. It is therefore a safety boundary, not a
display label. Terminal success or rollback is mirrored to
`incident.fleet_reissuance.recorded` only with a compact-JWS audit export that verifies
offline. Pause/resume and restart retain the same H2 cursor and immutable bindings. The
legacy `POST /api/v1/incidents/executions` mutation now returns conflict with this H2
route as guidance; historical execution reads remain available. CLI parity is
`trstctl-cli incidents fleet-reissuance start|list|get|pause|resume|rollback|evidence`.

The `/incidents` console configures the same contract as a three-step journey; it
does not ask an operator to paste UUIDs or hand-write cohort JSON. First choose a
served X.509 issuer and active replacement authority, then build ordered waves
from the affected identity and enrolled-agent rosters. The final step names the
exact issuer, authority, mode, wave order, and identity-to-agent assignments
before start. An empty issuer, authority, agent, or affected-identity roster
blocks progress with a named prerequisite instead of guessing. The advanced
exact-request disclosure remains available for audit and API comparison, while
the primary path keeps the immutable-plan, canary-first, signed-gate, and
predecessor-after-proof safety order visible in plain language.

### Just-in-time issuance with approval (F33)

F33 has three related lanes, and the distinction matters. The ordinary self-service
certificate lane opens one seven-day request and requires one **different** principal
with `certs:issue` to approve it. The attested ephemeral lane is **dual-control** by
default (2 required, configurable for m-of-n), has a shorter approval window, and queues
its approver notification through the transactional outbox. The PAM lane opens a
short-lived database or SSH session instead of minting a general-purpose certificate.
All three block self-approval and keep the grant time-bounded.

On `/request`, the requester first reviews an exact, effect-free server preview bound to
the tenant owner, active profile version, requester, subject, and optional requester-held
CSR. Preview writes nothing, calls no signer or CA, and explains that submission opens a
request only. On `/approvals`, a different principal can review the subject, purpose,
owner, profile, decision expiry, immutable request ID, and audit link in one dialog.
Approve and deny take an `Idempotency-Key`; denial requires a reason and is terminal.
Approval still mints nothing: it reveals the separate prepare/issue/complete step. If
that step fails, the request remains approved and retries the same deterministic identity
and issuance key instead of minting a duplicate.

The generic operation-review surface keeps those domains separate: certificate
review requires `certs:issue`, secret review requires `secrets:write`, and managed-key
review requires `keys:approve`. List responses contain only the caller's authorized
domains and paginate with an opaque composite cursor. Approve and deny re-check the
request's exact kind, action, resource, and intent digest while the request row is
locked. A denial closes only the immutable request; it does not mutate the requested
resource.

For privileged-access management, the same JIT model opens short-lived sessions instead
of standing database or shell access. `POST /api/v1/access/sessions` verifies an
attestation, grants a scoped Postgres login role or signs an OpenSSH user certificate
for a configured SSH target, returns the one-time credential to the caller, and records a
tenant-scoped session row. The session expires automatically: Postgres roles are revoked
by the background expiry worker, and SSH access ends at the certificate `valid_before`
time. The event trail is filterable by `pam.session.started` and
`pam.session.expired`; credential material is not written into those events.

**Status:** the core identity approval gate is served through
`POST /api/v1/identities/{id}/approvals`. The self-service certificate portal is
served through `/request` plus `/approvals` and the
`/api/v1/issuance-requests{,/preview,/{id}/{approve,deny,cancel,prepare,complete}}`
family. It previews and submits a profile-bound `x509_certificate` request, denies
requester self-issue, blocks RA self-approval of privileged issue, rotate, or revoke
actions, accepts a distinct approval, then mints through the signer-backed issuance
outbox and records certificate inventory evidence. The direct review dialog and the
history panel are two views of the same event-projected request; failed issuance stays
visible with an explicit safe-retry action.
Ephemeral/JIT credential issuance is served when configured through `POST /api/v1/ephemeral` plus
`POST /api/v1/ephemeral/{id}/approvals`, where `{id}` is the genuine
`approval_request_id` and the body carries the same UUID as `request_id` plus its
matching `intent_digest`; PAM-lite sessions are served
through `POST /api/v1/access/sessions`, `GET /api/v1/access/sessions`, and
`GET /api/v1/access/sessions/{id}`. The ephemeral path verifies the attestation first,
writes the approval request and outbox notification intent in the same tenant
transaction, blocks requester self-approval, then mints a short-TTL credential only
after a distinct approver records approval. CLI parity is `trstctl-cli identities
approve issue|rotate|revoke`, `trstctl-cli ephemeral issue`, and `trstctl-cli
ephemeral approve`; PAM sessions use `trstctl-cli access sessions open`, `trstctl-cli
access sessions list`, and `trstctl-cli access sessions get`.

### Break-glass procedures (F34)

If the control plane is reachable during an incident, `POST /api/v1/breakglass/issue`
serves online emergency issuance gated by an **m-of-n operator quorum**. The caller
first sends the exact CSR/reason/TTL to
`POST /api/v1/breakglass/issue-ceremonies/preview`. This effect-free check opens no
ceremony, appends no event, records no idempotency key, calls no signer, and performs
no external request. It returns the request and CSR fingerprints, effective lifetime,
safe deployment-readiness checklist, configured threshold and roster count (never
operator names), exact execution effects, recovery steps, and verification steps.
The caller then opens the unchanged request as a ceremony at
`POST /api/v1/breakglass/issue-ceremonies`; distinct configured operators approve it
with their own authenticated tokens, and the execution body contains only the
ceremony id—not approver names. The server matches the roster to immutable
`ca.ceremony.approved` event actors in the same locked transaction, so sub-quorum,
cross-tenant, altered-request, and reused-ceremony attempts fail closed. The escrow
signing key is a persisted purpose-constrained handle into the separate, isolated
signing service, never caller-supplied key material in the API process. The result is a
**self-verifying signed bundle** — anyone can verify it offline (signature + chain to
the CA), and the served route reconciles it into the hash-chained audit log as
immutable `breakglass.issued` before responding. If the control plane was unreachable,
operators can still run the same quorum ceremony offline and later call
`POST /api/v1/breakglass/reconcile`, which verifies those bundles against
deployment-pinned break-glass verifier material and records the same audit event. A
bundle that fails verification stops the batch, so a forged emergency issuance can't be
silently absorbed.

The same configured authority supports ceremony-bound CA rotation at
`POST /api/v1/breakglass/rotate` and target-CA cross-signing at
`POST /api/v1/breakglass/cross-sign`. Rotation creates a fresh signer-held key,
preserves the predecessor policy lane, emits new-by-previous and previous-by-new
cross-certificates for overlap/rollback, and replays the active handle after restart.

### In the console

The `/incidents` screen is the response console: a served **blast-radius** preview for the
compromised identity, replacement-before-revoke execution with the resulting evidence,
automated remediation playbooks for revoke / rotate / NHI right-size, a
CAP-REM-02 owner self-remediation queue where bound owners can accept least-privilege
right-size recommendations without broad incident authority, a
SIEM/SOAR/chat/ITSM response-dispatch form for Splunk, Jira, Slack, and ServiceNow, a
ServiceNow ITSM ticket form that queues the Table API call through the outbox, and a
guided **emergency certificate access** workspace. That workspace collects a structured
request, shows the exact zero-effect server preview, reports deployment-owned signer and
quorum readiness without exposing the operator roster, opens the request-bound ceremony,
waits for independently authenticated approvals, executes only after quorum, and gives the
operator a verification checklist. Its advanced recovery panel folds offline-issued,
quorum-approved bundles back into the event log (`/api/v1/breakglass/reconcile`). The
self-service approvals inbox at
`/approvals` blocks self-approval of your own request. See
[The web console](../web-console.md).

## Use it

Credential compromise is served through REST, CLI, and the console:

`compromised-issuer.json` names the exact reviewed H2 plan; the API rejects a
caller-supplied subset when it does not equal the issuer's active identity denominator:

```json
{
  "issuer_id": "11111111-1111-4111-8111-111111111111",
  "replacement_authority_id": "22222222-2222-4222-8222-222222222222",
  "mode": "live",
  "reason": "intermediate signing key exposure",
  "rollback_ref": "restore the exact predecessor for the failed cohort",
  "cohorts": [
    {
      "id": "canary",
      "ordinal": 1,
      "members": [
        {
          "identity_id": "33333333-3333-4333-8333-333333333333",
          "agent_id": "44444444-4444-4444-8444-444444444444",
          "trust_anchor_path": "/etc/trstctl/trust/replacement-root.pem"
        }
      ]
    }
  ]
}
```

```bash
# This legacy mutation now refuses with H2 guidance; list/get still read history.
trstctl-cli incidents executions execute -f incident.json
trstctl-cli incidents fleet-reissuance start -f compromised-issuer.json
trstctl-cli incidents fleet-reissuance pause 33333333-3333-4333-8333-333333333333 -f pause.json
trstctl-cli incidents fleet-reissuance evidence 33333333-3333-4333-8333-333333333333
trstctl-cli incidents response-integrations dispatch -f response-dispatch.json
trstctl-cli itsm servicenow tickets create -f servicenow-ticket.json
trstctl-cli remediation playbooks
trstctl-cli remediation playbooks run nhi-right-size -f right-size.json
trstctl-cli remediation playbook-runs list --playbook_id nhi-right-size
trstctl-cli remediation owner-actions list
trstctl-cli remediation owner-actions accept right-size-aWRlbnRpdHkvMTEx -f accept-owner-action.json
trstctl-cli incidents executions list --identity_id 11111111-1111-1111-1111-111111111111
trstctl-cli incidents executions get 22222222-2222-2222-2222-222222222222
```

`right-size.json` names the identity whose usage-backed posture finding supplies the
allowed scope delta. The `connector` must match an operator
`connectors.right_size` binding, and `target` is the entitlement resource at that
provider:

```json
{
  "target_identity_id": "11111111-1111-1111-1111-111111111111",
  "reason": "remove the unused deployment grant",
  "connector": "least-privilege",
  "target": "payments-deployer",
  "remove_scopes": ["deploy:write"],
  "recommended_scopes": ["deploy:read"]
}
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

Dispatch the same incident response packet to Splunk, Jira, Slack, and ServiceNow:

```bash
trstctl-cli incidents response-integrations dispatch -f response-dispatch.json
```

`response-dispatch.json`:

```json
{
  "title": "Contain compromised payments credential",
  "summary": "Rotate, revoke, page responders, and open investigation.",
  "severity": "critical",
  "correlation_id": "incident-2026-06-25",
  "evidence_refs": ["incident/22222222-2222-2222-2222-222222222222"],
  "destinations": [
    {
      "id": "splunk",
      "provider": "splunk",
      "endpoint_url": "https://splunk.example.com/services/collector",
      "token_ref": "env:TRSTCTL_SPLUNK_TOKEN"
    },
    {
      "id": "jira",
      "provider": "jira",
      "endpoint_url": "https://jira.example.com",
      "project_key": "SEC",
      "issue_type": "Task",
      "token_ref": "env:TRSTCTL_JIRA_TOKEN"
    },
    { "id": "slack", "provider": "slack", "channel": "security-incidents" },
    {
      "id": "servicenow",
      "provider": "servicenow",
      "instance_url": "https://example.service-now.com",
      "table": "incident",
      "token_ref": "env:TRSTCTL_SERVICENOW_TOKEN"
    }
  ]
}
```

Queue a ServiceNow incident ticket from the same response surface:

```bash
export TRSTCTL_SERVICENOW_INSTANCE_URL=https://example.service-now.com
export TRSTCTL_SERVICENOW_TOKEN_REF=env:TRSTCTL_SERVICENOW_TOKEN
trstctl-cli itsm servicenow tickets create -f servicenow-ticket.json
```

`servicenow-ticket.json`:

```json
{
  "instance_url": "https://example.service-now.com",
  "table": "incident",
  "token_ref": "env:TRSTCTL_SERVICENOW_TOKEN",
  "short_description": "Rotate exposed TLS private key",
  "description": "trstctl incident response queued replacement-before-revoke remediation.",
  "category": "security",
  "urgency": "1",
  "impact": "2",
  "correlation_id": "incident-2026-06-25"
}
```

Equivalent REST call:

```bash
export TRSTCTL_CA_FILE=/etc/trstctl/pki/control-plane-ca.pem
curl -fsS --cacert "$TRSTCTL_CA_FILE" -X POST "https://trstctl.example.com/api/v1/itsm/servicenow/tickets" \
  -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  -H "Idempotency-Key: incident-2026-06-25-servicenow" \
  -H "Content-Type: application/json" \
  -d '{"instance_url":"https://example.service-now.com","table":"incident","token_ref":"env:TRSTCTL_SERVICENOW_TOKEN","short_description":"Rotate exposed TLS private key","description":"trstctl incident response queued replacement-before-revoke remediation.","category":"security","urgency":"1","impact":"2","correlation_id":"incident-2026-06-25"}'
```

The caller needs `incidents:write`. The returned receipt names the outbox row and
`idempotency_key`; the worker marks that row delivered only after ServiceNow accepts the
Table API request.

Online break-glass issue is API-served when the signer-backed break-glass issuer is
configured:

```bash
curl -fsS --cacert "$TRSTCTL_CA_FILE" -X POST "https://trstctl.example.com/api/v1/breakglass/issue-ceremonies/preview" \
  -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"request_id":"bg-001","subject":"recovery.svc.example.test","csr_der":"...base64-csr...","reason":"regional outage","ttl_seconds":900}'

curl -fsS --cacert "$TRSTCTL_CA_FILE" -X POST "https://trstctl.example.com/api/v1/breakglass/issue-ceremonies" \
  -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  -H "Idempotency-Key: incident-2026-06-25-bg-ceremony" \
  -H "Content-Type: application/json" \
  -d '{"request_id":"bg-001","subject":"recovery.svc.example.test","csr_der":"...base64-csr...","reason":"regional outage","ttl_seconds":900}'

# Each command uses a different configured operator's token.
trstctl-cli ca ceremonies approve <ceremony-id>
trstctl-cli ca ceremonies approve <ceremony-id>

curl -fsS --cacert "$TRSTCTL_CA_FILE" -X POST "https://trstctl.example.com/api/v1/breakglass/issue" \
  -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  -H "Idempotency-Key: incident-2026-06-25-bg-issue" \
  -H "Content-Type: application/json" \
  -d '{"ceremony_id":"<ceremony-id>","request_id":"bg-001","subject":"recovery.svc.example.test","csr_der":"...base64-csr...","reason":"regional outage","ttl_seconds":900}'
```

Break-glass reconciliation remains API-served after an offline ceremony:

```bash
curl -fsS --cacert "$TRSTCTL_CA_FILE" -X POST "https://trstctl.example.com/api/v1/breakglass/reconcile" \
  -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  -H "Idempotency-Key: incident-2026-06-25-bg-reconcile" \
  -H "Content-Type: application/json" \
  -d '{"bundles":[{"request_id":"bg-001","subject":"recovery.svc.example.test","cert_der":"...base64...","reason":"regional outage","approvals":["op1","op2"],"issued_at":"2026-06-25T17:00:00Z","signature":"...base64..."}]}'
```

The caller needs `certs:issue`; audit readers can then confirm the result with
`GET /api/v1/audit/events?type=breakglass.issued`.

Open a short-lived Postgres session:

```bash
curl -fsS --cacert "$TRSTCTL_CA_FILE" -X POST "https://trstctl.example.com/api/v1/access/sessions" \
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
curl -fsS --cacert "$TRSTCTL_CA_FILE" -X POST "https://trstctl.example.com/api/v1/access/sessions" \
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

- **Serving status:** historical credential-compromise execution evidence (F31) remains
  readable through `/api/v1/incidents/executions`, `trstctl-cli incidents executions *`,
  and `/incidents`, while its unsafe direct mutation refuses with H2 fleet guidance;
  automated remediation playbooks (CAP-REM-01) are served through
  `/api/v1/remediation/playbooks`,
  `/api/v1/remediation/playbooks/{id}/runs`,
  `/api/v1/remediation/playbook-runs{,/{id}}`, `trstctl-cli remediation playbooks*`,
  and `/incidents`; owner-driven self-remediation (CAP-REM-02) is served through
  `/api/v1/remediation/owner-actions`,
  `/api/v1/remediation/owner-actions/{id}/accept`,
  `trstctl-cli remediation owner-actions *`, and the `/incidents` console; NHI
  right-size runs require usage-backed CAP-POST-01 posture evidence and queue
  `connector.right_size` through the outbox. A configured tenant/connector binding
  applies the least-privilege scope removal to the external entitlement API, reads
  the effective scopes back, and records a delivered/failed connector receipt;
  CA-compromise fleet re-issuance (F32) is served through
  `/api/v1/incidents/fleet-reissuance-runs`,
  `trstctl-cli incidents fleet-reissuance *`, and the `/incidents` console;
  compromised-credential / stolen-token detection (CAP-ITDR-02) is served through
  `credential_compromise` Discovery sources, runs, and findings; malicious /
  abused OAuth-grant detection (CAP-ITDR-03) is served through `oauth_grant`
  Discovery sources, runs, and `oauth_grant_abuse` findings;
  SIEM/SOAR/chat/ITSM response dispatch (CAP-REM-03) is served through
  `/api/v1/incidents/response-integrations/dispatch`,
  `trstctl-cli incidents response-integrations dispatch`, and `/incidents`;
  ServiceNow / ITSM ticket creation is served through
  `/api/v1/itsm/servicenow/tickets` and the `/incidents` console. JIT issuance is
  served. Online m-of-n break-glass issue/rotation/cross-signing is conditionally
  served when its signer handle, tenant, authenticated operator roster, and threshold
  are configured; offline-bundle reconciliation is served at
  `/api/v1/breakglass/reconcile`.
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
- **Playbooks:** `/api/v1/remediation/playbooks`,
  `/api/v1/remediation/playbooks/{id}/runs`, `remediation.playbook_run.recorded`,
  and `connector.right_size` outbox delivery plus authenticated entitlement readback
  for right-size; revoke/rotate use the lifecycle state machine. The operator binding
  is under `connectors.right_size` in
  [Configuration](../configuration.md#native-connector-and-external-ca-assembly).
- **ITSM:** `/api/v1/itsm/servicenow/tickets`, `itsm.ticket.requested`,
  `itsm.servicenow` outbox delivery; token material by `token_ref` only.
- **Response integrations:** `/api/v1/incidents/response-integrations/dispatch`,
  `response.integration.dispatched`, and outbox fan-out to `response.splunk`,
  `response.jira`, `notification.response`, and `itsm.servicenow`; token material by
  `token_ref` only.
- **Fleet:** `/api/v1/incidents/fleet-reissuance-runs`,
  `trstctl-cli incidents fleet-reissuance *`,
  `migration.run.recorded`, and `incident.fleet_reissuance.recorded` — exact-H1 planned,
  trust-before-leaf, signed-live-gated, revoke-after-verify, resumable, and JWS-sealed.
- **JIT:** `RequestIssuance`, `Approve`, `Deny`; default `RequiredApprovals: 2`,
  self-approval blocked.
- **PAM-lite:** `/api/v1/access/sessions`; Postgres scoped login roles; OpenSSH user
  certificates; `pam.session.started`, `pam.session.expired`.
- **Break-glass:** ceremony/execution pairs at
  `/api/v1/breakglass/issue-ceremonies` + `/issue`,
  `/api/v1/breakglass/rotation-ceremonies` + `/rotate`, and
  `/api/v1/breakglass/cross-sign-ceremonies` + `/cross-sign`; `IssueOffline`,
  `Verify`, and `POST /api/v1/breakglass/reconcile` remain the disconnected path.
- **Events:** `incident.*`, `response.integration.dispatched`, `fleet.*`, `approval.*`, `pam.session.*`,
  `breakglass.issued`.

## See also

[Graph, query & AI](graph-query-ai.md) (blast radius) ·
[Issuance & certificate authorities](issuance-and-cas.md) (revocation, CA rotation) ·
[Policy & governance](policy-and-governance.md) (approver policy, notifications) ·
[Incident-response runbook](../runbooks/incident-response.md) ·
glossary: [revocation](../glossary.md), [rotation](../glossary.md), [CA](../glossary.md)

**Covers:** F31, F32, F33, F34
