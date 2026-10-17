# PCAS Operations Runbook

Proof-Carrying Algorithm Succession (PCAS) lets an identity move from one
algorithm epoch to the next without asking relying parties to guess which key is
current. The control plane records a tenant-scoped request, the outbox drains it,
and the isolated signer mints or zeroizes key material. Private keys stay in the
signer process.

To serve signed epoch checkpoints, set these control-plane settings before
startup while keeping the isolated signer and its persistent key store attached:

```text
TRSTCTL_PCAS_CHECKPOINTS_ENABLED=true
TRSTCTL_PCAS_CHECKPOINTS_INTERVAL=1m
TRSTCTL_PCAS_CHECKPOINTS_SIGNING_KEY_HANDLE=pcas-checkpoint-signer
TRSTCTL_PCAS_CHECKPOINTS_SIGNING_ALGORITHM=ECDSA-P256
```

Choose a deployment-specific stable handle and keep it through restarts. The
worker provisions that signer-held key if it does not already exist. Store its
public-key fingerprint through an independent trusted channel before using it
as a relying-party pin. PCAS and this worker are in the core build and need no
commercial license.

## First use: register, verify, then succeed an identity

Use a tenant principal with `keys:write` to register the immutable starting
anchor. The control plane queues the operation; the isolated signer creates the
tenant trust root and identity key. Registration is complete only after the
request status says `delivered` and the chain endpoint returns `genesis` and
`trust_root_public_der`. A `certs:read` principal can read status and chain;
`certs:write` is needed to request a succession.

```bash
cat > /secure/operator-genesis.json <<'JSON'
{"identity_id":"spiffe://example.test/workload/api","algorithm":"ECDSA-P256","deployment_scope":"spiffe://example.test"}
JSON
trstctl pcas genesis register -f /secure/operator-genesis.json
trstctl pcas requests status REQUEST_ID
trstctl pcas chain get --identity_id spiffe://example.test/workload/api
```

If checkpoint generation is enabled, read the latest epoch checkpoint with
`trstctl pcas checkpoints get --identity_id spiffe://example.test/workload/api`
or the Posture console's **Read signed checkpoint** action. The response keeps
the checkpoint signer's public DER captured when that checkpoint was minted,
alongside the signed identity, epoch, successor public key and transparency log
head. Compare the SHA-256 fingerprint of that DER with a checkpoint-signer key
obtained and pinned through a separate trusted channel; then verify the
checkpoint signature. A key returned in the same response is not a trust
anchor by itself. Older checkpoints without a captured signer key leave
`signer_public_der` absent; verify them only if the historical key is available
from a separately trusted record. Do not substitute the current signer key for
an older checkpoint after rotation.

Save the returned trust-root public key fingerprint in an independently
controlled trust store before distributing the chain. A fresh client must not
silently trust a root supplied in the same response it verifies. Confirm the
registered tenant, identity, scope, algorithm and epoch zero, then verify the
root signature on genesis. The Posture console shows the root fingerprint and
chain count for this review. Keep the output as public evidence; it contains no
private key.

After genesis is delivered, submit a different target algorithm and poll its
request. The successor record is returned in `records` as base64 JSON bytes;
verify both signatures, epoch continuity, policy and scope against the pinned
root before changing a relying party. The chain API does not deploy a new
credential or make a relying party adopt it.

```bash
cat > /secure/operator-succession.json <<'JSON'
{"identity_id":"spiffe://example.test/workload/api","credential_type":"workload-svid","target_algorithm":"ECDSA-P384","policy_ref":"policy:operator","deployment_scope":"spiffe://example.test"}
JSON
trstctl pcas succession request -f /secure/operator-succession.json
trstctl pcas requests status REQUEST_ID
trstctl pcas chain get --identity_id spiffe://example.test/workload/api
```

Use distinct idempotency keys for distinct POST operations. A request for an
unregistered identity returns 409 with the registration path; it never creates
an unanchored chain. Do not register the same identity under a different scope
or algorithm to recover an error: the anchor is immutable. A previously used
unscoped signer handle requires an explicit custody migration, as described in
[PCAS key custody](../pcas-key-custody.md).

## Delegation scopes and signer floor

A delegation scope limits which algorithm epoch the signer may mint. Configure
it before requesting a succession with `delegation_scope`. The isolated signer
must have its persistent keystore mounted; the control plane does not write the
signer's scope file. A scope belongs to one tenant. Its parent cannot change,
and its floor can only rise. Create a root before its children. Use `certs:write`
for commands and `certs:read` for readback.

```bash
cat > /secure/pcas-root-scope.json <<'JSON'
{"scope_id":"qa-root","epoch_floor":1}
JSON
trstctl pcas delegation scopes set -f /secure/pcas-root-scope.json
trstctl pcas requests status REQUEST_ID
trstctl pcas delegation scopes list
```

The POST returns HTTP 202 and `queued`; only the outbox command is durable at
that point. Wait until request status is `delivered`, then read
`GET /api/v1/pcas/delegation/scopes` or use the CLI/console. The matching row
must say `signer_confirmed: true` and include a signed receipt binding tenant,
operation ID, scope, parent, and applied floor. Verify that signature with the
included signer public key, then compare its fingerprint with a key obtained
through an independent trusted channel. A key returned alongside its own
signature is not an independently trusted anchor.

To raise a floor, send `{"scope_id":"qa-root","epoch_floor":3}` through
`trstctl pcas delegation floors raise -f /secure/pcas-floor.json`. The signer
refuses a lower floor, unknown scope, unknown parent, or changed parent. A lost
worker response reuses the same operation ID and signed receipt. In the
Posture console, open **Proof-carrying key succession → Signer-enforced
delegation scopes**, review the exact scope/parent/floor, queue the command,
and refresh status and scope readback. Older rows without signer receipts are
marked unconfirmed. Re-provision them through this command path before relying
on them; a control-plane-local scope file cannot establish signer custody.

## Retiring a predecessor epoch

Before an old signing key can retire, record which relying parties must attest
that they have advanced. Open **Algorithms and future readiness → Compatibility,
PQC policy, and upgrade planning → Proof-carrying key succession**. Enter the
stable identity and predecessor epoch, then read the current policy. The form
shows the exact relying-party names and public keys, quorum, acknowledgment
window, rewrap state, and last update. The server derives the predecessor
signer handle; the console does not ask the operator to enter it.
Compare each public key through a separate trusted channel. Review the exact
draft before saving it; changing an input cancels that review.

The same operation works through the Core API and CLI. The `public_der` values
are base64-encoded DER public keys, not private keys. Keep the policy JSON in a
protected operator file and do not place private key material in it.

```bash
trstctl pcas retirement show \
  --identity_id spiffe://example.test/workload/api \
  --predecessor_epoch 0
trstctl pcas retirement policy set -f /secure/retirement-policy.json
trstctl pcas retirement show \
  --identity_id spiffe://example.test/workload/api \
  --predecessor_epoch 0
```

`retirement-policy.json` contains `identity_id`, `predecessor_epoch`, a positive
`threshold`, a nonempty `roster` of distinct `relying_party` and `public_der`
entries and `validity_window_seconds`. Omit `predecessor_handle`: the server
derives it from the authenticated tenant, identity and predecessor epoch, and
rejects a supplied value unless it matches that exact key. The console does
not ask an operator to copy an internal signer handle. The server rejects
duplicate relying parties, invalid public keys, or a threshold above the
roster size. A successful policy read means the quorum is configured. After
the signed acknowledgment, verify `retired` with the API and CLI, then confirm
the exact predecessor signer key refuses signing; the status alone is not proof
of zeroization. `rewrap_complete` is false when there are no rewrap jobs; in
that case there is no ciphertext to rewrap. Do not infer that a relying party
changed trust stores just because it appears in the roster.

On restart, the retirement worker checks previously retired policies against
the signed retirement event and the tenant-bound signer handle. This also
repairs older policies that were marked retired after deleting a different,
unscoped handle. A missing retirement event is an error; the worker will not
destroy a key based only on a mutable status row. After recovery, independently
check that the exact predecessor handle cannot sign.

## Recovery request admission

`POST /api/v1/pcas/recovery/policies` requires `identity_id`, a positive
`threshold`, a nonempty `roster` array and `trust_root_der`. Each roster member
uses the JSON fields `ID` and `PubDER`; the latter is a base64-encoded public-key
DER value. The server refuses duplicate IDs or public keys, unusable keys and a
threshold greater than the distinct roster size. Keep the trust-root private key
and every approver private key outside the policy document.
The accepted public policy is appended as a tenant-bound event before its serving
copy is updated. If the control plane stops between those steps, event replay
restores the serving policy. Policies written by an older build without a source
event are not accepted as recovery authority after this upgrade; reconfigure
them through the API, CLI, or console before requesting recovery. Reuse the
same `Idempotency-Key` when retrying an uncertain configuration response.

Before asking custodians to sign, run
`trstctl pcas recovery successor prepare -f successor.json --force` (or POST
`/api/v1/pcas/recovery/successors/prepare`). The document names the registered
`identity_id`, its exact `deployment_scope`, the next `epoch`, and a signature
`algorithm` the isolated signer can generate. Preparation creates a tenant,
identity and epoch-bound key inside signer custody and appends its signed public
receipt to the event log. Poll the returned request status to `delivered`, then
read `trstctl pcas recovery successor get --identity-id ID --epoch N` (or GET
`/api/v1/pcas/recovery/successors?identity_id=ID&epoch=N`). Compare the public
key and signer receipt independently. Give the custodians the **public key from
that readback**, never a separately generated key. A second preparation with a
different algorithm or scope for that epoch is refused; a lost response can be
retried without replacing the key. The isolated signer does not support Ed25519
for this key-creation path.

In the console, open **Algorithms and future readiness → Compatibility, PQC
policy, and upgrade planning → Proof-carrying key succession**, enter the stable
identity and read its chain. The **Threshold recovery** section reads the
currently enforced public policy. Its policy form accepts only public DER keys;
review the exact threshold, ordered roster and recovery root before saving.
Read the saved policy back before preparation. The next panel derives the
deployment scope and next epoch from the tenant chain, prepares the key inside
signer custody, and reads its signed public receipt. Hand that exact public key
and the signed statement to separate custodians through a trusted channel.
The final panel accepts a JSON authorization containing `Statement`,
`Threshold`, ordered `Roster`, `RosterSig`, and distinct `Approvals`. It
checks the visible identity, tenant, scope, epoch, public key and policy binding
before the reviewed submission; the server verifies the signatures at admission
and again at delivery. The browser never asks for custodian private keys.

The one-shot `trstctl-signer --pcas-recovery-mode` ceremony produces that JSON
without bringing root or custodian private keys into the control plane. Run each
key operation as its own signer process on the machine holding that person's
owner-only key file. `keygen` creates an ECDSA-P384 PKCS#8 private key and a
public `{ "ID", "PubDER" }` roster entry; use it separately for the recovery
root and for every custodian. Save the recovery root public DER and ordered
custodian entries in the tenant policy. Save the genesis trust-root public key
from the original verified chain as a separate, independently pinned public
entry; it may differ from the recovery root. Keep these roots distinct in the
operator record.

After reading the current policy, chain and prepared successor through the API
or CLI into public JSON files, produce the exact statement:

```sh
trstctl-signer --pcas-recovery-mode statement \
  --pcas-recovery-chain chain.json \
  --pcas-recovery-successor successor.json \
  --pcas-recovery-pinned-root pinned-genesis-root.json \
  --pcas-recovery-output statement.json
```

This refuses a chain whose genesis signature does not verify under the pinned
root, a changed tenant, identity or scope, a successor that is not the next
epoch, an altered first-writer event ID, or an invalid signature made with the
prepared successor key. The public GET readback includes the tenant ID because
it is part of the bytes the isolated signer signed.
The statement contains a fresh nonce. The recovery root signs the exact ordered
roster and threshold; each custodian then signs the same statement with their
own key and ID:

```sh
trstctl-signer --pcas-recovery-mode roster \
  --pcas-recovery-policy policy.json --pcas-recovery-key root.key \
  --pcas-recovery-output roster-signature.json
trstctl-signer --pcas-recovery-mode approve \
  --pcas-recovery-policy policy.json --pcas-recovery-statement statement.json \
  --pcas-recovery-chain chain.json \
  --pcas-recovery-successor successor.json \
  --pcas-recovery-pinned-root pinned-genesis-root.json \
  --pcas-recovery-id custodian-a --pcas-recovery-key custodian-a.key \
  --pcas-recovery-output custodian-a-approval.json
```

Each custodian independently checks the pinned genesis and the prepared
successor's signature, then derives the same statement before their own key
signs.
Repeat approval on another custodian's machine. Combine only the **public**
approval documents into a JSON array, for example with `jq -s` over their
paths, then assemble and verify the quorum before submitting:

```sh
jq -s '.' custodian-a-approval.json custodian-b-approval.json > approvals.json
trstctl-signer --pcas-recovery-mode assemble \
  --pcas-recovery-policy policy.json --pcas-recovery-statement statement.json \
  --pcas-recovery-roster-signature roster-signature.json \
  --pcas-recovery-approvals approvals.json \
  --pcas-recovery-output authorization.json
```

The signer refuses a signature from the wrong key, a reordered or changed
roster, and fewer than the configured number of distinct valid approvals.
The output is create-new and owner-only. Independently verify the full chain
and the prepared successor receipt before asking custodians to sign; the
statement command verifies the pinned genesis and immediate binding, while
the server checks the current event-sourced chain and signed successor receipt
again at request admission and delivery. Do not treat copied JSON alone as
proof that the successor is served or that recovery completed.
After delivery, refresh the served chain and verify its inclusion proof with
an independent relying party.

`POST /api/v1/pcas/recovery/requests` then refuses a request unless its tenant
and identity have a configured policy, its signer handle is the derived tenant
handle for that prepared epoch, its predecessor matches the current recorded
chain, and its trust root, quorum, roster, signed statement and signatures
match the policy and prepared public key. An accepted response means the
request was queued. The worker checks the same policy, chain and signer receipt
again at delivery; changing authority after queueing makes the old request fail
closed. The worker reports delivery only after the signed recovery record is an
immutable event, its tenant-scoped chain row has been projected, and a separate
event has attached a signer-signed RFC-6962 inclusion proof. The transparency
tree contains every event-sourced recovery commitment for this identity in
epoch order; its signing key is the tenant root public key already pinned from
genesis. A crash after either append can replay the same outbox command without
changing the record or its first proof. Fetch the chain with the API or
`trstctl pcas chain get --identity_id ID`, and verify the recovery record with
the pinned genesis root and `rpverify.VerifyRecovery` (including its minimum
approval threshold and signed tree head). A queued response or SQL status alone
is not proof of minting, signer custody or relying-party acceptance.

## PCAS issuer registration

Before `POST /api/v1/pcas/issuers`, complete the managed-CA ceremony and
confirm the CA authority is active in this tenant. Use that authority's exact
signer handle and the DER encoding of the **first** public CA certificate in
its `certificate_pem` chain. The server parses the full public-only chain but
binds only that first certificate to the signer-held key. The named PCAS identity must have a
verified tenant-bound genesis, and `current_epoch` must equal its recorded
algorithm epoch (zero before its first succession). Registration checks the
tenant-owned CA row, the isolated signer's live key, and the exact certificate
public key before storing an issuer. A foreign, superseded, absent or mismatched
CA returns a refusal at registration instead of failing during leaf issuance.
The issuer-leaf and stapled-leaf routes use the same managed-CA issuance path as
the hierarchy API. That path binds this tenant's exact active CA handle and
first public certificate, applies the CA's leaf profile and revocation pointers,
obtains the signer's per-sign authorization through the configured CA authority,
and appends the issued certificate to the event-sourced inventory. It does not
silently follow a CA rotation; re-register the PCAS issuer with the new handle
and certificate after the intended epoch change. If the managed-CA issuer is
unavailable, a protected signer key is refused at registration (409), and an
older registration cannot bypass the signer policy during leaf issuance.
Both leaf routes require `certs:issue`, the same permission as the managed CA
hierarchy's leaf-issue route. `certs:write` alone cannot mint a certificate.
Leaf issuance rechecks the managed CA's active state and the PCAS epoch; a
superseded authority or a newer succession stops issuance from the stale issuer
registration until the operator binds the active authority and epoch.
The accepted registration is appended as a tenant-bound source event before its
serving copy is updated. Event replay restores it after a crash. Registrations
from an older direct-write build have no source event and are not served after
this upgrade; re-register them through the supported API before issuing leaves.
Retry an uncertain registration response with the same `Idempotency-Key`.

## Federation bridge imports

`POST /api/v1/pcas/federation/imports` queues verification of a foreign
genesis and succession chain. The `202` response means only that the import
was queued. Send `foreign_genesis` as the JSON `genesis` object from the
foreign deployment's chain response. Decode each base64 `records` entry from
that response into a JSON succession record object before putting it in
`foreign_chain`; base64-encoded record strings are refused before queueing.
Pass its `trust_root_public_der` as `foreign_trust_root_der` (a base64 SPKI byte string).
Before import, register a tenant PCAS genesis whose `identity_id`
equals the request's `local_deployment_id`. Omit `local_authority_handle` and
the server derives that tenant identity's epoch-zero signer handle. An explicit
handle must match the same value. A handle from another tenant or an unregistered local
authority is refused, and the worker rechecks the exact public key against the
tenant genesis before signing. `GET /api/v1/pcas/federation/bridges` shows a bridge only after
the worker verifies the foreign trust root and chain and signs the local bridge
record. The foreign deployment and identity in the request must match the
signed foreign genesis. The verified bridge is then appended as a tenant-bound
event and replayed into the serving list after a restart. Older direct-write
rows without source events are not served; import them again through the API.
A failed or still-pending import is not a trust relationship. Compare the listed
`trust_root_sha256` with the foreign deployment's public root before using the
bridge.

The recovery, federation and KEM mutation responses include a `status_url` to
`GET /api/v1/pcas/requests/{request_id}`. That read reports this tenant's
outbox state even when the operator has configured custom PCAS breadth topics;
it also recognizes canonical topics left queued before a configuration change.
`delivered` means the worker finished its call. For KEM, use the separate
`GET /api/v1/pcas/rewrap` stage readback and verify the paired public record
before treating a rewrap as complete.

The native CLI mirrors these routes: `trstctl pcas federation bridges list`,
`trstctl pcas federation imports request -f import.json`,
`trstctl pcas kem rewrap request -f rewrap.json`, and
`trstctl pcas rewrap status --identity_id <identity>`.
Recovery uses `trstctl pcas recovery policy set -f policy.json --force` and
`trstctl pcas recovery policy get --identity_id ID` to read back the exact
public quorum and trust root currently enforced for that tenant identity,
`trstctl pcas recovery successor prepare -f successor.json --force`, the
successor readback command above, and
`trstctl pcas recovery request -f request.json --force`; the force flag makes
the operator acknowledge the authority change or mint. Issuer registration and
leaf issuance use `trstctl pcas issuers register`,
`trstctl pcas issuers leaf issue`, and `trstctl pcas staple leaf issue`, each
with `-f` and the reviewed JSON body. These commands use the same tenant and
idempotency headers as the API.

## Health Signals

Scrape `/metrics` on the control plane. PCAS feature work is exposed through the
shared feature metrics:

- `trstctl_feature_operations_total{feature="pcas_succession",action="mint",outcome="success"}`
- `trstctl_feature_operations_total{feature="pcas_succession",action="genesis",outcome="success"}`
- `trstctl_feature_operations_total{feature="pcas_delegation",action="apply",outcome="success"}`
- `trstctl_feature_operations_total{feature="pcas_kem",action="rewrap",outcome="success"}`
- `trstctl_feature_operations_total{feature="pcas_retirement",action="worker",outcome="success"}`
- `trstctl_feature_operations_total{feature="pcas_checkpoint",action="worker",outcome="success"}`
- `trstctl_feature_operations_total{feature="pcas_monitor",action="worker",outcome="success"}`
- `trstctl_feature_operation_duration_seconds_count{feature="pcas_succession",action="mint"}`

The labels are fixed strings. They never include tenant IDs, identities, serials,
handles, ciphertexts, shared secrets, or other secret material.

Also watch:

- `trstctl_signer_up`: must be `1` on a healthy node.
- `trstctl_signer_restarts_total`: should not grow during normal operation.
- Outbox lag and timeout metrics for `pcas.*` destinations.
- Bulkhead metrics for queue depth and rejection spikes.

## Integration checks

PCAS ships in the core. Run its conformance suite locally:

```bash
bash scripts/pcas_no_skip_gate.sh
go test ./internal/succession/conformance -count=1 -timeout=10m
```

The suite includes the real embedded PostgreSQL, NATS/JetStream, cross-process
signer, and WASM verifier checks. It also exercises a multi-tenant burst, durable
outbox draining, metrics, and duplicate delivery without a second mint. The
no-skip check rejects tests that silently bypass missing infrastructure. Missing
prerequisites must be resolved before treating the run as passed.

For a focused operations investigation:

```bash
go test ./internal/succession/conformance -run TestINT21_PCASOpsSLOBackpressureAndCrash -count=1 -timeout=10m
```

The shared `make test` and `make editions-gate` checks cover the core package and
edition boundary; there is no separate proprietary PCAS release target.

## Backpressure Model

PCAS mutations use the normal API path, so the global API rate limiter applies
before a request is accepted. Accepted asynchronous work is durable outbox work:
one row per tenant-scoped external effect. Delivery is retried by the outbox
worker with leases, retry backoff, and destination/tenant fairness.

Operationally:

1. If the API rate limit trips, the request is rejected before it can create more
   work.
2. If an outbox destination is slow, other tenants and destinations can still be
   claimed by workers.
3. If a PCAS worker crashes after minting but before publish, the idempotency key
   makes redelivery return the original result instead of minting again.

## Common Checks

Check a succession chain:

```bash
curl -fsS "$TRSTCTL_URL/api/v1/pcas/chain?identity_id=$IDENTITY_ID"
```

Check a KEM re-wrap:

```bash
curl -fsS "$TRSTCTL_URL/api/v1/pcas/rewrap?identity_id=$IDENTITY_ID&predecessor_epoch=$EPOCH"
```

Check retirement:

```bash
curl -fsS "$TRSTCTL_URL/api/v1/pcas/retirement?identity_id=$IDENTITY_ID&predecessor_epoch=$EPOCH"
```

To configure retirement, enable `TRSTCTL_PCAS_RETIREMENT_ENABLED=true` on the
control plane and register the exact predecessor epoch and relying-party public
keys through `POST /api/v1/pcas/retirement/policies`. The `roster` field is a
JSON array of `{"relying_party":"rp1","public_der":"BASE64_SPKI_DER"}` objects, not
a quoted JSON string. Set a positive `threshold` no greater than the roster
size. Relying-party names must be unique and each `public_der` must be a valid
SubjectPublicKeyInfo public key; invalid or impossible quorums return 400 before
the policy is saved. Each relying party signs the domain-separated acknowledgment for the
tenant, identity, epoch and its own roster name, then posts it to
`POST /api/v1/pcas/acks`. An active policy or accepted acknowledgment alone does
not prove retirement. Read `status: retired`, check signed retirement evidence,
and independently confirm the predecessor signer handle is unusable.

Check posture:

```bash
curl -fsS "$TRSTCTL_URL/api/v1/pcas/posture?identity_id=$IDENTITY_ID"
```

## Crash Recovery

After a control-plane or signer restart:

1. Confirm `trstctl_signer_up` returns to `1`.
2. Confirm PCAS outbox rows continue to drain.
3. Re-fetch the chain for the affected identity.
4. Verify there is exactly one record for the requested successor epoch.
5. Check the feature metric outcome labels for `outcome="error"` growth.

The signer floor is monotonic and durable. A restarted signer must refuse a stale
asserted predecessor epoch; that is the key property that prevents floor
regression and double minting.

## Escalation

Escalate immediately if:

- `pcas_succession/mint` errors grow while `trstctl_signer_up` is `1`;
- retirement worker errors persist after re-wrap completion;
- two different records appear for the same tenant, identity, and epoch;
- KEM re-wrap stays incomplete while its outbox rows are delivered;
- `pcas_monitor/misissuance` records a finding.

Do not manually delete PCAS rows. The event log, outbox, and RLS tables are the
evidence trail. If repair is needed, use a new idempotent operation that records
what was changed.
