# Keep your existing CA

<!-- trstctl:journey-census:start -->
!!! success "Served path — wiring census 81/81"

    The Definition-of-Done census reports **81/81 required capabilities served**: **12 of 81 census rows launch the shipped binary** and **69 of 81 are proved through the production-assembled handler**.
    Production-assembled means production `buildRunDeps` output driving the assembled `Server.Handler` in-process, with a hand-built `Deps` rejected; only the process launch differs.
    Independently proof-gated capability rows used by this journey (all `required`, all `served`): `connector.registry`, `external_ca.registry`, `notification_channel.dispatch`.
    Core surfaces guarded by route and journey tests: `certificate_discovery`, `certificate_inventory`, `connector_target_test`, `notification_routing`.
    This badge is generated from `wiring-census.json`; `make journey-census-check` fails closed if the census or this page drifts.
<!-- trstctl:journey-census:end -->

## Goal

Use trstctl as the inventory, policy, automation, deployment, and evidence control
plane while your existing certificate authority stays in charge of signing. In plain
language: **trstctl does not replace your CA**. A configured external CA receives the
CSR, applies its own authority policy, and returns the certificate. trstctl records
which authority issued it and never silently falls back to its built-in signer.

This is the default CA-agnostic journey. Use it when changing the authority would be
unnecessary, politically difficult, contractually prohibited, or unsafe.

## The trust boundary

There are two different administrative jobs:

- The control-plane operator adds the external CA integration in server configuration.
  Its credential is a `file:/absolute/path` reference to an operator-owned file; the
  credential is not accepted from tenant JSON and is not returned by the API.
- A tenant operator chooses one configured external CA by its exact registry ID and
  submits only a CSR, requested names, profile name, and lifetime. The private key is
  created outside the control plane and never sent to the CA integration.

If the selected authority is missing, unavailable, or rejected by outbound-network
policy, issuance fails closed. trstctl never silently falls back to another external
CA or to its own signing service.

## Operator prerequisites

These operator prerequisites must be complete before a tenant follows the steps
below. The control-plane operator must:

1. Add the intended authority under `external_cas` and supply its credential through
   an operator-owned file reference. See
   [Native connector and external-CA assembly](../configuration.md#native-connector-and-external-ca-assembly).
2. Allow only the authority's required outbound addresses and install any private
   trust root or mTLS identity needed to reach it.
3. Restart the control plane and confirm that `GET /api/v1/external-cas` returns the
   non-secret registry row with the expected ID, type, name, and status.
4. Configure a notification channel and an owner-scoped route before relying on
   expiry alerts. A row in the notification inbox is not proof that Slack, email, or
   another receiver accepted the message.
   `notification_receiver_not_configured` means delivery has no receiver. Configure
   the channel and route; the pending outbox retry keeps the original alert key.
5. For an ACME authority that validates names with DNS-01 (`upstream_dns01`), make
   sure the tenant has a **DNS-01 provider config** that covers the zone of every
   name you will issue, with `dns-01` in `allowed_methods` and
   `allow_upstream_dv` enabled. Without it, issuance cannot publish the challenge
   record. The endpoint lifecycle preview now refuses with that exact reason instead
   of queueing work that would fail asynchronously. Create the config through
   `POST /api/v1/acme/dns-01/provider-configs` or
   `trstctl-cli acme dns-01 provider-configs`; the console has no page for it yet.
   See [ACME and DNS validation](../features/acme-and-dns.md).
6. For a host-executed destination (Apache, NGINX, HAProxy, Caddy, Traefik, IIS,
   PostgreSQL, and the other file-and-reload connectors), set
   `"executor": "agent"` in the destination configuration. An external CA answers
   asynchronously, so the enrolled host agent must generate the private key, submit
   only a CSR, install the returned certificate, and verify the listener. The preview
   refuses control-plane key custody for an external CA on a host connector rather
   than risk a certificate whose key no longer exists.

The tenant operator needs `issuers:read`, `certs:issue`, discovery access, and
the permissions required for the chosen destination and notification route. Use a
non-production hostname and destination for the first proof.

The accountable owner must be ready before you bind an endpoint: a complete record
(application ID and environment) with a current human attestation. Deployment is
refused for an owner whose attestation is missing or stale, so the endpoint lifecycle
preview refuses such an owner up front; use **Ownership → Re-attest** (or attest when
creating the owner) and preview again.

## What the current workflow proves

The upstream-CA registry and issue route are real served paths. The CA Hierarchy page
and `trstctl-cli external-cas` commands use the same API. Endpoint lifecycle setup now
binds one exact configured external CA, destination revision, and custody plan into an
effect-free preview. Execution requires that preview's unchanged fingerprint. The
initial issue and every later renewal route through the selected authority; missing
or unavailable authority configuration fails closed without platform-CA fallback.

The identity detail shows **Selected issuance CA** for endpoint automation. This
is the current issuance and renewal choice, not proof of who issued an older
certificate. Use each certificate's retained issuance evidence to establish its
actual authority, including when checking revocation.

The lifecycle preview proves the plan, not the outcome. Issuance, deployment,
listener readback, renewal, alert delivery, recovery, revocation, and retirement
need their own durable receipts or independent observations. The proof gate at
the end of this page names the evidence required before calling the complete loop
production-ready.

After a temporary CA failure, a successful host-agent retry returns the identity
from `renewal_failed` to `deployed` with an `identity.renewal_recovered` audit event.
Current ownership attestation is still required. Recording that recovery does not
queue another deployment: the host has already installed the certificate. Confirm
the rotation result and listener fingerprint as well as the lifecycle state.
Upgrading does not rewrite historical failed rotation results as successful.

## Steps

If discovery already created a requested X.509 identity for this DNS name, the
preview names that identity and enrollment pins the selected CA on it before
issuance. The existing owner must match, and any previously pinned CA must agree.
An issued or deployed identity needs its lifecycle actions or a separate
replacement identity; endpoint enrollment refuses to repurpose it. Changes to
the reviewed identity metadata require a fresh preview.

For a managed listener, choose **Replace a managed certificate** in the
destination workflow. Select the exact original identity; the console carries
forward its DNS name and owner, and still requires an explicit CA selection.
The API equivalent adds `"replace_identity_id":"<original-identity-id>"` to
the endpoint binding plan and uses the original destination's `target_id`.
The preview names `replaced_identity` and its lifecycle version. Execution
creates a separate identity; it never revokes the original as a side effect.

Wait for any earlier issuance, renewal, deployment, or rollback work to finish.
A replacement refuses an original that is renewing or a destination with pending
work. Once replacement issuance is queued, renewal of the original is held so it
cannot overwrite the new certificate. Review the new delivery and independent
listener proof, then revoke and retire the exact original identity. If issuance
or deployment fails, use its job receipts and retry the same reviewed request;
the replacement identity is retained rather than duplicated. A policy refusal
before issuance leaves a requested record and does not pause the original's
renewal. Changes to the original require a new preview.

### 1. Record the before baseline

Query the live listener before changing it. Save the leaf fingerprint, issuer, expiry,
and full chain outside the trstctl evidence directory:

```sh
openssl s_client -connect web-canary.example.test:443 \
  -servername web-canary.example.test -showcerts </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 -issuer -subject -dates
```

This is the comparison oracle. If the later certificate is not observable on the
listener, a successful API or connector receipt is insufficient.

### 2. Discover the certificate before managing it

Declare the canary's exact hostname as a bounded segment in `segment.json`:

```json
{"name":"existing-ca-canary","ranges":["web-canary.example.test"],"staleness_hours":24,"excluded":false}
```

Create `source.json` for that segment and start a run. A
network source performs a normal TLS handshake; it does not install software or send
an exploit to the target.

```json
{"kind":"network","name":"existing-ca-canary","config":{"segment":"existing-ca-canary","targets":["web-canary.example.test:443"],"allow_rfc1918":true}}
```

```sh
trstctl-cli discovery segments create -f segment.json
trstctl-cli discovery sources create -f source.json
trstctl-cli discovery sources preflight <source-id>
```

Copy the returned source ID into `run.json` before starting the run:

```json
{"source_id":"<source-id>"}
```

```sh
trstctl-cli discovery runs start -f run.json
trstctl-cli discovery runs get <run-id>
```

Starting returns accepted work. Read that exact run until its status is `succeeded`;
if it is `failed`, inspect its error and target results before retrying. Only then
inspect the findings and compare their fingerprint with the baseline:

```sh
trstctl-cli discovery findings list --run_id <run-id>
trstctl-cli certificates list --limit 50
```

The example explicitly permits an owned private IPv4 canary with `allow_rfc1918`.
Omit that flag for public-only discovery. It never permits metadata, link-local,
multicast or other prohibited addresses. If using a literal IP instead of a hostname,
declare that exact IP or its narrow CIDR; an IP-only segment does not authorize a
hostname automatically. Preflight does not contact the target.

The finding and inventory row should agree with the before baseline. Stop if the
hostname, listener fingerprint, or owner is wrong.

### 3. Select the authority explicitly

List configured upstreams and copy the intended ID exactly:

```sh
trstctl-cli external-cas list
```

Do not continue when the intended row is absent or unhealthy. A similar display name
is not a safe substitute for the registry ID.

### 4. Preview the exact CA-to-endpoint lifecycle

Create an enabled canary destination with only non-secret metadata and `secret://`
references. Put the binding plan below in `endpoint-binding-plan.json`, replacing
the IDs with the exact owner, target, and external CA you inspected:

```json
{
  "owner_id": "<owner-id>",
  "identity_name": "web-canary.example.test",
  "target_id": "<target-id>",
  "reason": "prove CA-preserving lifecycle on the isolated canary",
  "issuer": {"source":"external","id":"<external-ca-id>"}
}
```

```sh
trstctl-cli lifecycle endpoint-bindings preview \
  -f endpoint-binding-plan.json > endpoint-binding-preview.json
jq '{ready,effect_free,issuer,target,custody,changes,queued_lifecycle_intents,recovery_steps,verification_steps,preview_writes,preview_external_effects,request_fingerprint}' \
  endpoint-binding-preview.json
```

Stop unless the response names the intended CA and target, explains key custody,
says `ready: true` and `effect_free: true`, and returns empty `preview_writes` and
`preview_external_effects`. If the destination has `verify_server_name`, use that
exact value as `identity_name`; the preview refuses a mismatch before certificate
files can be replaced and then fail their own listener proof. For Apache, IIS, and other host connectors, the normal
plan is host-generated key custody: the edge collector sends a CSR, not a private
key, to the control plane. A target-vantage connector test remains a separate useful
check because it contacts the destination safely; **Configuration valid — target not
contacted** is not live readiness.

### 5. Authorize the unchanged plan

Bind execution to the reviewed fingerprint, then submit one idempotent mutation:

```sh
jq --arg fingerprint "$(jq -r .request_fingerprint endpoint-binding-preview.json)" \
  '. + {preview_fingerprint:$fingerprint}' \
  endpoint-binding-plan.json > endpoint-binding-execute.json
trstctl-cli --idempotency-key preserve-ca-canary-001 \
  lifecycle endpoint-bindings create -f endpoint-binding-execute.json \
  > endpoint-binding-result.json
jq '{identity:.identity.id,issuer,target:.target.id,queued_lifecycle_intents,renewal_intent}' \
  endpoint-binding-result.json
```

The response is accepted work, not delivery proof. Repeating the exact command with
the same idempotency key returns the original result; changing the request while
reusing that key is rejected. Changing the CA, destination, or plan after preview is
also rejected because the fingerprint no longer matches.

### 6. Inspect issuance, deployment, and listener proof

Inspect the rotation run, connector receipt, certificate inventory, and independent
listener. The public certificate issuer must agree with the CA selected in step 4,
and the listener fingerprint must differ from the before baseline. A queued receipt
with zero attempts is only intent evidence. Follow
[Deployment connectors](../features/deployment-connectors.md) for exact target-vantage,
readback, and recovery requirements.

### 7. Verify expiry routing and operator ownership

Preview the exact owner/asset/severity route, then inspect the inbox and acknowledge
the controlled alert:

```sh
trstctl-cli notifications routing-preview \
  --workspace certificate-lifecycle --owner_ref owner/<owner-id> \
  --asset_ref <identity-id> --severity warning
trstctl-cli notifications list --status sent
trstctl-cli --idempotency-key preserve-ca-alert-read-001 \
  notifications read <notification-id>
```

For an external channel, retain the provider's acceptance receipt as well as the
trstctl outbox receipt. This is the alert acknowledgement proof that an owner can see
and work the warning.

### 8. Verify revocation and retirement

Use a disposable certificate for this step. Record its exact inventory ID, serial,
fingerprint, and issuing authority before changing it. If it is serving traffic,
first deploy and independently verify a replacement with a new key. Identity-wide
revocation includes the identity's current and historical certificates, so keep
the replacement under a separate identity if it must remain valid. Include any
predecessor restored during rollback in the containment plan: a `superseded`
inventory row can still be the certificate served by the workload.

The identity workflow resolves each certificate's authority from retained issuance
evidence and dispatches through that integration's revocation adapter. A later
change to the identity's selected CA does not redirect revocation. Selection uses
exact issuance and delivery bindings, including superseded certificates restored
by rollback and certificates minted for host jobs that never finished deployment.
An external certificate is recorded as revoked only after its authority accepts
the request; its serial is not added to trstctl's own CA ledger or CRL.

Preview and execute the identity transition with `identities:write` permission:

```sh
printf '%s\n' '{"to":"revoked","reason":"keyCompromise"}' > revoke-plan.json
trstctl-cli identities transition-preview <identity-id> -f revoke-plan.json \
  > revoke-preview.json
jq '{ready,from,to,expected_version,side_effect_destination,warnings}' revoke-preview.json
# After reviewing the plan and confirming ready=true:
jq --argjson version "$(jq .expected_version revoke-preview.json)" \
  '. + {expected_version:$version}' revoke-plan.json > revoke-execute.json
trstctl-cli --idempotency-key preserve-ca-revoke-001 \
  identities transition <identity-id> -f revoke-execute.json
```

This is asynchronous: the identity's `revoked` status acknowledges the intent,
not the external outcome. Missing issuance evidence, unavailable credentials, or
an unsupported revocation adapter leave the worker unsuccessful; no different CA
is substituted. The exact-certificate bulk-revoke route still rejects unsupported
external issuers in individual result items, even when HTTP status is 200. For
those integrations, use the issuing CA's supported revocation procedure and
record the manual step as an automation gap. Certificates incorrectly marked
revoked by older versions require separate reconciliation with their issuer;
upgrading does not establish that those earlier revocations actually happened.

Confirm the issuing authority accepted the exact serial and factual revocation
reason. Where that authority publishes CRL or OCSP data, verify its signature and
status, then use a stock client configured to enforce revocation to prove that the
old certificate is rejected. Record any authority or client enforcement limit.
A normal TLS handshake does not usually check revocation by itself.

Rollback refuses a missing or revoked predecessor, and a revoked or retired
identity bound to the command. These checks run before queueing, when the agent
claims queued work, and when the updated agent asks for authorization immediately
before restoration. A host-target action also derives its identity from the last
successful deployment when the request omits it. Refused work must not report
that an agent restored the target.

Upgrade both the control plane and agents for the pre-restoration check. An
updated agent refuses restoration if its server cannot authorize it, including
an older server that does not support that check. This does not cancel a remote
operation already in progress or remove a certificate already installed. Replace
compromised material through the target's operating procedure and independently
verify the safe replacement; upstream revocation alone does not complete that
containment work.

Verify that the workload serves the replacement and cannot restore compromised
key material through rollback. When the identity is no longer needed, retire it
through the reviewed lifecycle transition. Confirm retirement stops future
renewals and deployments while preserving the issuance, replacement, revocation,
and retirement audit records. Retirement is not a substitute for revocation.

## Proof gate before you call it automated

Do not present the journey as production-ready until one isolated lab has all of the
following evidence:

- the before baseline, exact selected external-CA ID, and returned issuer agree;
- deployment changes the listener fingerprint while preserving the expected issuer
  chain, and independent readback proves the target is serving the new leaf;
- one scheduled renewal completes without a manual signing step, and a **second renewal**
  repeats the result with a new serial and the same expected authority;
- the expiry alert reaches the controlled sink, maps to the right owner, and an
  **alert acknowledgement** is visible in the inbox and audit trail;
- an unreachable authority, invalid CSR, and unreachable destination all fail closed;
- rollback restores a previously proven certificate and independent listener
  fingerprint;
- revocation reaches the exact selected authority, with its acceptance evidence
  and, where supported, signed CRL/OCSP status and rejection by a revocation-aware
  client; the workload serves the replacement and cannot restore compromised material;
- retirement stops future automation and retains the complete lifecycle audit export.

The running-operation, replacement, and unsupported-authority limits above leave this
full-lifecycle gate open even when issuance, deployment, renewal, alerts, and
upstream revocation succeed.

Until every item is evidenced, describe the demonstrated boundary precisely: trstctl
can discover the existing certificate and create one CA-explicit, fingerprint-bound
lifecycle plan whose worker routes initial issuance and renewal through the same
external CA. Do not turn accepted work or separate receipts into a claim that the
listener changed, renewed twice, alerted its owner, recovered, revoked at the
issuing CA, or retired safely unless those exact outcomes were observed.

## Where next

- [Replace your existing CA (optional)](migrate-from-existing-ca.md) — use only when
  the authority itself must change.
- [Automate TLS across your fleet](automate-fleet-tls.md) — ACME-based renewal and
  connector deployment.
- [Issuance and certificate authorities](../features/issuance-and-cas.md) — upstream
  registry, custody, retry, and provider details.

**Journey:** J5A  
**Steps through:** F1, F2, F4, F7, F17, F26, F27, F29, F46
