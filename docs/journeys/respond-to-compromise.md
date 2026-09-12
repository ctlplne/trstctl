# Respond to a key or certificate compromise

<!-- trstctl:journey-census:start -->
!!! success "Served path — wiring census 81/81"

    The Definition-of-Done census reports **81/81 required capabilities served**: **12 of 81 census rows launch the shipped binary** and **69 of 81 are proved through the production-assembled handler**.
    Production-assembled means production `buildRunDeps` output driving the assembled `Server.Handler` in-process, with a hand-built `Deps` rejected; only the process launch differs.
    Independently proof-gated capability rows used by this journey (all `required`, all `served`): `breakglass_rotation.cross_sign_rekey`, `connector.registry`, `notification_channel.dispatch`.
    Core surfaces guarded by route and journey tests: `credential_graph`, `incident_execution`, `revocation`, `evidence_export`.
    This badge is generated from `wiring-census.json`; `make journey-census-check` fails closed if the census or this page drifts.
<!-- trstctl:journey-census:end -->

## Goal

Replace a compromised leaf credential, revoke the exact affected certificates at
their issuing authority, verify the workload and revocation outcome, and retain a
checkable incident timeline. A compromised CA requires a separate fleet response
that also replaces trust. Choose the response scope before authorizing work.

Replacement-before-revocation keeps a working credential available while the new
one is installed. It does not guarantee uninterrupted service or contain an active
attacker during that overlap. The incident lead must decide whether immediate
revocation and service isolation are necessary.

## Before you start

- Use an authenticated operator with the permissions required by each reviewed
  action. The bootstrap token is deliberately insufficient for issuance.
- Keep the inspected CA bundle configured as `TRSTCTL_CA_FILE`, as described in
  [Getting started](../getting-started.md).
- Record the affected certificate ID, serial, fingerprint, issuing authority,
  managing identity, owner, and deployment destination. Certificate IDs and
  identity IDs name different records; a shared DNS name is not an exact binding.
- For replacement, have an enabled destination, its enrolled agent or supported
  executor, and an available issuing CA. Preserve your existing CA unless it is
  itself compromised or your response explicitly requires a different one.
- Fleet re-issuance additionally requires an active incident-response entitlement,
  the compromised issuer in the served issuer catalog, an active signer-backed
  replacement authority, exact enrolled agents and trust paths, and a rollback
  reference. A license does not create these prerequisites.

## 1. Preserve evidence and identify affected resources

Assign an incident lead and record the exposure window. Follow the
[incident-response runbook](../runbooks/incident-response.md) to capture safe
support diagnostics and a full backup without delaying urgent containment. Export
the incident audit window and retain its independently pinned verification key.

In **Certificates**, find the exact certificate and open its details. **View in
credential graph** scopes that certificate; **Start incident response** uses its
exact managing identity when one is recorded. Inspect affected resources and
owners. If no exact managing identity is available, resolve that binding before
using identity-wide actions.

The equivalent certificate graph read uses the actual inventory ID:

```sh
trstctl-cli graph blast-radius "cert:${CERTIFICATE_ID}"
```

## 2. Replace one leaf credential

Use this path when the leaf key or certificate is affected and its issuing CA is
still trusted:

1. Open **Operations → Where credentials are installed → Destinations and safe
   actions**. Choose **Replace a managed certificate**, the enabled destination,
   and its exact original identity. Confirm the retained DNS name and owner, and
   enter the incident reason.
2. Choose the exact issuing CA. The wizard has no implicit CA default. Review the
   preview's original identity, destination revision, key custody, queued effects,
   recovery steps, and independent verification requirements.
3. Authorize issuance and deployment. This creates a separate successor identity;
   the original's renewal is held during the handoff. Acceptance is not proof of
   completed delivery. Inspect the successor's lifecycle and connector receipts,
   including failures and retries.
4. Open a fresh connection from the workload's client network. Verify the DNS name,
   chain, new serial and fingerprint, and expected application response. Compare
   that fingerprint with the successor's exact inventory and delivery evidence.
   Follow [Deployment connectors](../features/deployment-connectors.md) for the
   execution and rollback limits of the selected connector.
5. After that proof, review **Revoke** on the original managing identity. Confirm
   its exact ID and reason. Identity-wide revocation can include historical and
   undelivered certificates; the successor must remain a separate identity.
   Revocation is asynchronous. Follow the authority result as described below.

The endpoint replacement workflow authorizes issuance and deployment. It does
**not** automatically complete the operator's subsequent revocation and retirement
steps. Keep the incident open until those steps and their evidence are complete.
The [existing-CA journey](preserve-existing-ca.md#8-verify-revocation-and-retirement)
contains the equivalent reviewed CLI transitions and external-issuer limits.

## 3. Replace a compromised CA across its fleet

Use **Security incidents → Fleet re-issuance** for CA compromise. Select the
compromised issuer and clean replacement authority, then assign every affected
active identity to an exact enrolled agent and public trust-anchor path in ordered
waves. Review the complete scope, canary order, mode and rollback reference before
starting. A single leaked leaf is not permission to replace an entire issuer fleet.

Each wave installs replacement trust, requires signed host readback, issues from a
host-generated CSR, deploys the successor, and requires signed live-listener proof
before revoking the exact predecessor. Revocation receipts must arrive before the
next wave starts. A failed proof gate restores the current unrevoked wave; completed
waves with revoked predecessors are not rolled back to those credentials.

The served CLI family is `trstctl-cli incidents fleet-reissuance
start|list|get|pause|resume|rollback|evidence`. For its request fields, game-day
restrictions, and signed evidence contract, see
[Fleet re-issuance for CA compromise](../features/incident-and-jit.md#fleet-re-issuance-for-ca-compromise-f32).

The former `trstctl-cli incidents executions execute` mutation is retired. Do not
use it for new containment. Historical execution reads remain available. An
unconfigured or unlicensed deployment must not be treated as a completed fleet run.

## 4. Prove revocation, then retire the predecessor

Read the exact original certificate and identity independently:

```sh
trstctl-cli certificates get "$CERTIFICATE_ID"
trstctl-cli identities get "$IDENTITY_ID"
```

The identity's `revoked` state acknowledges lifecycle intent. Confirm the exact
certificate inventory status and the issuing authority's acceptance of its serial
and reason. For trstctl-issued certificates, check the signed tenant CRL and OCSP
response. For external certificates, check the external authority; trstctl's own
CA revocation ledger does not prove an external serial was revoked.

Where the authority publishes CRL or OCSP data, verify its signature and use a
client configured to enforce revocation to prove rejection. An ordinary successful
TLS handshake does not establish revocation status. Record unsupported adapters,
authority publication limits, client enforcement limits, and any manual CA action
as gaps in automation.

Verify the workload still serves the successor. Review **Retire** on the original
identity only after revocation is confirmed. Retirement stops its future lifecycle
work and retains its history; it does not replace revocation. Never restore a
compromised or revoked predecessor. See the existing-CA journey for rollback
checks, in-flight operation limits, and required control-plane/agent versions.

## 5. Close the response with evidence

Retain the before and after certificates, exact original/successor bindings,
reviewed plans, issuance and delivery results, independent listener checks,
authority revocation receipts, retirement event, and the incident audit export.
Verify the export offline using
[the audit verification procedure](../cli.md#verify-audit-exports-offline), and
record whether a timestamp anchor was available. A signed export is not proof
that an omitted lifecycle step happened. Fleet runs also provide their dedicated
signed evidence export; an endpoint replacement does not create a legacy incident
execution pack.

If policy requires another approver, obtain the distinct operator's approval
before the privileged action. Use the configured break-glass quorum or short-lived
brokered access when needed; neither removes the need to inspect the actual
outcome. Follow [Incident response and just-in-time access](../features/incident-and-jit.md)
for those separate workflows. Confirm delivery failures and outstanding owner
notifications are resolved before closing the incident.

## Where next

- [Keep your existing CA](preserve-existing-ca.md)
- [Run trstctl in production](run-in-production.md)
- [Getting started](../getting-started.md)

**Journey:** J9
**Steps through:** F31, F32, F33, F34, F47, F18, F19
