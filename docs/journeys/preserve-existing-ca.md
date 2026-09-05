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

The tenant operator needs `issuers:read`, `certificates:issue`, discovery access, and
the permissions required for the chosen destination and notification route. Use a
non-production hostname and destination for the first proof.

## What the current workflow proves

The upstream-CA registry and issue route are real served paths. The CA Hierarchy page
and `trstctl-cli external-cas` commands use the same API. Connector target testing is
a separate effect-free preview: it validates the destination from the execution
vantage point and reports the proposed writes without deploying a certificate.

Raw external-CA issuance and connector deployment are deliberately described as
separate operations here. Do not claim a closed-loop external-CA renewal until the
selected issuer, issued certificate, private-key custody, destination, renewal, and
verification receipts are bound into one reviewed lifecycle. The proof gate at the
end of this page makes that boundary explicit.

## Steps

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

Create a bounded network discovery source for the canary host and start a run. A
network source performs a normal TLS handshake; it does not install software or send
an exploit to the target.

```json
{"kind":"network","name":"existing-ca-canary","config":{"targets":["web-canary.example.test:443"]}}
```

```sh
trstctl-cli discovery sources create -f source.json
trstctl-cli discovery runs start -f run.json
trstctl-cli discovery findings list --run_id <run-id>
trstctl-cli certificates list --limit 50
```

The finding and inventory row should agree with the before baseline. Stop if the
hostname, listener fingerprint, or owner is wrong.

### 3. Select the authority explicitly

List configured upstreams and copy the intended ID exactly:

```sh
trstctl-cli external-cas list
```

Do not continue when the intended row is absent or unhealthy. A similar display name
is not a safe substitute for the registry ID.

### 4. Create the key and CSR where the workload owner controls them

The following lab command writes a new private key locally with owner-only
permissions. Use the workload's HSM, KMS, or approved key-generation process in
production.

```sh
umask 077
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -nodes -keyout web-canary.key -out web-canary.csr \
  -subj '/CN=web-canary.example.test' \
  -addext 'subjectAltName=DNS:web-canary.example.test'
jq -n --rawfile csr web-canary.csr \
  '{csr_pem:$csr,dns_names:["web-canary.example.test"],profile_name:"tls-server-30d",ttl_seconds:2592000,requested_ekus:["serverAuth"]}' \
  > external-ca-issue.json
```

Review the CSR and request file. They must name only the canary and the approved
profile.

### 5. Issue through that authority and inspect the receipt

Replace `<external-ca-id>` with the registry ID from step 3:

```sh
trstctl-cli --idempotency-key preserve-ca-canary-001 \
  external-cas issue <external-ca-id> -f external-ca-issue.json \
  > external-ca-issued.json
jq '{serial,issuer,not_after}' external-ca-issued.json
```

The issuer must match the selected authority. Repeating the exact command with the
same idempotency key returns the original result; changing the request while reusing
that key is rejected. Store `certificate_pem` only where the approved installation
process needs it, then delete the temporary response according to your retention
policy.

### 6. Preview the destination without writing

Create the canary destination with only non-secret metadata and `secret://`
references, bind the intended identity, then run the target test:

```sh
trstctl connector target test --target <target-id>
```

A ready result is `dry_run_planned`; a blocked result is `dry_run_blocked`. The target
test is an effect-free preview: it must report zero writes and the exact later
mutations. **Configuration valid — target not contacted** is not live readiness.
Follow [Deployment connectors](../features/deployment-connectors.md) for the connector's
execution-vantage and key-custody requirements.

### 7. Verify expiry routing and operator ownership

Preview the exact owner/asset/severity route, then inspect the inbox and acknowledge
the controlled alert:

```sh
trstctl-cli notifications routing-preview \
  --workspace certificate-lifecycle --owner_ref <owner-id> \
  --asset_ref <identity-id> --severity high
trstctl-cli notifications list --status unread
trstctl-cli --idempotency-key preserve-ca-alert-read-001 \
  notifications read <notification-id>
```

For an external channel, retain the provider's acceptance receipt as well as the
trstctl outbox receipt. This is the alert acknowledgement proof that an owner can see
and work the warning.

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
  fingerprint.

Until every item is evidenced, describe the demonstrated boundary precisely: trstctl
can discover the existing certificate, issue through the explicitly configured
external CA, inventory the result, preview a destination, and route alerts. Do not
turn those separate receipts into a claim that the complete lifecycle ran.

## Where next

- [Replace your existing CA (optional)](migrate-from-existing-ca.md) — use only when
  the authority itself must change.
- [Automate TLS across your fleet](automate-fleet-tls.md) — ACME-based renewal and
  connector deployment.
- [Issuance and certificate authorities](../features/issuance-and-cas.md) — upstream
  registry, custody, retry, and provider details.

**Journey:** J5A  
**Steps through:** F1, F2, F4, F7, F17, F26, F27, F29, F46
