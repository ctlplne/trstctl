# Stay crypto-agile and migrate to post-quantum

<!-- trstctl:journey-census:start -->
!!! success "Served path — wiring census 81/81"

    The Definition-of-Done census reports **81/81 required capabilities served**: **12 of 81 census rows launch the shipped binary** and **69 of 81 are proved through the production-assembled handler**.
    Production-assembled means production `buildRunDeps` output driving the assembled `Server.Handler` in-process, with a hand-built `Deps` rejected; only the process launch differs.
    Independently proof-gated capability rows used by this journey (all `required`, all `served`): `pqc_end_to_end.automated_rollout_tls_findings`, `pqc_end_to_end.multikey_spiffe_hybrid_svid`, `pqc_end_to_end.pure_mldsa_leaf_stock_clients`.
    Core surfaces guarded by route and journey tests: `crypto_inventory`, `migration_plans`.
    This badge is generated from `wiring-census.json`; `make journey-census-check` fails closed if the census or this page drifts.
<!-- trstctl:journey-census:end -->

## Goal

When you finish this journey you will understand where your weak and
quantum-vulnerable cryptography lives, why trstctl can swap algorithms in one place
instead of a rewrite, and how a post-quantum migration is planned and what it targets.
It is for a security or platform engineer getting ahead of the quantum transition. In
plain terms: you cannot migrate what you cannot see, so you first inventory the
algorithms in your estate, then lean on the fact that all of trstctl's cryptography
goes through one isolated path (so adding a post-quantum algorithm is a contained
change), then plan the re-issue of every quantum-vulnerable credential to a
post-quantum target.

> **In the console:** the `/posture` screen shows the CBOM cryptographic inventory, a
> PQC readiness gauge (readiness % with quantum-vulnerable / PQC-ready / out-of-policy
> counts), and the migration-orchestration panel that queues and can roll back a
> migration run. An enrolled host with a retained encrypted predecessor can
> restore and verify that exact served certificate; issuance-only historical
> runs still have inventory-only rollback. See [The web console](../web-console.md).

## Before you start

- A running control plane and an API token, set up in
  [Getting started](../getting-started.md).
- The lifecycle, crypto-agility, and PQC-migration model is in
  [Lifecycle & PQC](../features/lifecycle-and-pqc.md); how the key-encryption key and
  secret material are protected is in [Secrets](../features/secrets.md).
- The shipped Core path serves two concrete compatibility anchors: pure
  ML-DSA-65 leaf enrollment over EST with stock OpenSSL 3.5 and a two-entry classical +
  ML-DSA-65 SPIFFE Workload API response. The Envoy host-agent TLS posture
  path requires an enrolled, assigned host agent, a bound loopback management
  endpoint and listener, and a signed served-state report. See [Current limitations](../limitations.md) for the tested client boundary;
  it is not a promise that every legacy client understands ML-DSA.

## Steps

1. Understand the crypto-agility model. All cryptography in trstctl routes through
   a single isolated path; no other part of the system performs crypto directly, and a
   build check fails the build if anything tries. That is what makes adding or swapping
   an algorithm — including a post-quantum one — a one-place change rather than a
   redesign. The detail is in [Lifecycle & PQC](../features/lifecycle-and-pqc.md).

2. Know which post-quantum algorithms are available. Behind that single path,
   alongside classical RSA and ECDSA/Ed25519, the Core algorithms are
   ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) signatures, ML-KEM (FIPS 203) key
   encapsulation, and classical+ML-DSA hybrids — the full catalog, with
   guidance on which suits roots versus high-volume leaves, is in
   [Lifecycle & PQC](../features/lifecycle-and-pqc.md). What matters for this
   journey: signing algorithms are pinned per certificate profile; ML-KEM is
   key establishment, not a certificate signer; the served TLS listeners
   already prefer `X25519MLKEM768` for TLS 1.3 peers that support it; and
   hybrid transition leaves bind a standard ECDSA P-256 TLS certificate to an
   ML-DSA-44 public key. ACME, EST, SCEP, and CMP can issue that transition
   leaf when the CSR carries the hybrid proof.

3. Inventory the algorithms you run. A cryptographic bill of materials (CBOM)
   classifies each observation by algorithm family and strength and flags the
   quantum-vulnerable ones. Its findings become crypto-asset nodes in the credential
   graph, so posture flows into blast-radius and compliance views. Start a scan against
   the TLS endpoints and host configs you want in the inventory:

   ```sh
   curl -sS \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Content-Type: application/json" \
     -H "Idempotency-Key: cbom-pqc-001" \
     -X POST https://trstctl.example.com/api/v1/cbom/scans \
     -d '{
       "tls_endpoints": ["payments.internal.example:443"],
       "host_configs": ["/etc/nginx/sites-enabled/payments.conf"]
     }'
   ```

   Then read the PQC posture and migration targets:

   ```sh
   curl -sS \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     https://trstctl.example.com/api/v1/cbom/assets
   ```

   The response includes `migration_progress`: total assets, how many are already
   post-quantum-ready, how many are quantum-vulnerable, and a ready percentage. Classical
   signature algorithms map to ML-DSA/FIPS 204 targets; weak TLS protocol or cipher
   findings map to ML-KEM/FIPS 203; DSA maps to SLH-DSA/FIPS 205.

   You can also explore the graph nodes that the CBOM feeds:

   ```sh
   trstctl-cli graph nodes
   ```

   You should see your inventory as graph nodes. The CBOM scanner, its policy floor
   (RSA-2048, EC-256, TLS 1.2), and the scan/inventory API are in
   [Observability & risk](../features/observability-and-risk.md).

4. Pin the algorithm a profile may use. A certificate profile is a versioned,
   tenant-scoped rulebook for what may be issued — including the allowed key
   algorithms. To prepare a profile that issues hybrid transition leaves through served
   enrollment protocols, allow the hybrid key label and create it:

   ```sh
   trstctl-cli profiles create -f hybrid-web-30d.json
   ```

   You should see the new profile version created. Editing a profile creates a new
   version while old versions stay queryable, so you always know which rules a past
   certificate was issued under. Profiles are covered in
   [Lifecycle & PQC](../features/lifecycle-and-pqc.md).

5. Prepare a host-bound certificate migration. The selected CBOM
   `certificate-key` asset must contain the SHA-256 fingerprint of the leaf
   actually served at its `location`. Register an enabled host-agent connector
   target with `cert_path`, `key_path`, `verify_address` equal to that location,
   `verify_server_name` equal to the certificate DNS name, and an enrolled
   `required_agent_id`. The host execution profile must allow both file paths
   and, for an ML-DSA TLS listener, name a local OpenSSL 3.5 executable through
   `tls_probe_openssl`.

   Create an active certificate profile allowing `ML-DSA-65`, `serverAuth`,
   the DNS suffix, and the `api` protocol. Create an X.509 identity in
   `requested` state for that name and owner. Its attributes must pin
   `deployment_target_id`, `profile_name`, `subject_key_algorithm: ML-DSA-65`,
   `issuing_authority_source`, and `issuing_authority_id`; bind it to the target
   with `POST /api/v1/identities/{id}/connector-target`. The selected issuing
   authority must be the platform CA or a signer-backed managed private CA.
   A profile requiring distinct issuance approval needs its own approved
   operation before use; migration start will not bypass that control.

   Pick the observed asset ID from `GET /api/v1/cbom/assets`, then send the
   same exact target and identity binding to plan and start:

   ```json
   {
     "asset_ids": ["<cbom-asset-id>"],
     "target_algorithm": "ML-DSA-65",
     "protocol": "host-csr",
     "rollback_on_failure": true,
     "certificate_bindings": [
       {"asset_id": "<cbom-asset-id>", "target_id": "<host-target-id>", "identity_id": "<requested-identity-id>"}
     ]
   }
   ```

   ```sh
   curl -sS \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Content-Type: application/json" \
     -H "Idempotency-Key: pqc-migration-001" \
     -X POST https://trstctl.example.com/api/v1/pqc/migrations \
     -d @pqc-migration.json
   ```

   The response returns a `run_id`, `queued`, `effective_algorithm`, and current
   `migration_progress`. The outbox routes an `endpoint.renew` job to the exact
   enrolled host. The agent first checks the installed certificate and key
   against the CBOM fingerprint and the served leaf, then seals that exact
   predecessor in its encrypted local rollback store. It generates and keeps
   the ML-DSA-65 subject key locally, sends only a CSR to the selected signer,
   installs the returned leaf and key, and signs an independent TLS readback.
   Only the verified signed result changes the CBOM finding to `applied`.
   `trstctl-cli migration plan|start|status|rollback` drives the same Core API.
   The normal host renewal path then rotates the deployed identity without
   moving its subject key into the control plane. Each renewed served leaf gets
   a new signed readback and CBOM fingerprint; rollback is bound to that latest
   verified successor and the original pinned predecessor.

   For CBOM TLS endpoint and host-config findings, use the normal host-agent
   connector lifecycle, independently read the listener's effective TLS policy,
   and rescan before recording remediation. An automatic Envoy TLS migration
   queues an outbox job to the exact enrolled host assigned to the target. The
   host stores the observed predecessor encrypted before changing Envoy, reads
   Envoy's active posture, probes the served listener, and signs the result.
   Rollback restores that predecessor on the same host and probes the listener
   again. For an automatic TLS
   preview, bind each selected TLS finding to the exact enabled deployment
   target with `tls_bindings`: an `asset_id`, `target_id`, and `desired` posture
   containing `minimum_version: "TLSv1.3"`, `cipher_suites: []`, and
   `key_exchange_groups: ["X25519MLKEM768"]`. Envoy's cipher-suite field
   controls TLS 1.2 and earlier; the agent records the actual TLS 1.3 suite
   from the wire. The console asks for these bindings and sends the reviewed
   request unchanged at start. Missing bindings return HTTP 400. An absent or
   mismatched assigned host, management endpoint, or loopback verification
   address returns HTTP 409 before enqueue.

   Name the Envoy target after the exact listener resource exposed by the
   co-resident management API. `secret_name` names its SDS certificate secret;
   it does not choose the listener whose TLS policy is changed. The target's
   `verify_address` is the listener address from the assigned agent's network
   namespace, so a container sidecar uses its container port rather than a
   port published on the Docker host.

6. Verify the served leaf independently with a stock TLS client, then exercise
   rollback before broad rollout:

   ```json
   {
     "asset_ids": ["<cbom-asset-id>"],
     "reason": "canary rollback drill"
   }
   ```

   Submit that payload to the Core rollback endpoint:

   ```sh
   curl -sS \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Content-Type: application/json" \
     -H "Idempotency-Key: pqc-rollback-001" \
     -X POST https://trstctl.example.com/api/v1/pqc/migrations/<run-id>/rollback \
     -d @pqc-rollback.json
   ```

   A host-bound certificate rollback queues a `connector.rollback` job to the
   same agent and target revision. The agent restores the sealed original
   certificate and key, probes the listener, and signs the readback. The run
   becomes `rolled_back` and CBOM returns to its original facts only after that
   receipt is accepted. The managed identity returns to `issued`: its leaf still
   exists, but that leaf is no longer deployed. Read the served leaf again with
   a stock client. A cold restart completes the lifecycle event if the control
   plane stopped after the signed receipt and before that event. Older
   issuance-only runs have no host predecessor and retain their truthful
   `rollback_unverified` state.

7. Set the renewal window the migration will ride on. Migration re-issues
   credentials, and lifecycle thresholds govern when renewal happens. Configure them:

   ```json
   {
     "lifecycle": {
       "renew_before": "720h",
       "alert_before": "168h"
     }
   }
   ```

   You should see `renew_before` (the window before expiry in which trstctl
   re-issues) and `alert_before` (when it warns) take effect. The PQC migration trigger
   creates a managed identity; lifecycle scheduling controls later renewals.

8. Keep what protects your secrets quantum-aware too. Secret material — including
   the key-encryption key that seals everything at rest — lives only in wipeable
   memory and is zeroed after use, and it routes through the same single crypto path,
   so the same agility applies. Protect the KEK in production:

   ```sh
   export TRSTCTL_SECRETS_KEK_FILE=/secure/trstctl-kek.key
   ```

   You should keep the KEK in strong custody (back it with an HSM/KMS in production).
   The envelope-encryption and KEK model is in [Secrets](../features/secrets.md).

## Where next

- [Run trstctl in production](run-in-production.md)
- [Build on the API, CLI, and SDKs](build-on-the-api.md)

**Journey:** J12
**Steps through:** F16, F57, F66
