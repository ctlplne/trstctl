# Stay crypto-agile and migrate to post-quantum

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
> migration. See [The web console](../web-console.md).

## Before you start

- A running control plane and an API token, set up in
  [Getting started](../getting-started.md).
- The lifecycle, crypto-agility, and PQC-migration model is in
  [Lifecycle & PQC](../features/lifecycle-and-pqc.md); how the key-encryption key and
  secret material are protected is in [Secrets](../features/secrets.md).
- An honest expectation: the served migration trigger covers CBOM certificate-key assets
  first. It queues ACME re-issuance through the outbox and uses a hybrid transition leaf
  for deployability; broader TLS protocol/cipher and every-client pure ML-DSA rollout
  still need protocol and deployment-specific work. See
  [Current limitations](../limitations.md) for served-vs-library detail.

## Steps

1. **Understand the crypto-agility model.** All cryptography in trstctl routes through
   a single isolated path; no other part of the system performs crypto directly, and a
   build check fails the build if anything tries. That is what makes adding or swapping
   an algorithm — including a post-quantum one — a one-place change rather than a
   redesign. The detail is in [Lifecycle & PQC](../features/lifecycle-and-pqc.md).

2. **Know which post-quantum algorithms are available.** Behind that single path,
   alongside classical RSA and ECDSA/Ed25519, these primitives are available:

   - **ML-DSA** (FIPS 204) — the lattice signature, e.g. `ML-DSA-65`.
   - **ML-KEM** (FIPS 203) — key encapsulation for hybrid key exchange.
   - **SLH-DSA** (FIPS 205) — the hash-based signature, e.g. `SLH-DSA-SHA2-128f`,
     the conservative choice for long-lived roots (its signatures are large).
   - **A hybrid** `HybridEd25519Dilithium3` — classical Ed25519 paired with ML-DSA, so
     breaking either component alone does not forge a signature.

   You should pick signing algorithms per certificate profile — large hash-based
   signatures suit roots, not high-volume leaves. ML-KEM is not a certificate signer; it
   is the key-establishment primitive protocols use before they protect traffic. The
   served TLS listeners already prefer `X25519MLKEM768` for TLS 1.3 peers that support
   it, and hybrid transition leaves bind a standard ECDSA P-256 TLS certificate to an
   ML-DSA-44 public key for PQ-aware verifiers. ACME, EST, SCEP, and CMP can issue that
   transition leaf when the CSR carries the hybrid proof.

3. **Inventory the algorithms you run.** A cryptographic bill of materials (CBOM)
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

4. **Pin the algorithm a profile may use.** A certificate profile is a versioned,
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

5. **Start the served PQC migration for certificate-key assets.** Pick the
   `certificate-key` asset ids from `GET /api/v1/cbom/assets` whose
   `migration_target` is `ML-DSA-65`, then queue the migration:

   ```json
   {
     "asset_ids": ["<cbom-asset-id>"],
     "target_algorithm": "ML-DSA-65",
     "protocol": "acme",
     "rollback_on_failure": true
   }
   ```

   ```sh
   trstctl-cli pqc migrations start -f pqc-migration.json
   ```

   The API equivalent is:

   ```sh
   curl -sS \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Content-Type: application/json" \
     -H "Idempotency-Key: pqc-migration-001" \
     -X POST https://trstctl.example.com/api/v1/pqc/migrations \
     -d @pqc-migration.json
   ```

   The response returns a `run_id`, `queued`, `effective_algorithm`, and current
   `migration_progress`. The outbox worker mints a `Hybrid-ML-DSA-44-ECDSA-P256`
   transition certificate through the served ACME/protocol issuer, records
   `protocol.issued` and `pqc.migration.asset_completed`, and updates CBOM progress.

6. **Exercise rollback before broad rollout.** Keep rollback boring and rehearsed:

   ```json
   {
     "asset_ids": ["<cbom-asset-id>"],
     "reason": "canary rollback drill"
   }
   ```

   ```sh
   trstctl-cli pqc migrations rollback <run-id> -f pqc-rollback.json
   ```

   This queues rollback through the outbox and records
   `pqc.migration.rollback_completed`, restoring the original CBOM posture for those
   assets.

7. **Set the renewal window the migration will ride on.** Migration re-issues
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
   still uses the served issuance path directly; lifecycle scheduling controls ordinary
   renewal pressure around it.

8. **Keep what protects your secrets quantum-aware too.** Secret material — including
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
