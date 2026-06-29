# Runbook: CA key ceremony (m-of-n)

Generating or rotating a Certificate Authority key is the most consequential
operation in trstctl: whoever controls a CA key can mint trust. trstctl gates
CA-key operations behind an **m-of-n key ceremony** — the key is created only after
a configured number of distinct **custodians** approve — so no single operator can
unilaterally stand up or rotate a CA.

> **Maturity note.** Root and intermediate CA ceremonies are now served over REST,
> including the offline-root flow where trstctl imports only the public root
> certificate, generates a signer-held intermediate CSR, and imports the
> offline-root-signed intermediate. The served path still keeps online CA private
> keys in the isolated signer process and stores only signer handles in the control
> plane; the offline root private key never enters trstctl. Rotation, cross-signing,
> and online break-glass issuance remain library/operator procedures. Break-glass bundle
> reconciliation is served separately at `POST /api/v1/breakglass/reconcile` so
> operators can verify signed emergency bundles into the audit chain after recovery.
> The **assembled issuing CA's key is now persisted, sealed at rest** (R3.2): the
> signer reloads it after a restart, so the CA is not silently rotated (see
> [Configuration -> Signer](../configuration.md#signer-topology--ca-custody) and
> [disaster recovery](../disaster-recovery.md)). Helm `externalKMS` is wired for
> signer key-store envelope custody; non-extractable HSM/KMS-resident CA private
> keys and online break-glass issuance remain future work (see
> [Current limitations](../limitations.md) and the [incident-response
> runbook](incident-response.md)).

## The model

A ceremony has a **purpose** (the exact key operation and resource it authorizes)
and a **threshold** *m*: the number of distinct custodian approvals required.
Custodians approve independently; the CA-key operation is **refused until quorum is
reached** (`ErrQuorumNotMet`), refused if the purpose does not match the requested
operation (`ErrKeyCeremonyPurposeMismatch`), and refused if the ceremony was already
used (`ErrKeyCeremonyNotPending`).

Purpose values are deliberately concrete:

- `root:<sha256-of-ca-spec>` authorizes one new root CA with that exact reviewed
  `CASpec` (common name, constraints, path length, EKUs, and TTL).
- `intermediate:<parent-ca-id>:<sha256-of-ca-spec>` authorizes one intermediate
  under that exact parent with that exact reviewed `CASpec`.
- `offline-root:<sha256-of-root-cert-der>:root:<sha256-of-ca-spec>` authorizes
  importing one public, self-signed offline root certificate that matches the exact
  reviewed `CASpec`.
- `offline-intermediate:<parent-ca-id>:<sha256-of-ca-spec>` authorizes generating
  one signer-held intermediate CSR beneath that imported offline root and importing
  the corresponding offline-root-signed intermediate certificate.
- `import-existing-ca:<signer-handle>:<sha256-of-chain-der>:root:<sha256-of-ca-spec>`
  authorizes importing one existing root/intermediate public certificate chain and
  binding it to the exact signer-held key handle whose public key appears in the
  first certificate.
- `rotation:<ca-id>` authorizes one rotation of that exact CA.
- `cross-sign:<ca-id>:<sha256-of-target-cert-der>` authorizes one cross-signature
  from that CA over that exact target certificate.

The mechanism, in the hierarchy manager:

- `StartCeremony(tenant, purpose, threshold)` opens an m-of-n ceremony and returns
  its id.
- `Approve(tenant, ceremonyID, custodian)` records one custodian's approval and
  returns the running approval count. Approvals are de-duplicated per custodian.
- `CreateRoot` / `CreateIntermediate` / `ImportOfflineRoot` /
  `ImportExisting` / `CreateOfflineIntermediateCSR` /
  `ImportOfflineIntermediate` / `Rotate` / `CrossSign` are **gated on
  purpose-bound quorum**. CA mutations lock the pending
  ceremony, check quorum and exact purpose, and mark it completed in the same
  database transaction as the mutation. `CreateOfflineIntermediateCSR` checks the
  same quorum and purpose before creating the signer-held key, and
  `ImportOfflineIntermediate` consumes the ceremony when the signed certificate is
  accepted. After consumption, that ceremony cannot be reused. Cross-signing is
  gated because it, too, extends trust (it mints a CA certificate under your signing
  CA).

The ceremony and its approvals are tenant-scoped rows under row-level security:
`ca_key_ceremonies` (with the `threshold`) and `ca_ceremony_approvals`.

## Procedure: standing up a new CA

1. **Convene the custodians.** Choose *n* trusted custodians and a threshold *m*
   (e.g. 3-of-5). More than half is the usual floor; pick *m* so that losing a
   custodian does not block operations but a single compromised custodian cannot
   reach quorum alone.
2. **Open the ceremony** for the exact root or intermediate spec. The served route
   is `POST /api/v1/ca/ceremonies` with bearer auth that has `issuers:write` and an
   `Idempotency-Key` header:

   ```json
   {
     "operation": "create_root",
     "threshold": 2,
     "spec": {
       "common_name": "Example Root CA",
       "ttl_seconds": 315360000,
       "signature_algorithm": "ECDSA-P256",
       "max_path_len": 1,
       "permitted_dns_domains": ["example.internal"]
     }
   }
   ```

   For an intermediate, use `"operation": "create_intermediate"` and include
   `"parent_id": "<root-ca-id>"`; the server derives
   `intermediate:<parent-ca-id>:<sha256-of-ca-spec>` from the same request the CA
   operation will execute.
3. **Collect approvals.** Each custodian independently reviews the request and calls
   `POST /api/v1/ca/ceremonies/{id}/approvals` with their own token. The opener is
   not allowed to approve their own ceremony. Every approval is auditable and emits
   `ca.ceremony.approved`.
4. **Create the CA.** Once *m* distinct custodians have approved, call
   `POST /api/v1/ca/authorities/roots` or
   `POST /api/v1/ca/authorities/intermediates` with the `ceremony_id` and the same
   reviewed spec. Before quorum the operation fails closed with `ErrQuorumNotMet`;
   if the ceremony was opened for a different resource, it fails closed with
   `ErrKeyCeremonyPurposeMismatch`.
5. **Distribute trust.** Publish the new CA certificate to relying parties; for an
   intermediate, verify the chain to its parent.
6. **Record the ceremony** in your change-management system alongside the audit
   trail.

After an intermediate exists, leaf issuance is served at
`POST /api/v1/ca/authorities/{id}/issue` with a CSR PEM, the desired validity, and a
token carrying `certs:issue`. The CA private key still signs inside the isolated
signer process; the API returns the issued certificate and chain.

## Procedure: offline root with served intermediate

Use this when the root key lives outside the control plane and only comes online for
ceremonies.

1. **Create the offline root certificate outside trstctl.** Keep the root private key
   on the offline system. Export only the public root certificate PEM.
2. **Open the offline-root import ceremony** with the exact public root certificate
   and reviewed `CASpec`:

   ```json
   {
     "operation": "import_offline_root",
     "threshold": 2,
     "certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
     "spec": {
       "common_name": "Example Offline Root CA",
       "ttl_seconds": 315360000,
       "signature_algorithm": "ECDSA-P256",
       "max_path_len": 1,
       "permitted_dns_domains": ["example.internal"]
     }
   }
   ```

3. **Collect approvals** with `POST /api/v1/ca/ceremonies/{id}/approvals`.
4. **Import the public offline root** with
   `POST /api/v1/ca/authorities/offline-roots`. The request repeats
   `ceremony_id`, `certificate_pem`, and the same reviewed `spec`. The server
   accepts exactly one certificate PEM, rejects private-key PEM blocks, verifies the
   root is self-signed and CA-capable, and stores the authority with no signer handle.
5. **Open the offline-intermediate ceremony** with operation
   `create_offline_intermediate`, `parent_id` set to the imported root authority id,
   and the exact intermediate `CASpec`. Collect the required approvals.
6. **Generate the signer-held CSR** with
   `POST /api/v1/ca/authorities/{offline-root-id}/offline-intermediates/csr`. The
   signer process creates and keeps the intermediate private key; the API returns
   only a CSR PEM plus the signer handle.
7. **Sign the CSR on the offline root system.** Move only the CSR to the offline
   system, sign it as a CA certificate under the offline root, then bring back only
   the signed intermediate certificate PEM.
8. **Import the offline-signed intermediate** with
   `POST /api/v1/ca/authorities/{offline-root-id}/offline-intermediates`. The server
   verifies the certificate chains to the imported offline root, matches the reviewed
   `CASpec`, obeys path-length constraints, and contains the exact public key from
   the signer-held CSR.

After that, leaf issuance uses the imported intermediate at the normal
`POST /api/v1/ca/authorities/{intermediate-id}/issue` route. Leaf issuance directly
from the imported offline root fails closed because the root has no signer handle.

## Procedure: importing an existing signer-backed CA chain

Use this when an existing root or issuing intermediate certificate should become a
served trstctl authority and the matching private key already lives behind a signer
handle. Do not paste private-key PEM into the API or UI.

1. **Pre-provision the signer handle.** The signer must already hold the CA private
   key under a handle constrained to CA signing. The control plane will use only that
   handle and the public key returned by the signer.
2. **Export the public CA chain.** Put the imported authority certificate first,
   followed by its issuer chain up to a self-signed root. For a root import, the
   chain is just the self-signed root certificate. The PEM bundle must contain only
   `CERTIFICATE` blocks.
3. **Open the import ceremony** with the exact chain, signer handle, and reviewed
   `CASpec`:

   ```json
   {
     "operation": "import_existing_ca",
     "threshold": 2,
     "certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
     "signer_handle": "customer-existing-ca",
     "spec": {
       "common_name": "Example Imported Issuing CA",
       "ttl_seconds": 71280000,
       "signature_algorithm": "ECDSA-P256",
       "max_path_len": 0,
       "permitted_dns_domains": ["example.internal"]
     }
   }
   ```

4. **Collect approvals** with `POST /api/v1/ca/ceremonies/{id}/approvals`.
5. **Import the CA** with `POST /api/v1/ca/authorities/imported`. The request
   repeats `ceremony_id`, `certificate_pem`, `signer_handle`, and the same `spec`.
   The server verifies the first certificate is a usable CA, the chain reaches a
   self-signed root, the reviewed profile matches, and the first certificate's
   public key exactly matches the signer-held key. The stored authority contains
   only public chain metadata plus the signer handle.

Leaf issuance then uses `POST /api/v1/ca/authorities/{imported-ca-id}/issue`.

## Procedure: rotating a CA

Rotation is the same ceremony model, but the purpose is bound to the exact CA:
`rotation:<ca-id>`.

1. Open a `rotation:<ca-id>` ceremony with threshold *m* and collect *m* approvals.
2. Run `Rotate` for the CA; it is refused until quorum.
3. If your hierarchy requires cross-signing the new CA, **open a separate
   `cross-sign:<ca-id>:<sha256-of-target-cert-der>` ceremony** and collect its *m*
   approvals — `CrossSign` is refused until quorum and exact target-certificate
   match, exactly like the create/rotate operations. Then distribute the new CA and
   renew issuance under it.
4. Retire the old key per your policy (and per the
   [incident-response runbook](incident-response.md) if the rotation is
   compromise-driven).

## Custodian hygiene

- Custodians should be distinct people with independent credentials; do not let one
  operator hold multiple custodian identities.
- Choose *m* and *n* so the loss of one custodian is recoverable but a single
  compromise cannot mint trust.
- Treat every approval as a logged, attributable action (it is recorded against the
  ceremony).

See [Current limitations](../limitations.md) for the remaining rotation,
cross-signing, non-extractable HSM/KMS-resident CA-key, and online break-glass
issuance gaps, and [Disaster recovery](../disaster-recovery.md) for CA-key loss
handling.
