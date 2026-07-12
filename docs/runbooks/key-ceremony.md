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
> plane; the offline root private key never enters trstctl. Zero-downtime successor
> activation, signer-backed cross-signing, offline-root public re-key/cross-sign
> import, and configured online break-glass issue/rotation/cross-sign are all served.
> Online approvals are derived only from authenticated immutable ceremony-event
> actors in the configured roster; execution bodies cannot nominate approvers.
> Bundle reconciliation remains available at `POST /api/v1/breakglass/reconcile`
> so operators can verify signed emergency bundles into the audit chain after
> recovery.
> The **assembled issuing CA's key is now persisted, sealed at rest** (R3.2): the
> signer reloads it after a restart, so the CA is not silently rotated (see
> [Configuration -> Signer](../configuration.md#signer-topology--ca-custody) and
> [disaster recovery](../disaster-recovery.md)). Helm `externalKMS` is wired for
> signer key-store envelope custody; non-extractable HSM/KMS-resident CA private
> key custody remains future work outside the managed-key path (see
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
- `cross-sign:<ca-id>:<sha256-of-target-cert-der>` authorizes one cross-signature
  from that CA over that exact target certificate.
- `offline-root-rekey:<sha256-of-authority/successor/both-cross-certs/reason/spec>`
  authorizes importing one offline-root successor plus both direction-specific
  cross-certificates. The private keys stay on the disconnected root systems.
- `offline-cross-sign:<sha256-of-authority/target/cross-cert>` authorizes importing
  one already-produced offline-root cross-certificate for an exact target.

The mechanism, in the hierarchy manager:

- `StartCeremony(tenant, purpose, threshold)` opens an m-of-n ceremony and returns
  its id.
- `Approve(tenant, ceremonyID, custodian)` records one custodian's approval and
  returns the running approval count. Approvals are de-duplicated per custodian.
- `CreateRoot` / `CreateIntermediate` / `ImportOfflineRoot` /
  `ImportExisting` / `CreateOfflineIntermediateCSR` /
  `ImportOfflineIntermediate` / `Rotate` / `CrossSignAuthority` /
  `RekeyOfflineRoot` / `ImportOfflineRootCrossSign` are **gated on purpose-bound
  quorum**. CA mutations lock the pending
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

Zero-downtime rotation is a two-step model: create or import the successor CA under
the same ceremony rules as any other authority, then activate that successor behind
the predecessor's stable issue URL.

1. Create or import the successor CA with the same kind, parent, path-length, DNS,
   and EKU constraints as the predecessor. This step uses the root/intermediate,
   offline-root, offline-intermediate, or existing-CA import ceremony described
   above, so the new signing key is reviewed before it can issue.
2. Activate the overlap window with
   `POST /api/v1/ca/authorities/{predecessor-id}/rotate` and a JSON body containing
   the `successor_id`. The server marks the predecessor `superseded`, records the
   successor's `replaces_id`, emits `ca.authority.rotated`, and keeps the
   predecessor issue URL live while routing new issuance to the successor.
3. Verify both issue URLs: the predecessor URL should still answer, but the returned
   chain should verify to the successor; the successor URL should also issue
   directly. Already-issued predecessor-chain certificates continue to validate
   until their normal expiry or revocation.
4. If your hierarchy requires cross-signing the new CA, **open a separate
   `cross-sign:<ca-id>:<sha256-of-target-cert-der>` ceremony** and collect its *m*
   approvals. Submit the ceremony id and the exact target certificate to
   `POST /api/v1/ca/authorities/{issuer-id}/cross-sign`; the route is refused until
   quorum and exact target-certificate match. Independently verify the returned
   certificate against the issuer before distributing the new chain.
5. Retire the old key per your policy (and per the
   [incident-response runbook](incident-response.md) if the rotation is
   compromise-driven).

## Procedure: renewing or re-keying a signer-backed CA

Use re-key when the authority should keep the same logical lane but receive a fresh
CA key and certificate. The served path covers signer-backed online roots and
intermediates. Offline-root private operations stay outside the binary, while the
served import path verifies their public successor and cross-certificates.

1. Start a ceremony with `POST /api/v1/ca/ceremonies`:

   ```json
   {
     "operation": "rekey_ca",
     "authority_id": "<ca-authority-id>",
     "threshold": 2,
     "spec": { "common_name": "Reviewed re-key" }
   }
   ```

   The ceremony purpose is `rotation:<ca-authority-id>`, so it cannot be replayed
   against a different CA.
2. Collect approvals with `POST /api/v1/ca/ceremonies/{id}/approvals`.
3. Activate the re-key with `POST /api/v1/ca/authorities/{id}/rekey`:

   ```json
   {
     "ceremony_id": "<rekey-ceremony-id>",
     "ttl_seconds": 7776000,
     "reason": "planned CA renewal"
   }
   ```

   The server creates a fresh signer-held CA key, issues a replacement CA
   certificate with the predecessor's common name, DNS constraints, EKUs, and path
   length, emits `ca.authority.rekeyed`, marks the predecessor `superseded`, and
   records `replaces_id` on the successor.
4. Verify the stable predecessor issue URL and the fresh successor issue URL both
   return chains signed by the fresh successor CA.

## Procedure: re-keying an offline root

The disconnected root system performs every private operation. trstctl receives
only public certificates and refuses a private-key PEM block.

1. On the offline systems, create a self-signed successor root with constraints no
   wider than the predecessor. Produce both cross-certificates: successor signed by
   predecessor, and predecessor signed by successor.
2. Start `operation=rekey_offline_root` at `POST /api/v1/ca/ceremonies`. Bind
   `authority_id`, the successor in `certificate_pem`, the two direction-specific
   certificates in `cross_certificate_pem` and
   `reverse_cross_certificate_pem`, the reason, threshold, and exact `CASpec`.
3. Collect distinct authenticated approvals at
   `POST /api/v1/ca/ceremonies/{ceremony-id}/approvals`.
4. POST the same public package plus `ceremony_id` to
   `/api/v1/ca/authorities/{predecessor-id}/offline-rekey`. trstctl verifies both
   signatures, overlapping validity, key usages, EKUs, DNS/path constraints,
   subject/public keys, SKI, and AKI before it supersedes the predecessor and records
   `ca.authority.rekeyed`.
5. Verify both returned cross chains with a client independent of trstctl, for
   example `openssl verify`, before distributing either trust path.
6. To import a target CA cross-certificate produced by the new offline root, open
   `operation=import_offline_cross_sign` bound to the successor authority, target,
   and cross-certificate; collect quorum; then POST the same public values to
   `/api/v1/ca/authorities/{successor-id}/offline-cross-signs`.

## Procedure: online break-glass issue and CA rotation

Bootstrap the authority through the served `ca ceremonies start` / `ca ceremonies
approve` / `ca authorities create-root` commands while online break-glass is off.
Save the returned certificate and signer handle, derive the public-key file from
that certificate, then enable the online block. Set one tenant, a distinct
operator-subject roster, and a threshold of at least two; see
[Configuration](../configuration.md#break-glass-lifecycle-and-reconciliation).

1. Start an issuance ceremony with `trstctl-cli breakglass issue-ceremony -f
   issue-intent.json`. The intent contains request id, subject, CSR, reason, and TTL,
   but no approver names.
2. Have distinct configured operators run `trstctl-cli ca ceremonies approve
   <ceremony-id>` using their own authenticated tokens.
3. Add only `ceremony_id` to the exact approved intent and run `trstctl-cli
   breakglass issue -f issue.json`. Any changed CSR/reason/TTL, sub-quorum, wrong
   tenant, or reused ceremony fails closed.
4. Rotate with the same two-phase pattern: `breakglass rotation-ceremony`, approvals,
   then `breakglass rotate`. Independently validate the returned new-by-previous and
   previous-by-new cross-certificates and retain both verifier certificates for the
   overlap window.
5. Cross-sign an external target with `breakglass cross-sign-ceremony`, approvals,
   then `breakglass cross-sign`. The target certificate digest is part of the
   ceremony purpose, so swapping the target after approval fails.

## Custodian hygiene

- Custodians should be distinct people with independent credentials; do not let one
  operator hold multiple custodian identities.
- Choose *m* and *n* so the loss of one custodian is recoverable but a single
  compromise cannot mint trust.
- Treat every approval as a logged, attributable action (it is recorded against the
  ceremony).

See [Current limitations](../limitations.md) for the remaining local in-process key
lifecycle and deployment-specific custody qualifications, and
[Disaster recovery](../disaster-recovery.md) for CA-key loss handling.
