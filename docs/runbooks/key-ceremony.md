# Runbook: CA key ceremony (m-of-n)

Generating or rotating a Certificate Authority key is the most consequential
operation in trstctl: whoever controls a CA key can mint trust. trstctl gates
CA-key operations behind an **m-of-n key ceremony** — the key is created only after
a configured number of distinct **custodians** approve — so no single operator can
unilaterally stand up or rotate a CA.

> **Maturity note.** Root/intermediate ceremonies, offline-root import,
> zero-downtime rotation, cross-signing, offline-root re-key, and online
> break-glass issue/rotation/cross-sign are all served over REST. Online CA
> private keys stay in the isolated signer process; the offline root key never
> enters trstctl. The issuing CA's key is persisted and sealed at rest
> (R3.2), so the signer reloads it after a restart instead of silently rotating
> the CA (see
> [Configuration -> Signer](../configuration.md#signer-topology-and-ca-custody)
> and [disaster recovery](../disaster-recovery.md)).
> `POST /api/v1/breakglass/reconcile` verifies signed emergency bundles into the
> audit chain after recovery. Helm `externalKMS` wires signer key-store custody;
> non-extractable HSM/KMS-resident custody remains future work (see
> [Current limitations](../limitations.md) and the
> [incident-response runbook](incident-response.md)).

## The model

A ceremony has a **purpose** (the exact key operation and resource it authorizes)
and a **threshold** *m* — the number of distinct custodian approvals required.
Custodians approve independently; the CA-key operation is refused until quorum is
reached (`ErrQuorumNotMet`), refused if the purpose does not match the requested
operation (`ErrKeyCeremonyPurposeMismatch`), and refused if the ceremony was
already used (`ErrKeyCeremonyNotPending`).

Purpose values are deliberately concrete:

| Purpose format | Authorizes |
| --- | --- |
| `root:<sha256-of-ca-spec>` | One new root CA matching the reviewed `CASpec`. |
| `intermediate:<parent-ca-id>:<sha256-of-ca-spec>` | One intermediate under that parent, matching `CASpec`. |
| `offline-root:<sha256-of-root-cert-der>:root:<sha256-of-ca-spec>` | Importing a public, self-signed offline root certificate matching `CASpec`. |
| `offline-intermediate:<parent-ca-id>:<sha256-of-ca-spec>` | Generating a signer-held CSR under the offline root, then importing the signed intermediate. |
| `import-existing-ca:<signer-handle>:<sha256-of-chain-der>:root:<sha256-of-ca-spec>` | Importing an existing certificate chain, bound to the named signer-held key handle. |
| `cross-sign:<ca-id>:<sha256-of-target-cert-der>` | One cross-signature from that CA over the target certificate. |
| `offline-root-rekey:<sha256-of-authority/successor/both-cross-certs/reason/spec>` | Importing an offline-root successor plus both direction-specific cross-certificates; private keys stay on the disconnected systems. |
| `offline-cross-sign:<sha256-of-authority/target/cross-cert>` | Importing an already-produced offline-root cross-certificate for a target. |

In the hierarchy manager, `StartCeremony` opens an m-of-n ceremony and
`Approve` records one de-duplicated custodian approval. **Every procedure below
collects approvals the same way**: each custodian calls
`POST /api/v1/ca/ceremonies/{id}/approvals` with their own token (the opener
cannot approve their own ceremony); every approval is auditable and emits
`ca.ceremony.approved`.

CA-mutating calls (`CreateRoot`, `Rotate`, `CrossSignAuthority`, and the rest) are
**gated on purpose-bound quorum**: each locks the pending ceremony, checks quorum
and exact purpose, and marks it completed in the same transaction as the
mutation. Consuming a ceremony on success means it cannot be reused; cross-signing
is gated too, since it also extends trust (it mints a CA certificate under your
signing CA).

The ceremony and its approvals are tenant-scoped rows under row-level security:
`ca_key_ceremonies` (with the `threshold`) and `ca_ceremony_approvals`.

## Procedure: standing up a new CA

1. **Convene the custodians.** Choose *n* trusted custodians and a threshold *m*
   (e.g. 3-of-5); see [custodian hygiene](#custodian-hygiene) below for sizing.
2. **Open the ceremony** for the reviewed root or intermediate spec:
   `POST /api/v1/ca/ceremonies` with bearer auth carrying `issuers:write` and an
   `Idempotency-Key` header.

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
3. **Collect approvals** at `POST /api/v1/ca/ceremonies/{id}/approvals` (see
   above).
4. **Create the CA.** Once *m* custodians have approved, call
   `POST /api/v1/ca/authorities/roots` or
   `POST /api/v1/ca/authorities/intermediates` with the `ceremony_id` and the same
   reviewed spec. Before quorum this fails closed with `ErrQuorumNotMet`; for a
   mismatched resource it fails closed with `ErrKeyCeremonyPurposeMismatch`.
5. **Distribute trust.** Publish the new CA certificate to relying parties.
   Verify: for an intermediate, the chain resolves to its parent.
6. **Record the ceremony** in your change-management system alongside the audit
   trail.

Leaf issuance (once an intermediate exists) is served at
`POST /api/v1/ca/authorities/{id}/issue` (CSR PEM, validity, a `certs:issue`
token); the CA key still signs inside the isolated signer process.

## Procedure: offline root with served intermediate

Use this when the root key lives outside the control plane and only comes online
for ceremonies.

1. **Create the offline root certificate outside trstctl.** Keep the root private
   key on the offline system. Export only the public root certificate PEM.
2. **Open the offline-root import ceremony** with the public root certificate
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

3. **Collect approvals** at `POST /api/v1/ca/ceremonies/{id}/approvals`.
4. **Import the public offline root** with
   `POST /api/v1/ca/authorities/offline-roots` (same `ceremony_id`,
   `certificate_pem`, `spec`). The server accepts exactly one certificate PEM,
   rejects private-key blocks, verifies the root is self-signed and CA-capable,
   and stores the authority with no signer handle.
5. **Open the offline-intermediate ceremony** with operation
   `create_offline_intermediate`, `parent_id` set to the imported root authority,
   and the intermediate `CASpec`; collect approvals as above.
6. **Generate the signer-held CSR** with
   `POST /api/v1/ca/authorities/{offline-root-id}/offline-intermediates/csr`; the
   signer creates and keeps the intermediate private key, returning only a CSR
   PEM plus signer handle.
7. **Sign the CSR on the offline root system**: move only the CSR over, sign it
   as a CA certificate under the offline root, and bring back only the signed
   certificate PEM.
8. **Import the offline-signed intermediate** with
   `POST /api/v1/ca/authorities/{offline-root-id}/offline-intermediates`; the
   server verifies the certificate chains to the offline root, matches the
   reviewed `CASpec`, obeys path-length constraints, and contains the exact
   public key from the CSR.

Leaf issuance then uses `POST /api/v1/ca/authorities/{intermediate-id}/issue`.
Issuing directly from the imported offline root fails closed (no signer handle).

## Procedure: importing an existing signer-backed CA chain

Use this when an existing root/intermediate certificate should become a served
trstctl authority whose private key lives behind a signer handle. Never
paste private-key PEM into the API or UI.

1. **Pre-provision the signer handle.** The signer holds the CA private
   key under a handle constrained to CA signing; the control plane uses only that
   handle and its public key.
2. **Export the public CA chain.** Put the imported authority certificate first,
   followed by its issuer chain up to a self-signed root (for a root import, just
   the self-signed root certificate). The PEM bundle must contain only
   `CERTIFICATE` blocks.
3. **Open the import ceremony** with the chain, signer handle, and reviewed
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

4. **Collect approvals** at `POST /api/v1/ca/ceremonies/{id}/approvals`.
5. **Import the CA** with `POST /api/v1/ca/authorities/imported` (same
   `ceremony_id`, `certificate_pem`, `signer_handle`, `spec`). The server
   verifies the first certificate is a usable CA, the chain reaches a self-signed
   root, the reviewed profile matches, and the certificate's public key exactly
   matches the signer-held key. The stored authority holds only public chain
   metadata plus the signer handle.

Leaf issuance then uses `POST /api/v1/ca/authorities/{imported-ca-id}/issue`.

## Procedure: rotating a CA

Zero-downtime rotation: create or import the successor CA under the normal
ceremony rules, then activate it behind the predecessor's stable issue URL.

1. Create or import the successor CA with the same kind, parent, path-length,
   DNS, and EKU constraints as the predecessor, using whichever ceremony
   procedure above applies.
2. Activate the overlap window with
   `POST /api/v1/ca/authorities/{predecessor-id}/rotate` (JSON body:
   `successor_id`). The server marks the predecessor `superseded`, records
   `replaces_id`, emits `ca.authority.rotated`, and keeps the predecessor issue
   URL live while routing new issuance to the successor.
3. Verify both issue URLs: the predecessor URL still answers but its chain now
   verifies to the successor, and the successor URL issues directly.
4. If your hierarchy requires cross-signing the new CA, open a separate
   `cross-sign:<ca-id>:<sha256-of-target-cert-der>` ceremony and collect its *m*
   approvals as above. Submit the ceremony id and target certificate to
   `POST /api/v1/ca/authorities/{issuer-id}/cross-sign`, refused until quorum and
   exact target-certificate match. Verify the returned certificate independently
   against the issuer before distributing the new chain.
5. Retire the old key per your policy (and per the
   [incident-response runbook](incident-response.md) if the rotation is
   compromise-driven).

## Procedure: renewing or re-keying a signer-backed CA

Use re-key to give an authority a fresh CA key/certificate in the same logical
lane. The served path covers signer-backed online roots/intermediates;
offline-root private operations stay outside the binary, though the import path
verifies their public successor and cross-certificates.

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
2. **Collect approvals** at `POST /api/v1/ca/ceremonies/{id}/approvals`.
3. Activate the re-key with `POST /api/v1/ca/authorities/{id}/rekey`:

   ```json
   {
     "ceremony_id": "<rekey-ceremony-id>",
     "ttl_seconds": 7776000,
     "reason": "planned CA renewal"
   }
   ```

   The server creates a fresh signer-held CA key, issues a replacement
   certificate matching the predecessor's common name, DNS constraints, EKUs,
   and path length; emits `ca.authority.rekeyed`; marks the predecessor
   `superseded`; and records `replaces_id` on the successor.
4. Verify: both the predecessor and successor issue URLs return chains signed by
   the new successor CA.

## Procedure: re-keying an offline root

The disconnected root system performs every private operation; trstctl receives
only public certificates and refuses a private-key PEM block.

1. On the offline systems, create a self-signed successor root with constraints
   no wider than the predecessor, and produce both cross-certificates
   (successor-by-predecessor and predecessor-by-successor).
2. Start `operation=rekey_offline_root` at `POST /api/v1/ca/ceremonies`. Bind
   `authority_id`, the successor in `certificate_pem`, the two direction-specific
   certificates in `cross_certificate_pem` and `reverse_cross_certificate_pem`,
   the reason, threshold, and exact `CASpec`.
3. **Collect approvals** at `POST /api/v1/ca/ceremonies/{ceremony-id}/approvals`.
4. POST the same public package plus `ceremony_id` to
   `/api/v1/ca/authorities/{predecessor-id}/offline-rekey`. trstctl verifies both
   signatures, overlapping validity, key usages, EKUs, DNS/path constraints,
   subject/public keys, SKI, and AKI before superseding the predecessor and
   recording `ca.authority.rekeyed`.
5. Verify both returned cross chains with a client independent of trstctl, for
   example `openssl verify`, before distributing either trust path.
6. To import a target CA cross-certificate produced by the new offline root,
   open `operation=import_offline_cross_sign` bound to the successor authority,
   target, and cross-certificate; collect quorum; then POST the same public
   values to `/api/v1/ca/authorities/{successor-id}/offline-cross-signs`.

## Procedure: online break-glass issue and CA rotation

Bootstrap the authority via `ca ceremonies start` / `ca ceremonies approve` /
`ca authorities create-root` while break-glass is off; save the certificate and
signer handle, derive the public-key file, then enable the online block (one
tenant, a distinct operator-subject roster, threshold at least two — see
[Configuration](../configuration.md#break-glass-lifecycle-and-reconciliation)).

1. Start an issuance ceremony with `trstctl-cli breakglass issue-ceremony -f
   issue-intent.json`. The intent carries request id, subject, CSR, reason, and
   TTL, but no approver names.
2. **Collect approvals**: distinct configured operators each run
   `trstctl-cli ca ceremonies approve <ceremony-id>` with their own token.
3. Add only `ceremony_id` to the exact approved intent and run
   `trstctl-cli breakglass issue -f issue.json`. Any changed CSR/reason/TTL,
   sub-quorum, wrong tenant, or reused ceremony fails closed.
4. Rotate with the same two-phase pattern: `breakglass rotation-ceremony`,
   approvals, then `breakglass rotate`. Independently validate the returned
   new-by-previous and previous-by-new cross-certificates and retain both
   verifier certificates for the overlap window.
5. Cross-sign an external target with `breakglass cross-sign-ceremony`,
   approvals, then `breakglass cross-sign`. The target certificate digest is part
   of the ceremony purpose, so swapping the target after approval fails.

## Custodian hygiene

- Custodians should be distinct people with independent credentials; do not let
  one operator hold multiple custodian identities.
- Choose *m* and *n* so the loss of one custodian is recoverable but a single
  compromise cannot mint trust.
- Every approval is a logged, attributable action recorded against the ceremony.

See [Current limitations](../limitations.md) for remaining local key-custody
qualifications, and [Disaster recovery](../disaster-recovery.md) for CA-key loss
handling.
