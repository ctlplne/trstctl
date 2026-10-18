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
| `ca-rekey-v2:<sha256-of-authority/spec/reason>` | Re-keying one active signer-backed authority with the exact reviewed profile and lifetime. |
| `cross-sign:<ca-id>:<sha256-of-target-cert-der>` | One cross-signature from that CA over the target certificate. |
| `offline-root-rekey:<sha256-of-authority/successor/both-cross-certs/reason/spec>` | Importing an offline-root successor plus both direction-specific cross-certificates; private keys stay on the disconnected systems. |
| `offline-cross-sign:<sha256-of-authority/target/cross-cert>` | Importing an already-produced offline-root cross-certificate for a target. |

For an externally held intermediate key, create its CSR on the external host and
keep that private key there. In **Certificate authorities → Overview**, open
the active signer-backed parent authority, then **Sign intermediate CSR**.
Paste the public CSR and complete spec, choose **Review CSR ceremony**, and
check the request SHA-256 before opening the two-custodian ceremony. A field
change invalidates that review. Give the ceremony ID to two distinct
custodians, who sign in and approve separately; refresh the ceremony in the
dialog and sign only after it shows 2 of 2. The server binds the parent, exact
CSR and spec to the ceremony purpose and refuses mismatches. The same request
is available through `POST /api/v1/ca/authorities/{id}/intermediates/csr` and
`trstctl-cli ca authorities issue-intermediate-csr`, both with `ceremony_id`.
Save the returned public certificate chain and independently verify that its
leaf public key matches the CSR and that it chains to the selected parent.

In the hierarchy manager, `StartCeremony` opens an m-of-n ceremony and
`Approve` records one de-duplicated custodian approval. **Every procedure below
collects approvals the same way**: each custodian calls
`POST /api/v1/ca/ceremonies/{id}/approvals` with their own token (the opener
cannot approve their own ceremony); every approval is auditable and emits
`ca.ceremony.approved`.

In the console, the opener copies the exact ceremony ID into the change request.
Each custodian signs in with their own identity, opens **Certificate authorities →
Lifecycle**, enters that ID under **Find ceremony by ID**, and selects **Load
ceremony**. They check the purpose, opener, and remaining quorum before selecting
**Approve**. Loading is a tenant-scoped read; knowing an ID never grants approval
permission. A fresh browser session does not inherit another operator's local
ceremony panel.

Before `StartCeremony`, send the exact proposed request to
`POST /api/v1/ca/ceremonies/preview`. This is an effect-free validation step: it
creates no ceremony, key, certificate, event, idempotency record, or external
request. The response gives the normalized public CA spec, tenant-scoped public
authority identity, approval threshold, risks, verification steps, and a request
fingerprint. Certificate PEM, CSR PEM, and signer-handle values are never echoed;
only the names of protected fields appear. Submit the same reviewed body to the
mutation only after the preview reports `ready=true` with empty `preview_writes`
and `preview_external_effects`. The mutation independently rechecks everything.

CA-mutating calls (`CreateRoot`, `Rotate`, `CrossSignAuthority`, and the rest) are
**gated on purpose-bound quorum**: each locks the pending ceremony, checks quorum
and exact purpose, and marks it completed in the same transaction as the
mutation. Consuming a ceremony on success means it cannot be reused; cross-signing
is gated too, since it also extends trust (it mints a CA certificate under your
signing CA).

The ceremony and its approvals are tenant-scoped rows under row-level security:
`ca_key_ceremonies` (with the `threshold`) and `ca_ceremony_approvals`.

## Release one historical managed CA leaf dependency

Use this narrow path only when a managed CA leaf was minted with requester-held
subject-key custody, has expired, and has no managed deployment or later served
observation. Expiry alone cannot prove that an off-product service stopped using
it. The operator explicitly accepts that residual risk; the two custodians
approve the exact public certificate and original mint event. A serial-only
historical dependent, a still-valid leaf, a host-managed leaf, or a leaf with a
managed deployment cannot use this path. Reissue and verify such credentials
instead.

1. Read `GET /api/v1/ca/keys/{id}/retirement` and
   `GET /api/v1/certificates/{certificate_id}`. Keep the certificate ID and its
   public SHA-256 fingerprint. In the console, **Certificate authorities →
   Lifecycle → Release an expired CA leaf dependency** displays those facts.
2. Preview, then start a `release_managed_ca_leaf` ceremony with
   `issuers:write`, a fresh `Idempotency-Key`, and the same body for both calls:

   ```json
   {"operation":"release_managed_ca_leaf","authority_id":"<CA id>",
    "dependent_id":"<certificate id>","expected_certificate_sha256":"<public DER digest>",
    "reason":"expired-requester-custody-external-use-risk-accepted",
    "risk_accepted":true,"threshold":2}
   ```

   Review the returned certificate ID, subject, serial, digest, expiry, mint
   event ID and sequence. The preview writes nothing. Starting the ceremony
   rechecks these facts before its immutable purpose is recorded.
3. Give the ceremony ID to two distinct authenticated custodians. Each loads
   `GET /api/v1/ca/ceremonies/{id}`, checks `release_review`, and approves from
   their own session. The opener cannot approve. The console provides the same
   readback and approval action.
4. After quorum, submit `POST /api/v1/ca/keys/{id}/dependencies/release` with
   `keys:write`, a fresh `Idempotency-Key`, the same certificate ID, digest,
   reason and risk acceptance, plus `ceremony_id`. `trstctl-cli ca keys dependent
   release <id> -f dependent-release.json` sends this body. The result names the
   immutable release event. Read the retirement checklist again and verify that
   the exact dependent is accounted for before requesting key destruction.

The release event binds the original managed-CA mint, the certificate's public
DER hash, the ceremony and all distinct approval event IDs. A PostgreSQL
first-writer command fences cancellation and later approvals before the event
append; restart recovery publishes only that saved event after a lost response.
Its temporary actor and payload are scrubbed after projection, while the
opaque event identity remains for recovery and audit. A mismatched certificate,
tenant, CA, ceremony, reason or risk decision fails closed.

## Procedure: standing up a new CA

1. **Convene the custodians.** Choose *n* trusted custodians and a threshold *m*
   (e.g. 3-of-5); see [custodian hygiene](#custodian-hygiene) below for sizing.
2. **Preview, then open the ceremony** for the reviewed root or intermediate
   spec. First send the body below to `POST /api/v1/ca/ceremonies/preview`.
   Confirm its effect-free receipt, then send the exact same body to
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
   In the console, open **Certificate authorities → Lifecycle → Managed
   intermediate ceremony**. Select the active parent, edit the exact CA spec,
   review the server's normalized spec and effect-free plan, then start the
   ceremony. Give its ID to the two independently signed-in custodians. After
   quorum, open **Authorities → Create intermediate CA** and submit that ID,
   the same parent, and the same reviewed spec. A different parent or spec is
   refused instead of reusing the approval.
3. **Collect approvals** at `POST /api/v1/ca/ceremonies/{id}/approvals` (see
   above).
4. **Create the CA.** Once *m* custodians have approved, call
   `POST /api/v1/ca/authorities/roots` or
   `POST /api/v1/ca/authorities/intermediates` with the `ceremony_id` and the same
   reviewed spec. Before quorum this fails closed with `ErrQuorumNotMet`; for a
   mismatched resource it fails closed with `ErrKeyCeremonyPurposeMismatch`.
   In the console, a successful create closes the form and opens **Overview**
   with the new authority in **Served CA authorities**. Open its details to
   inspect the public certificate, serial, status, and signer reference.
5. **Distribute trust.** Publish the new CA certificate to relying parties.
   Verify: for an intermediate, the chain resolves to its parent.
6. **Record the ceremony** in your change-management system alongside the audit
   trail.

If a pending ceremony is no longer authorized, open it in **Certificate
authorities → Lifecycle**, select **Cancel ceremony**, review its ID, and enter a
reason. The API and CLI use `POST /api/v1/ca/ceremonies/{id}/cancel` with
`{"reason":"change window closed"}` and an `Idempotency-Key`; the CLI form is
`trstctl-cli ca ceremonies cancel <id> -f cancel-ceremony.json`. An
`issuers:write` principal can cancel only a still-pending tenant ceremony. The
result is terminal `cancelled`, preserves all approvals, records the actor and
reason in `ca.ceremony.cancelled`, and cannot be approved or consumed afterward.
Read back the exact ceremony and audit event before opening a replacement.
If event publication or SQL projection is interrupted after the cancellation
fence commits, the ceremony reads `cancellation_pending`. It cannot accept an
approval or sign during that state. The server retries the exact cancellation
event on startup and in its recovery worker; read back `cancelled` before treating
the close as fully recorded. A retry with a different reason is refused.

Leaf issuance (once an intermediate exists) is served at
`POST /api/v1/ca/authorities/{id}/issue` (CSR PEM, validity, a `certs:issue`
token); the CA key still signs inside the isolated signer process.

Before issuing a managed-CA leaf, set `ca.hierarchy_revocation_base_url` to the
operator-owned HTTP(S) **origin** that clients can reach, for example
`https://pki.example.internal`. The matching environment override is
`TRSTCTL_CA_HIERARCHY_REVOCATION_BASE_URL`. trstctl stamps the exact authority
and tenant into each signed leaf's CRL and OCSP URLs:

```text
/crl/{tenant}/authorities/{ca-id}
/ocsp/{tenant}/authorities/{ca-id}
```

Publish those paths at the configured origin without client authentication;
relying parties use them to check status. The built-in issuer's
`ca.crl_distribution_points` and `ca.ocsp_servers` are separate and are never
copied onto a managed-CA leaf. In regulated governance mode, managed-CA leaf
issuance refuses to sign until the hierarchy origin is configured. In standard
mode without this setting, issued leaves omit automatic status pointers;
configure each relying party with the exact issuer endpoints or reissue after
setting the origin.

The signed leaf is inventoried under its exact fingerprint. To revoke it, use
the Certificates console's **Review revocation** action, or select that
certificate ID through `POST /api/v1/certificates/bulk-revoke` with an RFC 5280
reason and an `Idempotency-Key`; the principal needs `identities:write` and
`certs:issue` plus any policy approvals. Read the exact certificate and audit
event again, then get its issuer's URL from `GET /api/v1/revocation/crls`.
Verify the returned DER with `openssl crl -inform DER -in <downloaded.crl>
-noout -text` and verify its signature against the **same managed CA**; use a
stock client configured to enforce that CRL or OCSP response to prove a relying
party rejects the revoked serial. A CA rotation keeps predecessor and successor
status paths separate; never substitute the current CA's CRL for a predecessor.

## Procedure: offline root with served intermediate

Use this when the root key lives outside the control plane and only comes online
for ceremonies.

1. **Create the offline root certificate outside trstctl.** Keep the root private
   key on the offline system. Export only the public root certificate PEM. The
   current import contract accepts an ECDSA P-256 root public key. Set
   `signature_algorithm` to `ECDSA-P256`; the server checks the certificate's
   actual public key against that reviewed choice. For imported certificates,
   `ttl_seconds` is the **maximum remaining validity at import**, so use a value
   at least as long as the certificate's remaining life. The preview and import
   both refuse a certificate that outlives this reviewed horizon.
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
   checks the reviewed key algorithm and remaining-validity cap again, and
   stores the authority with no signer handle.
5. **Open the offline-intermediate ceremony** with operation
   `create_offline_intermediate`, `parent_id` set to the imported root authority,
   and the intermediate `CASpec`; collect approvals as above.
6. **Generate the signer-held CSR** with
   `POST /api/v1/ca/authorities/{offline-root-id}/offline-intermediates/csr`; the
   signer creates and keeps the intermediate private key, returning only a CSR
   PEM plus signer handle. If a failed attempt destroyed this ceremony's signer
   handle, a retry returns `409` with recovery instructions. The signer never
   recreates a destroyed handle: cancel the pending ceremony in Key custody (or
   via the ceremony cancel API), start a new intermediate ceremony, collect fresh
   approvals, and request a new CSR.
7. **Sign the CSR on the offline root system**: move only the CSR over, sign it
   as a CA certificate under the offline root, and bring back only the signed
   certificate PEM.
8. **Import the offline-signed intermediate** with
   `POST /api/v1/ca/authorities/{offline-root-id}/offline-intermediates`; the
   server verifies the certificate chains to the offline root, matches the
   reviewed `CASpec`, obeys path-length constraints, and contains the exact
   public key from the CSR.

Leaf issuance then uses `POST /api/v1/ca/authorities/{intermediate-id}/issue`.
Issuing directly from the imported offline root returns HTTP 409 with the
signer-held intermediate recovery path: its private key is outside trstctl.

## Procedure: prepare a signer-held key for an external CA

Use this path when the child CA key does not yet exist. Keep only public
certificate and CSR bytes in the console or CLI.

1. Obtain the external issuer's public certificate chain, direct issuer first
   through its self-signed root. If that direct issuer is registered as an active
   authority in this tenant, select its exact `parent_id`.
2. Preview and open a `prepare_existing_ca` ceremony with the issuer chain in
   `certificate_pem`, the child `CASpec`, optional `parent_id`, and threshold 2.
   Two distinct custodians approve its exact purpose with their own sessions.
3. Call `POST /api/v1/ca/authorities/imported/csr` with the same issuer chain,
   profile, parent, and ceremony ID. The signer creates a tenant-bound key and
   returns a public CSR and handle. A different idempotency key or a cold restart
   still recovers the first CSR. Read it with
   `GET /api/v1/ca/authorities/imported/csr/{ceremony_id}` after a lost response.
4. Have the external issuer sign that exact CSR as a CA certificate under the
   reviewed profile. Verify the child signature and chain with a stock X.509
   client. Paste only the signed child certificate followed by the exact
   reviewed issuer chain into `POST /api/v1/ca/authorities/imported`, using the
   same ceremony, handle, profile and parent. A changed chain, key, profile or
   parent fails before authority creation.
5. Read the registered authority, issue a leaf and independently verify that
   leaf chains through the imported authority. Record the certificate and
   ceremony audit events.

## Procedure: importing an already-held signer-backed CA chain

Use this when an existing root/intermediate certificate should become a served
trstctl authority whose private key lives behind a signer handle. Never
paste private-key PEM into the API or UI.

1. **Use an already-held signer handle.** The signer holds the CA private
   key under a handle constrained to CA signing; the control plane uses only that
   handle and its public key. If the key is not already held by the signer, use
   the preparation procedure above. The legacy existing-chain import form itself
   does not create or import a private key.
   A handle belongs to one tenant and one approved ceremony on first use. A
   handle already claimed by another tenant or ceremony is refused before a CA
   event is appended. Keep the original ceremony ID for a retry after a lost
   response; starting another ceremony cannot take over its handle.
2. **Export the public CA chain.** Put the imported authority certificate first,
   followed by its issuer chain up to a self-signed root (for a root import, just
   the self-signed root certificate). The PEM bundle must contain only
   `CERTIFICATE` blocks.
3. **Open the import ceremony** with the chain, signer handle, and reviewed
   `CASpec`. When the direct issuer is registered in this tenant, include its
   `parent_id` in this body and the final import body:

   ```json
   {
     "operation": "import_existing_ca",
     "threshold": 2,
     "parent_id": "<registered-direct-issuer-id>",
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
   `ceremony_id`, `parent_id`, `certificate_pem`, `signer_handle`, `spec`). The server
   verifies the first certificate is a usable CA, the chain reaches a self-signed
   root, the reviewed profile matches, and the certificate's public key exactly
   matches the signer-held key. A selected parent must be active and its public
   certificate must exactly match the next certificate in the chain. The stored
   authority holds only public chain metadata plus the signer handle.

The global signer-claim fence survives database backup and restore. Tenant
offboarding removes the tenant owner from that fence but retains a digest-only
denial tombstone, so an orphaned signer key cannot be adopted by another tenant.
On upgrade, existing CA authorities seed the fence; a legacy database that has
already assigned one signer handle to more than one tenant fails migration for
custody review rather than accepting the ambiguous ownership.

Leaf issuance then uses `POST /api/v1/ca/authorities/{imported-ca-id}/issue`.

## Procedure: rotating a CA

Zero-downtime rotation: create or import the successor CA under the normal
ceremony rules, then activate it behind the predecessor's stable issue URL.

1. Create or import the successor CA with the same kind, parent, path-length,
   DNS, and EKU constraints as the predecessor, using whichever ceremony
   procedure above applies.
2. Preview the exact overlap change with
   `POST /api/v1/ca/authorities/{predecessor-id}/rotate/preview` (JSON body:
   `successor_id` and an optional `reason`). It applies the same tenant-scoped
   predecessor/successor eligibility rules as activation, returns only public CA
   identity plus risks and proof steps, and writes no authority or event state.
3. After the receipt names the intended authorities and reports no preview
   effects, send the same body to
   `POST /api/v1/ca/authorities/{predecessor-id}/rotate`. The server marks the predecessor `superseded`, records
   `replaces_id`, emits `ca.authority.rotated`, and keeps the predecessor issue
   URL live while routing new issuance to the successor.
4. Verify both issue URLs: the predecessor URL still answers but its chain now
   verifies to the successor, and the successor URL issues directly.
5. If your hierarchy requires cross-signing the new CA, open a separate
   `cross-sign:<ca-id>:<sha256-of-target-cert-der>` ceremony and collect its *m*
   approvals as above. Submit the ceremony id and target certificate to
   `POST /api/v1/ca/authorities/{issuer-id}/cross-sign`, refused until quorum and
   exact target-certificate match. Recover the same public result later with
   `GET /api/v1/ca/cross-signs/{ceremony-id}` or
   `trstctl-cli ca cross-signs get <ceremony-id>`; that indexed receipt is built
   from the immutable result event and survives a control-plane restart. Existing
   cross-signs from before the receipt projection are recovered by one indexed
   event-ID lookup on first read. The
   console's **CA hierarchy → Lifecycle → Cross-sign a CA** panel can preview,
   open, resume, and execute the same ceremony. For an inventoried target, it
   reviews the first certificate in that authority's PEM chain; a pasted
   external target must contain exactly one certificate. Verify the returned certificate
   independently against the issuer before distributing the new chain.
   Older in-process hierarchy events that recorded only the issuer and ceremony
   have no public certificate to recover; their receipt lookup remains 404.
6. Open **CA hierarchy → Lifecycle → Retirement** or read
   `GET /api/v1/ca/keys/{predecessor-id}/retirement` before requesting key
   destruction. The checklist is rebuilt from immutable CA issuance and
   dependency-completion events. It names each leaf, child CA, or cross-sign
   still tied to the old key; a missing checklist returns 404 rather than an
   empty safe list. A historical serial-only event stays a `serial:` dependent:
   it does not prove a recoverable leaf or subject key. Verify replacement or
   revocation using the original certificate and relying party before accounting
   for it. Retire the old key per your policy (and per the
   [incident-response runbook](incident-response.md) if compromise drove the
   rotation). The isolated signer still refuses destruction until its frozen
   event-set proof is complete.

## Procedure: renewing or re-keying a signer-backed CA

Use re-key to give an authority a fresh CA key/certificate in the same logical
lane. The served path covers signer-backed online roots/intermediates;
offline-root private operations stay outside the binary, though the import path
verifies their public successor and cross-certificates.

1. Read the active authority from `GET /api/v1/ca/authorities`. Copy its
   common name, DNS constraints, EKUs, and path length into the proposed
   spec. Choose a positive lifetime and write the reason before approval.
   Preview the exact body with `POST /api/v1/ca/ceremonies/preview`, then
   start it with `POST /api/v1/ca/ceremonies`:

   ```json
   {
     "operation": "rekey_ca",
     "authority_id": "<ca-authority-id>",
     "threshold": 2,
     "reason": "planned CA renewal",
     "spec": {
       "common_name": "Issuing CA",
       "permitted_dns_domains": ["example.test"],
       "extended_key_usages": ["serverAuth"],
       "max_path_len": 0,
       "ttl_seconds": 7776000,
       "signature_algorithm": "ecdsa-p256"
     }
   }
   ```

   The server checks the supplied profile against the current authority and
   displays the normalized spec, reason, and request fingerprint. The opaque
   `ca-rekey-v2` ceremony purpose binds the authority ID, exact profile,
   lifetime, and reason. A pending legacy `rotation:<ca-authority-id>` ceremony
   cannot authorize this operation; cancel it and start a new one.
2. **Collect approvals** at `POST /api/v1/ca/ceremonies/{id}/approvals`.
3. Activate the re-key with `POST /api/v1/ca/authorities/{id}/rekey`:

   ```json
   {
     "ceremony_id": "<rekey-ceremony-id>",
     "ttl_seconds": 7776000,
     "reason": "planned CA renewal"
   }
   ```

   A changed lifetime, reason, or authority profile is refused with 409; start
   a new ceremony for the revised plan. The server creates a fresh signer-held
   CA key, issues a replacement
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
   Preview and ceremony start verify the active offline predecessor, successor
   profile, and both public cross-signatures before asking custodians to approve;
   a `ready` preview means this package passed the same public checks used at
   activation. Execution still rechecks after approval in case authority state
   or certificate validity changed.
3. **Collect approvals** at `POST /api/v1/ca/ceremonies/{ceremony-id}/approvals`.
4. POST the same public package plus `ceremony_id` to
   `/api/v1/ca/authorities/{predecessor-id}/offline-rekey`. trstctl verifies both
   signatures, overlapping validity, key usages, EKUs, DNS/path constraints,
   subject/public keys, SKI, and AKI before superseding the predecessor and
   recording `ca.authority.rekeyed`.
   In the console, use **Certificate authorities → Imports → Re-key an offline
   root** for the same review, ceremony, approval readback, and activation. If
   the browser loses the activation response, enter the ceremony ID and use
   **Refresh offline-root ceremony**. The durable public result is also at
   `GET /api/v1/ca/offline-rekeys/{ceremony-id}`; it requires read access to both
   predecessor and successor authorities.
5. Verify both returned cross chains with a client independent of trstctl, for
   example `openssl verify`, before distributing either trust path.
6. To import a target CA cross-certificate produced by the new offline root,
   open `operation=import_offline_cross_sign` bound to the successor authority,
   target, and cross-certificate; collect quorum; then POST the same public
   values to `/api/v1/ca/authorities/{successor-id}/offline-cross-signs`.
   Preview and ceremony start verify the offline issuer and public signature
   before a custodian is asked to approve; import repeats that check.
   In the console, use **Certificate authorities → Lifecycle → Import an
   offline-root cross-sign**. Select the active imported offline root, paste
   one public target and one root-signed public cross-certificate, and review
   both certificate hashes and the request fingerprint. Two different
   custodians approve the ceremony from their own sessions. Refresh the
   ceremony before import; a changed certificate disables import. After a
   lost response or browser reload, enter the ceremony ID to recover the
   public cross-certificate from `GET /api/v1/ca/cross-signs/{id}`. Keep the
   offline signing key outside the control plane.

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
   If the HTTP response or browser is lost, run `trstctl-cli breakglass issues
   list` and `trstctl-cli breakglass issues get <ceremony-id>` with a tenant
   credential that has `certs:issue`. The latter returns the exact signed bundle
   projected from `breakglass.issued`; it does not reissue a certificate. The
   Incidents console offers the same readback and bundle/certificate downloads.
   Keep the subject private key that generated the CSR: it is never recoverable
   from trstctl. Verify the recovered bundle against the deployment-pinned
   emergency CA and match its certificate public key to the original CSR.
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
