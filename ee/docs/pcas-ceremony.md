# PCAS ceremony & break-glass runbooks (INT-22)

Operational runbooks for the two highest-consequence PCAS procedures: the **HSM key
ceremony** that stands up (or rotates) an issuing/succession authority key inside a
hardware module (claim 26), and the **break-glass / emergency succession** used when
the normal control plane is unavailable or a forced downgrade is required (claims 17 &
37). Both are rare, irreversible-if-wrong, and quorum-gated.

These runbooks assume the custody model in `pcas-key-custody.md` and the trust
boundaries in `pcas-threat-model.md`. They describe *procedure and controls*, not key
values; no secret material appears here or in any log this process produces.

---

## A. HSM key-ceremony runbook (claim 26)

Purpose: generate a succession authority (or issuer) private key such that the private
key is created **inside** the HSM/module custody boundary, never exists in exportable
form, and is usable by the signer only through the module's `DigestSigner` handle.

### Preconditions

- A quorum of ceremony participants (recommended m-of-n, m ≥ 3) with distinct roles:
  at least one **custodian** per key share, one **operator**, one **witness/auditor**.
- The HSM/module provisioned, firmware-attested, and reachable by the signer host only
  (AN-4: the signer speaks the module protocol and nothing else).
- A clean, offline-capable ceremony host; recording (video + written log) prepared.
- The signer built with the module backend attached (PCAS-22 custody seam), not the
  software backend.

### Roles and separation of duty

- **Custodians** hold module authentication factors (PINs / smartcards / key shares); no
  single custodian can authenticate the module alone.
- **Operator** drives the ceremony script; cannot authenticate without custodians.
- **Witness/Auditor** verifies each step against this runbook and signs the ceremony
  record; takes no operational action.

### Procedure

1. **Open the ceremony.** Witness starts the log; record date, participants, module
   serial, firmware attestation result. Abort if attestation fails.
2. **Authenticate the module** under quorum (custodians present their factors). Confirm
   the module reports the expected authenticated state.
3. **Generate the key in-module.** Instruct the module to generate the authority key of
   the chosen algorithm. The private key is created and retained inside the module; the
   ceremony **must** confirm the key is marked non-exportable / sensitive. If the module
   or policy permits an export flag, the ceremony fails — do not proceed.
4. **Capture only public material.** Export the public key (SubjectPublicKeyInfo DER) and,
   for an issuing authority, produce the self-signed CA certificate via the signer's
   `SelfSignedCACert` over the module `DigestSigner`. Record the public-key fingerprint;
   all participants independently verify it matches.
5. **Bind the key handle to the signer.** Record the module key handle the signer will
   use (e.g. `KeyHandle(identity, epoch)` for a succession key). No private bytes are
   recorded.
6. **Genesis / registration.** Register the authority's genesis (epoch 0) anchor and
   publish the public key + fingerprint through the normal, audited channel. For an
   issuer, this is the trust root RPs will pin.
7. **Seal custody factors.** Custodians re-seal their factors into separate tamper-evident
   storage in separate physical locations. Record seal IDs.
8. **Close the ceremony.** Witness/auditor signs the ceremony record binding: module
   serial + firmware attestation, public-key fingerprint, key handle, participant list,
   seal IDs, and the exact runbook version followed. File the signed record.

### Rotation / succession of an authority key

The same ceremony, plus: generate the successor in-module, then mint a **succession
record** advancing the authority's epoch (predecessor attests, successor possesses).
The predecessor is retired only after the re-wrap-before-retire gate and the evidence
quorum are satisfied (claims 8/15; INT-12/INT-17). Never delete the predecessor handle
before retirement is recorded.

### Failure / abort conditions (any one → abort and file an incident)

- Module firmware attestation fails, or the module cannot prove the key is
  non-exportable.
- Quorum cannot be assembled, or a custodian factor is unavailable.
- Public-key fingerprints do not match across participants.
- Any instruction would place private material outside the module.

---

## B. Break-glass / emergency-succession runbook (claims 17 & 37)

Purpose: perform a succession that the normal path forbids — a **strength downgrade**
(claim 17) or an **emergency/ceremony issuance** while the control plane is unavailable
(claim 37) — under stricter, auditable, single-use authorization, without ever leaving
the ledger or the epoch discipline.

Break-glass is **exceptional, not a bypass**: the record is minted as a distinct chained
record type at the next epoch, carries a mandatory transparency-log inclusion proof, and
its type is bound by the commitment and the signer attestation. RPs apply stricter
policy to it.

### When it applies

- **Forced downgrade** (claim 17): a successor whose algorithm class is weaker than the
  predecessor's — only ever with a valid break-glass token; otherwise the signer and the
  RP both refuse (`ErrStrengthDowngrade` / RP strength refusal).
- **Emergency issuance / ceremony** (claim 37): a control-plane-unavailable issuance or a
  key-ceremony record, minted as a distinct `ceremony`/`emergency` record type.

### Authorization (m-of-n, single-use, request-bound)

1. Convene the break-glass approval quorum (m-of-n, gathered **outside** the signer).
2. The approval authority mints a **single** break-glass token binding the exact
   succession: **identity + tenant + deployment scope + asserted predecessor epoch +
   target algorithm + nonce**. The deployment binding is mandatory (INT-22) so a token
   cannot be replayed into another deployment.
3. The token is authority-signed. The signer verifies the signature and the full binding,
   and **consumes** the nonce in durable single-use state (INT-06), so a replayed token
   after a signer restart is refused.

### Procedure

1. **Declare the emergency.** Open an incident record; capture reason, requesting party,
   and the exact (identity, target algorithm, epoch) being requested.
2. **Assemble quorum and mint the token** as above. Record token nonce and approver set
   (not the signature) in the incident.
3. **Submit the succession request** to the signer with the break-glass token attached.
   The signer verifies binding + single-use, mints the exceptional record at the next
   epoch, and dual-signs it. No private key leaves the signer.
4. **Log for inclusion.** The exceptional record MUST be appended to the transparency log
   and its inclusion proof attached before it is treated as effective — an exceptional
   path that is not logged does not take effect (claim 37 / INV-15).
5. **Notify relying parties** through the normal published channel. RPs accept the record
   only under their stricter exceptional policy (mandatory inclusion + type-binding
   attestation, and — for downgrades — a valid break-glass token they independently
   verify).
6. **Post-incident.** Within the incident SLA: review whether the downgrade/emergency was
   justified, confirm the token was single-use-consumed, confirm inclusion, and schedule
   the forward re-upgrade succession if the downgrade was temporary.

### Controls that make break-glass safe

- **Single-use + request-bound:** a token authorizes exactly one succession and cannot be
  rebound to a different identity, tenant, deployment, epoch, or target (INT-22 closed the
  deployment gap).
- **On-ledger + attributable:** every break-glass/emergency record is logged, type-bound,
  and signer-attested, so it is auditable and its minting signer is nameable.
- **RP stricter policy:** RPs may reject ceremony/emergency records outright or require an
  elevated confirmation; downgrades require independent break-glass verification.

### Failure conditions (refuse / abort)

- Quorum cannot be assembled → no token, no succession.
- Token binding mismatch (identity/tenant/deployment/epoch/target) or reused nonce →
  signer refuses.
- The record cannot be logged for inclusion → do not treat it as effective; investigate.

---

## Change control

Both runbooks are versioned with this file. Any change to the quorum size, the token
binding fields, the custody model, or the RP acceptance policy MUST update this document
in the same change.
