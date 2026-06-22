# Runbook: CA key ceremony (m-of-n)

Generating or rotating a Certificate Authority key is the most consequential
operation in trstctl: whoever controls a CA key can mint trust. trstctl gates
CA-key operations behind an **m-of-n key ceremony** — the key is created only after
a configured number of distinct **custodians** approve — so no single operator can
unilaterally stand up or rotate a CA.

> **Maturity note.** The m-of-n ceremony is implemented and tested as library code
> in the CA hierarchy manager; it is driven today through the Go API, not yet a
> served REST/UI flow. The **assembled issuing CA's key is now persisted, sealed at
> rest** (R3.2): the signer reloads it after a restart, so the CA is not silently
> rotated (see [Configuration → Signer](../configuration.md#signer-topology--ca-custody)
> and [disaster recovery](../disaster-recovery.md)). **HSM/KMS-backed custody** (vs.
> the local sealed key file) and a served, m-of-n break-glass flow remain future
> work (see [Current limitations](../limitations.md) and the
> [incident-response runbook](incident-response.md)). This runbook documents the
> real mechanism and the operating procedure around it.

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
- `rotation:<ca-id>` authorizes one rotation of that exact CA.
- `cross-sign:<ca-id>:<sha256-of-target-cert-der>` authorizes one cross-signature
  from that CA over that exact target certificate.

The mechanism, in the hierarchy manager:

- `StartCeremony(tenant, purpose, threshold)` opens an m-of-n ceremony and returns
  its id.
- `Approve(tenant, ceremonyID, custodian)` records one custodian's approval and
  returns the running approval count. Approvals are de-duplicated per custodian.
- `CreateRoot` / `CreateIntermediate` / `Rotate` / `CrossSign` are **gated on
  purpose-bound quorum**: each takes a `ceremonyID`, locks the pending ceremony,
  checks quorum and exact purpose, and marks it completed in the same database
  transaction as the CA mutation. On success the ceremony is consumed and cannot be
  reused. Cross-signing is gated because it, too, extends trust (it mints a CA
  certificate under your signing CA).

The ceremony and its approvals are tenant-scoped rows under row-level security:
`ca_key_ceremonies` (with the `threshold`) and `ca_ceremony_approvals`.

## Procedure: standing up a new CA

1. **Convene the custodians.** Choose *n* trusted custodians and a threshold *m*
   (e.g. 3-of-5). More than half is the usual floor; pick *m* so that losing a
   custodian does not block operations but a single compromised custodian cannot
   reach quorum alone.
2. **Open the ceremony** for the purpose (`root:<sha256-of-ca-spec>` or
   `intermediate:<parent-ca-id>:<sha256-of-ca-spec>`) with the chosen threshold
   *m*. In code, use `hierarchy.PurposeRoot(spec)` or
   `hierarchy.PurposeIntermediate(parentCAID, spec)` so the purpose is derived
   from the same request the CA operation will execute.
3. **Collect approvals.** Each custodian independently reviews the request (purpose,
   key parameters, the parent CA for an intermediate) and approves. Record who
   approved and when — the approvals are auditable.
4. **Create the CA.** Once *m* distinct custodians have approved, run the create
   (root / intermediate). Before quorum the operation fails closed with
   `ErrQuorumNotMet`; if the ceremony was opened for a different resource, it fails
   closed with `ErrKeyCeremonyPurposeMismatch`.
5. **Distribute trust.** Publish the new CA certificate to relying parties; for an
   intermediate, verify the chain to its parent.
6. **Record the ceremony** in your change-management system alongside the audit
   trail.

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

See [Current limitations](../limitations.md) for what is served by the binary today
versus driven through the Go API, and [Disaster recovery](../disaster-recovery.md)
for CA-key loss handling.
