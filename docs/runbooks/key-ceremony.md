# Runbook: CA key ceremony (m-of-n)

Generating or rotating a Certificate Authority key is the most consequential
operation in certctl: whoever controls a CA key can mint trust. certctl gates
CA-key operations behind an **m-of-n key ceremony** — the key is created only after
a configured number of distinct **custodians** approve — so no single operator can
unilaterally stand up or rotate a CA.

> **Maturity note.** The ceremony is implemented and tested as library code
> (`internal/ca/hierarchy`); it is driven today through the Go API, not yet a
> served REST/UI flow. Persistent CA-key custody (HSM / sealed storage) and a
> served break-glass flow are tracked for a later sprint (see
> [Current limitations](../limitations.md) and the
> [incident-response runbook](incident-response.md)). This runbook documents the
> real mechanism and the operating procedure around it.

## The model

A ceremony has a **purpose** (what key it authorizes — a root, an intermediate, or
a rotation) and a **threshold** *m*: the number of distinct custodian approvals
required. Custodians approve independently; the CA-key operation is **refused until
quorum is reached** (`ErrQuorumNotMet`), and refused again for any operation whose
ceremony has not reached its threshold.

The mechanism, in the hierarchy manager:

- `StartCeremony(tenant, purpose, threshold)` opens an m-of-n ceremony and returns
  its id.
- `Approve(tenant, ceremonyID, custodian)` records one custodian's approval and
  returns the running approval count. Approvals are de-duplicated per custodian.
- `CreateRoot` / `CreateIntermediate` / `Rotate` are **gated on quorum**: each calls
  the internal `requireQuorum` check first and returns `ErrQuorumNotMet (k of m
  approvals)` until *m* distinct custodians have approved. On success the ceremony
  is marked complete and cannot be reused.

The ceremony and its approvals are tenant-scoped rows under row-level security
(AN-1): `ca_key_ceremonies` (with the `threshold`) and `ca_ceremony_approvals`.

## Procedure: standing up a new CA

1. **Convene the custodians.** Choose *n* trusted custodians and a threshold *m*
   (e.g. 3-of-5). More than half is the usual floor; pick *m* so that losing a
   custodian does not block operations but a single compromised custodian cannot
   reach quorum alone.
2. **Open the ceremony** for the purpose (root or intermediate) with the chosen
   threshold *m*.
3. **Collect approvals.** Each custodian independently reviews the request (purpose,
   key parameters, the parent CA for an intermediate) and approves. Record who
   approved and when — the approvals are auditable.
4. **Create the CA.** Once *m* distinct custodians have approved, run the create
   (root / intermediate). Before quorum the operation fails closed with
   `ErrQuorumNotMet`.
5. **Distribute trust.** Publish the new CA certificate to relying parties; for an
   intermediate, verify the chain to its parent.
6. **Record the ceremony** in your change-management system alongside the audit
   trail.

## Procedure: rotating a CA

Rotation is the same ceremony, with `purpose = rotation`:

1. Open a rotation ceremony with threshold *m* and collect *m* approvals.
2. Run `Rotate` for the CA; it is refused until quorum.
3. Cross-sign or chain as your hierarchy requires, distribute the new CA, and renew
   issuance under it.
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
