# PCAS threat model (INT-22)

Proof-Carrying Algorithm Succession (PCAS) lets a non-human identity advance from one
signing/KEM algorithm to a stronger one across a monotonic **algorithm-epoch**, while
every relying party (RP) can verify the identity's current algorithm **offline** from a
chain of dual-signed **succession records**. This document is the security threat model
for that feature: what it protects, the boundaries it relies on, the adversaries it
resists, and the residual risk that is accepted rather than eliminated.

It complements — and does not replace — the product-wide `threat-model.md`, the key
custody note `pcas-key-custody.md` (claims 16 & 26), and the ceremony/break-glass
runbooks in `pcas-ceremony.md`.

## Assets

- **Succession authority.** The ability to mint a record advancing an identity's epoch.
  Compromise lets an attacker install a key they control as an identity's current key.
- **Predecessor / successor / issuer / KEM private keys.** Held only inside the isolated
  signer (or a workload agent, for the workload-held path). Never exported.
- **The epoch floor / last-accepted state.** The monotonic counters (per identity in the
  signer; per identity/authority at the RP) that make downgrade and replay detectable.
- **The transparency log.** The append-only RFC-6962 Merkle log whose signed tree heads
  (STHs) anchor inclusion proofs and make equivocation detectable.
- **Tenant isolation.** Records, floors, and ledger rows are partitioned per tenant
  (AN-1 Postgres RLS); a cross-tenant read or accept is a breach.

## Trust boundaries

PCAS inherits the platform architectural invariants (AN-1..AN-9) and adds succession
semantics on top. The boundaries that carry the most security weight:

- **AN-4 — the isolated signer.** All succession minting and key custody happen inside a
  process that speaks only the signer gRPC contract and links no message bus, SQL driver,
  or HTTP server. The control plane can *request* a succession over `MintSuccessor` but
  cannot forge one, because private key material never crosses the boundary — the RPC
  request carries only handles, and the response carries only public keys and the opaque
  record (claims 1/12/49). Verified by the signer dependency-closure test and the
  `netexec` linter.
- **AN-3 — the crypto boundary.** Only `internal/crypto` imports `crypto/*`. Every PCAS
  hash, signature, and X.509 parse (including `LeafExtensionValue`) routes through it, so
  algorithm handling is a compile-time mapping, never a runtime provider registry — this
  is the design-around and it removes a whole class of provider-substitution attacks.
- **AN-8 — key material.** Predecessor/successor keys live in locked, non-dumpable,
  zeroize-on-destroy buffers (claim 16). See `pcas-key-custody.md`.
- **AN-1 — tenancy.** Every verify/accept path checks tenant (genesis, each chain record,
  staple limbs, recovery/attestation statements).
- **AN-9 — editions.** Succession lives under `ee/`; core never imports it except through
  the tagged, licensed attach seams (`cmd/trstctl-signer`, `cmd/trstctl-agent`).
- **The RP boundary.** An RP is *outside* the deployment's trust: it is given a chain and
  verifies it with no network fetch and no negotiation. The security of the whole scheme
  reduces to "can a forged artifact pass RP verification?"

## Adversaries

1. **A malicious/compromised control plane.** Can call the signer's RPCs and shape
   requests, but cannot obtain key material or advance an epoch the signer's floor does
   not permit.
2. **A network/relay attacker between control plane, signer, agent, and RP.** Can drop,
   replay, or reorder messages and present arbitrary bytes to an RP.
3. **A malicious presenter / relying-party-facing peer.** Holds some valid artifacts and
   tries to get an RP to accept a forged, stale, downgraded, or equivocating posture.
4. **A curious/hostile co-tenant.** Tries to read or influence another tenant's records.
5. **An insider with partial authority** (one approver, one deployment operator) short of
   the m-of-n or dual-control quorum.

## Threats and mitigations

Mapped to the claim / invariant that carries the mitigation.

- **Forge a succession (install an attacker key).** Every record is dual-signed —
  predecessor attestation + successor possession over the same domain-separated
  commitment — and the commitment binds identity/tenant/deployment/epoch/keys. Forgery
  requires the predecessor key, which never leaves the signer (claims 1/4; AN-4/AN-8).
- **Downgrade to a weaker algorithm.** The signer refuses a forward succession to a
  weaker class without a distinct, single-use, request-bound **break-glass** token; the
  RP mirrors the refusal (claim 17 / INV-8). The break-glass token binds
  identity+tenant+**deployment**+epoch+target (deployment binding added in INT-22 after
  security review).
- **Rewind / replay an epoch.** The signer enforces `asserted predecessor epoch == floor`
  and advances a durable floor record-then-activate; the RP refuses a head at or below
  its durable last-accepted epoch (claims 4/13; INT-05). Recovery records — a distinct
  type that bypasses the chain verifier — now also carry an RP `EpochStore` check so a
  captured recovery artifact cannot be replayed to roll posture back (INT-22).
- **Strip the transparency-log proof to hide an off-ledger / equivocating record.**
  Exceptional (revocation/ceremony/emergency) and recovery records require a *real*
  RFC-6962 inclusion proof under a **signed** tree head; the primary chain verifier does
  likewise when inclusion is required. All three fail **closed** without a trusted log
  key — there is no injected-closure or empty-key escape hatch (INT-18; the primary-path
  fail-open was closed in INT-22). Equivocation (two records at one epoch) is detectable
  and attributable by the misissuance monitor (claims 11/28; INT-19).
- **Hide a revocation by flipping a record's type.** The record type is bound in the v2
  commitment, so base chain verification — not just the exceptional-record verifier —
  rejects a type flip (claims 24/36; INT-08/09).
- **Use the signer or agent as a signing oracle.** The workload agent signs only under a
  distinct key-usage purpose, only for its own identity/tenant/deployment, only as its
  own predecessor key, and only over a commitment it **reconstructs itself** from
  structured fields — never attacker-supplied opaque bytes (claim 19; FIG. 5). Enforced
  server-side whether the co-sign arrives in-process or over the transport (INT-16).
- **Escape a delegated-authority constraint.** A succession whose target epoch is below
  the effective ancestor floor is refused inside the signer before keygen, and the
  delegation path is bound in the commitment (claim 33; INT-13).
- **Accept a leaf from a superseded issuer.** End-entity certificates carry the
  `(issuer-epoch, rotation)` tuple in an X.509 extension; the RP rejects a leaf whose
  issuer epoch is below last-accepted (claim 27; INT-14).
- **Cross-tenant read/accept.** AN-1 RLS on storage; explicit tenant checks on every RP
  verify path.
- **Exfiltrate a KEM private key during KEM succession.** The signer generates the ML-KEM
  successor inside its boundary and returns only the public key; the record is publicly
  verifiable via the paired signing key's binding (claim 15; INT-12).
- **Malformed-input denial of service / parser confusion.** The hand-rolled
  length-prefixed decoders (translog proof, agent fields) and ASN.1 parsers bound
  allocations to remaining input, reject trailing bytes, and range-check integer
  narrowing (hardened in INT-22).

## Residual risk (accepted, honest)

- **Live-TLS-handshake stapling is not implemented.** The succession attachment rides in
  a real X.509 certificate extension with absence-as-failure (INT-15), but Go's
  `crypto/tls` exposes no general custom-handshake-extension hook, so inline verification
  during a live TLS handshake is out of scope until a served-stack transport provides it.
- **KEM Variant-A (interactive decap transcript) is not publicly verifiable and is not
  bound to the exact challenge ciphertext.** This is by design: RP acceptance is gated to
  the publicly verifiable Variant-B paired record (`RequirePublicVerifiability` →
  `ErrNotPubliclyVerif`), so Variant A never enters an RP trust decision. Hardening the
  transcript to bind the challenger's ciphertext is a recommended follow-up.
- **Full-stack durability guarantees (RLS, NATS RPO, cross-process signer under load)**
  are asserted by design and unit/integration tests but are proven end-to-end only by the
  Phase-5 e2e gate (INT-20), which provisions real Postgres + NATS + a cross-process
  signer in CI.
- **Policy-decision scope binding is best-effort-when-present.** A signed policy decision
  now binds tenant/deployment when it names them; a decision that omits them still binds
  identity+target. Operators should configure the policy authority to always emit the
  full scope. Dual-control and plan-provenance remain the primary gates.
- **The signer's trust in its host.** AN-8 locks and zeroizes key material, but a root
  attacker on the signer host with live-process memory access is out of scope for
  software custody; the HSM/module custody boundary (claim 26, `pcas-ceremony.md`) is the
  mitigation for that threat.

## Verification

The mitigations above are exercised by the PCAS conformance, differential, fuzz, and
golden-vector gates, the per-card integration tests (INT-01..INT-19), and the
security-review regression tests added in INT-22
(`internal/rpverify/security_hardening_test.go`, the cross-deployment break-glass case in
`internal/succession/minter/strength_test.go`). The architecture linter (`tools/trstctllint`)
enforces AN-3/AN-4/AN-9 on every build.
