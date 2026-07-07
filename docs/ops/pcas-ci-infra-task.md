# PCAS CI infrastructure-provisioning task (INT-20 / INT-21)

This is the actionable engineering task that unblocks the two remaining PCAS harness
gates: **INT-20** (full-stack e2e conformance, no skips) and **INT-21** (observability /
SLO / backpressure). Everything else in the harness (INT-00…INT-19, INT-22, and the
INT-23 production-caller gate + traceability matrix) is landed on `main`. What remains is
not more feature code — it is standing up real infrastructure in CI, wiring the
integration-tested breadth mechanisms into a running binary over that infrastructure, and
flipping two gates from advisory to blocking.

Owner: platform / CI. Estimated: one focused sprint. Definition of done is at the bottom.

## Why this is the blocker

The PCAS "DELIVERED" bar (TRACEABILITY-MATRIX-v2.md) is: *reachable in a running binary
via an integration test over real infrastructure, durable across restart, boundary-clean.*
The core succession loop already meets it — request-succession API → outbox worker → mint
over the isolated cross-process signer → dual-signed record + publish + durable high-water
in one transaction → chain served → offline RP verify — and ships in `cmd/trstctl` /
`cmd/trstctl-signer`. The breadth mechanisms (KEM-through-signer, delegation-in-signer,
issuer real leaves, stapling, retirement worker, recovery/federation, monitors) are real
and integration-tested but reachable today only from `_test.go`. `scripts/
pcas_prod_caller_gate.sh` lists them in its DEFERRED tier; `scripts/pcas_no_skip_gate.sh`
guards against the e2e silently degrading to in-memory. Both go BLOCKING at INT-23 once
the infra exists.

## 1. Infrastructure CI must provide

Most of this already exists in `.github/workflows/ci.yml`; the task is to compose it into
one PCAS full-stack job and make it authoritative.

- **Real PostgreSQL with RLS (AN-1).** The repo uses embedded-postgres (a pinned, scanned
  real PostgreSQL binary; see `scripts/supply-chain/verify-embedded-postgres.sh` and the
  `embedded-postgres-scan` matrix). The PCAS store migrations (`ee/succession/store`) and
  RLS tenant partitioning must run against it — not an in-memory `MemStore`. Confirm RLS
  policies are applied and a cross-tenant read is rejected under a non-superuser role.
- **Real NATS / JetStream (AN-2, AN-6).** `internal/events` runs an embedded NATS in file
  mode and requires a `StoreDir` ("events: embedded nats requires a store dir"). The
  outbox worker, publish consumer, and the ledger the monitors read must run against a
  real JetStream stream with the configured replica/RPO contract, so durability and
  at-least-once redelivery are exercised (not a slice-backed fake).
- **A real cross-process signer (AN-4).** Run `trstctl-signer` as a separate process
  serving `MintSuccessor` (and the agent co-sign service, INT-16) over a Unix domain
  socket (peer-cred) and/or mTLS. The per-job timeout note already anticipates a
  "embedded-PG/NATS/signer integration job." The e2e must dial the signer over the
  transport, never attach the minter in-process.
- **WASM toolchain (INT-07/13 RP parity).** `GOOS=js GOARCH=wasm` build of
  `ee/rpverify/wasm` plus a headless JS runtime (node) so the WASM RP verifier and the Go
  RP verifier can be asserted to agree on the same chain + inclusion proof.
- **A signer host that satisfies the secret-file ownership checks.** The sandbox failure
  `secretfile: parent directory /sessions owner uid 65534` is environmental; the CI signer
  host must own the KEK / auth-secret parent dir so custody setup succeeds.

## 2. INT-20 — full-stack e2e + wire the deferred mechanisms

### 2a. The flagship claim-1 e2e (no skips)

Add `ee/succession/conformance` (or a new `ee/succession/e2e`) test that, with **no
`t.Skip`**, provisions the four real dependencies above and runs the whole loop for a
PCAS-licensed deployment, then verifies the served chain **offline** with both the Go and
WASM RP verifiers. `scripts/pcas_no_skip_gate.sh` already fails if a gate package contains
`t.Skip`, so the e2e must fail loudly when infra is absent rather than degrade.

### 2b. Promotion checklist (each flips one DEFERRED → REQUIRED gate entry)

For each mechanism below: wire it into a running binary's non-test path, add an
integration test over the real infra, then move its entry from the DEFERRED to the
REQUIRED tier in `scripts/pcas_prod_caller_gate.sh` and mark its claim **DELIVERED** in
`TRACEABILITY-MATRIX-v2.md`. The gate will FAIL the moment a DEFERRED symbol gains a
non-test caller — that is the intended forcing function.

| Mechanism (entry point) | Wire it into | Acceptance test |
|---|---|---|
| Recovery mint (`recovery.Mint`) | a recovery API endpoint + worker (m-of-n trust-root authz) | real m-of-n recovery over PG/NATS; RP `VerifyRecovery` accepts with EpochStore replay-defense |
| KEM-through-signer (`kem.MintPairedThroughSigner`) | the served signer keystore path (a KEM key is not a `Signer`; needs a keystore variant that holds ML-KEM handles) | KEM succession over the transport; only public key crosses; re-wrap-before-retire gate blocks retirement |
| Misissuance monitor (`monitor.New`) | a scheduled worker reading the real ledger | inject an epoch collision; worker emits a durable, self-verifying `MisissuanceV1` naming the signers |
| Issuer real leaf (`issuer.IssueLeafCertificate`) | the CA issuance path | issue a real leaf carrying the epoch tuple; RP rejects a superseded-issuer-epoch leaf |
| Stapled leaf (`staple.IssueStapledLeaf`) | a serving/credential-issuance path | present a real cert; RP verifies inline; required-but-absent fails |
| Federation import (`federation.Import`) | the bridge API/worker | import a foreign chain over real infra; bad import quarantines with a signed failure event |
| Delegation constraint (`delegation.NewMinterConstraint`) | the production minter attach (`signerwiring.NewProductionMinter`), loading the RLS-partitioned constraint tree | raise an ancestor floor → descendant identities re-mint; below-floor succession refused in-signer |
| Checkpoint emitter (`succession.SignEpochCheckpoint`) | a scheduled checkpoint worker binding the translog head | checkpoints verify; equivocation between two heads at one epoch detected |
| Posture report (`succession.BuildPostureReport`) | a posture API endpoint | a signed posture report verifies standalone |

Note on KEM and delegation: both carry a small design item beyond wiring — the signer
keystore is signature-oriented (a KEM key is not a `crypto.Signer`), and the delegation
constraint tree needs a real RLS-partitioned config source. Budget for those.

## 3. INT-21 — observability, SLO, backpressure

- Metrics / tracing / structured audit on the mint + retirement hot paths.
- Bounded workers + backpressure (AN-7); rate limits on the succession API.
- A multi-tenant load test at a target QPS over the real stack; a chaos/crash test that
  asserts no double-mint and no floor regression across a signer restart.
- Runbooks under `docs/ops/` (this directory).

## 4. Flip the gates to blocking

Once §1–§3 land, in `.github/workflows/ci.yml`:

- Run `scripts/pcas_no_skip_gate.sh` as a required check (it already exits non-zero on a
  `t.Skip` in the gate packages `ee/succession/conformance ee/succession/signerwiring`).
- Run `make pcas-caller-gate` (→ `scripts/pcas_prod_caller_gate.sh`) as a required check.
  As each mechanism is promoted in §2b, this stays green; if a mechanism is wired but not
  promoted, it fails — keeping the matrix honest.
- Add the PCAS full-stack e2e job to the required set, modeled on the existing
  `compose-e2e` job (EXC-GATE-01) but provisioning PG + NATS + a cross-process signer +
  WASM instead of Pebble/ACME.

## 5. Definition of done (INT-23 green)

- The PCAS full-stack e2e runs over real PostgreSQL (RLS) + real NATS (JetStream) + a real
  cross-process signer (mTLS/UDS) + WASM parity, with **no `t.Skip`**, and is a required
  CI check.
- `scripts/pcas_no_skip_gate.sh` and `scripts/pcas_prod_caller_gate.sh` are required and
  green, with every mechanism promoted from DEFERRED to REQUIRED (or explicitly, and
  visibly, still deferred with a tracked reason).
- `TRACEABILITY-MATRIX-v2.md` shows **DELIVERED** for every claim, each backed by an
  integration test over real infra.
- The existing gates stay green: editions/AN-3 architecture linter, conformance,
  differential verifier, fuzz, and the frozen golden vectors (v1 `86ffbe67…`, v2, and the
  attestation/authz goldens).

## References

- Harness board + card specs: `patent-strategy/pcas-harness/HARNESS-INTEGRATION.md`
- Traceability (DELIVERED semantics): `patent-strategy/pcas-harness/TRACEABILITY-MATRIX-v2.md`
- Gates: `scripts/pcas_prod_caller_gate.sh`, `scripts/pcas_no_skip_gate.sh`
- Security: `docs/security/pcas-threat-model.md`, `docs/security/pcas-ceremony.md`,
  `docs/security/pcas-key-custody.md`
- CI patterns to model on: the embedded-postgres scan matrix and the `compose-e2e`
  (EXC-GATE-01) job in `.github/workflows/ci.yml`
