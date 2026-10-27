# Cryptographic risk and migration assurance

Know which keys and algorithms you run and where, find the weak, distrusted and
quantum-vulnerable ones and what depends on them, decide what to replace first
against published deadlines, move to post-quantum algorithms in waves you can
roll back, and close each migration with signed evidence.

In the console, start at **Posture** (`/posture`); the cryptographic risk report
is on **Policy** (`/policy`). The console home links here.

## How to read the proof column

Each step names the evidence it leaves behind and how strongly it is proved
today. The proof column names the test, so you can read it or run it yourself.

- **Proved end to end**: a test drives the step through the assembled control
  plane (the same handler the binary serves) and checks its effect.
- **Proved on the shipped binary**: a test builds and launches the binary.
- **What comes next**: not built yet; today's status is stated.

## The workflow

| Step | What happens | Evidence it leaves | Proof | Read more |
|---|---|---|---|---|
| Inventory | TLS endpoint and host configuration scans record the keys, algorithms, protocols and ciphers in use. | A cryptographic bill of materials, each asset with where it was seen | Proved end to end: `internal/server/cbom_served_test.go` | [The CBOM](../features/observability-and-risk.md#the-cbom-cryptographic-bill-of-materials-f52) |
| Find weak and distrusted keys | Keys are checked for known weaknesses (shared or small primes, ROCA, small curve scalars, short keys, weak signature hashes) and certificates matched against the distrust list. | Key verdicts and distrust matches, each tied to the certificate or trust store | Proved end to end: `internal/server/weak_key_audit_served_test.go`, `internal/server/agent_inventory_distrust_served_test.go` | [The checks](../security/weak-keys.md#the-checks), [The distrust list](../security/weak-keys.md#the-distrust-list) |
| Prioritize | The cryptographic risk report lists every weak, distrusted or quantum-vulnerable key with what depends on it, its NIST IR 8547 deadline and its plan, in the order to act on, and what changed since the last report. | A signed scheduled report and an on-demand report with CSV export | Proved end to end: `internal/server/crypto_risk_report_served_test.go` | [Cryptographic risk report](../features/lifecycle-and-pqc.md#cryptographic-risk-report) |
| Plan migrations | Migration campaigns and readiness actions group what to replace, with owners, waves and deadlines. | Campaign records, readiness actions and a signed readiness export | Proved end to end: `internal/server/aud65_test.go`, `internal/server/pqc_migration_campaign_served_test.go` | [Core migration campaigns](../features/lifecycle-and-pqc.md#core-migration-campaigns) |
| Issue post-quantum | Certificates are issued with ML-DSA, and SVIDs can carry a classical and a post-quantum key together. | Issued post-quantum certificates their stock clients accept | Proved on the shipped binary: `cmd/trstctl/dod_pqc_runtime_test.go` | [Running your own CA hierarchy](../features/issuance-and-cas.md#running-your-own-ca-hierarchy-f48) |
| Roll out and roll back | Migration runs move trust first, then leaves, and an enrolled host restores its retained predecessor if a wave goes wrong. | Migration runs with each wave's outcome and any rollback | Proved on the shipped binary: `cmd/trstctl/dod_pqc_runtime_test.go`; CA migration runs end to end: `internal/server/migration_run_served_test.go` | [PQC migration orchestration](../features/lifecycle-and-pqc.md#pqc-migration-orchestration-f57) |
| Close with evidence | A campaign closes only when its criteria hold, with a signed closure record. | A signed campaign closure, verifiable offline | Proved end to end: `internal/server/pqc_migration_campaign_served_test.go` | [Post-quantum pilot waves](../features/lifecycle-and-pqc.md#post-quantum-pilot-waves-a28a29) |

## What comes next

- **SLH-DSA certificates.** ML-DSA is served; SLH-DSA X.509 certificates are what
  comes next.
- **The rest of migration orchestration.** Parts of post-quantum migration
  orchestration are still partial; [PQC migration
  orchestration](../features/lifecycle-and-pqc.md#pqc-migration-orchestration-f57)
  says which.
- **CNSA 2.0 dates.** The risk report states the NIST IR 8547 deadlines; it does
  not encode the CNSA 2.0 milestones for national security systems, and says so.
