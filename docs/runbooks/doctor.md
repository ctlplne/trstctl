# Runbook: doctor — prove isolation on your own deployment (OPS-DOCTOR-001)

`trstctl doctor` runs a fixed set of invariant probes against your live
deployment and emits a human report plus a machine-readable receipt. It turns
the tenant-isolation guarantees our CI proves on our infrastructure into
something you can prove on yours, on demand, and hand to an auditor.

The probes reuse the exact shared inventories the CI guards run
(`store.TenantTableRLSStates`, `store.USINGOnlyTenantPolicies`), so the field
probe and the test suite cannot drift apart.

## Contract

```
trstctl doctor [--prove-isolation] [--write-probe] [--json PATH] [--sign]
               [--fail-on fail|warn] [--postgres-dsn DSN] [--audit-key PATH]
               [--signer-socket PATH]
```

- `--postgres-dsn` (or `TRSTCTL_POSTGRES_DSN`) — required; doctor probes the
  same datastore the deployment serves from.
- `--write-probe` — permits the two ephemeral probe tenants and the
  cross-tenant write attempts (ISO-3..ISO-5). Without it those probes report
  **SKIPPED**, never pass: a skipped proof must never look like a passed one.
- `--json PATH` — writes the `trstctl.doctor.v1` receipt.
- `--sign` — signs the receipt with the deployment's existing audit-export key
  (`--audit-key`, default `data/audit/signing-key.pem`). Doctor never creates
  a key; a missing key file is a configuration error. Same key, same RS256
  path as the audit bundle export — no new key type, no second signing path.
- Exit codes: `0` all probes pass · `1` at least one probe FAILS (or WARNs
  under `--fail-on warn`) · `2` configuration or connectivity error. Non-zero
  on FAIL is what lets you gate your own CI on it.

## Safety model

Read-only by default. With `--write-probe`, doctor creates rows under two
ephemeral probe tenants whose ids start with the reserved synthetic prefix
`00000000-d0c7` — unmistakable in an audit log, never a real tenant. Probe rows
are deleted afterwards and the deletion is verified (`ISO-CLEAN`); residue
under the prefix from any prior run fails the next run (`ISO-LEAK`). Probe
activity is ordinary database activity and may appear in your monitoring —
rows under `00000000-d0c7*` are doctor's.

## What each probe proves — and does not

| Probe | Proves | Does not prove |
|---|---|---|
| ISO-1 | every tenant table (derived live from `pg_class`, never a list) both ENABLEs and FORCEs row-level security | the absence of RLS-bypassing SQL elsewhere |
| ISO-2 | no tenant policy is USING-only; every one carries WITH CHECK | the semantic correctness of policy expressions |
| ISO-3 | a second tenant reading the first tenant's row gets zero rows | that no bug exists on any other table or path |
| ISO-4 | a cross-tenant primary-key upsert-hijack is refused fail-closed and the victim row survives | every write path |
| ISO-5 | a cross-tenant foreign-key parent is rejected by the composite tenant-scoped FK | every FK pair; it probes the pattern's reference table |
| ISO-6 | tenant work runs as the non-owner `trstctl_app` role with a transaction-local `trstctl.tenant_id` GUC | server-handler discipline (same `WithTenant` implementation, asserted in CI) |
| ISO-LEAK / ISO-CLEAN | no probe residue before the run; verified zero residue after | — |
| DUR-2 | no outbox lane holds undelivered work older than 15m at this instant | sustained delivery health (see the outbox dead-letters runbook) |
| POSTURE-1 | `row_security=on` and reports the server version | — |
| SIG-2 (with `--signer-socket`) | the signer endpoint is a Unix socket with owner-only mode | the signer's dependency closure |

SKIPPED with stated reasons, deliberately: SIG-1/SIG-3/SIG-4 (separate-process
and dependency-closure proofs live in the AN-4 CI gates; the health RPC
intentionally reports no PID and no closure fingerprint is compiled into the
binary yet), EVT-1..3 (audit-chain and projection-lag checks need event-log
credentials this datastore seat does not hold), DUR-1/3/4 (need the serving
process's API), ISO-7 (the RLS-bypass call-site inventory is a compile-time CI
pin). Each skip says exactly why in its detail line.

## Sample receipt

```json
{
  "schema": "trstctl.doctor.v1",
  "generated_at": "2026-08-01T12:00:00Z",
  "deployment": { "version": "trstctl dev", "write_probe": true },
  "probes": [
    { "id": "ISO-1", "group": "tenant-isolation (AN-1)", "status": "pass",
      "detail": "80/80 tenant tables ENABLE + FORCE row level security",
      "limits": "proves the catalog posture of every tenant table now, not the absence of RLS-bypassing SQL elsewhere",
      "evidence": { "source": "pg_class", "tables_checked": 80 } },
    { "id": "ISO-3", "group": "tenant-isolation (AN-1)", "status": "pass",
      "detail": "cross-tenant read returned 0 rows (expected 0)" }
  ],
  "summary": { "pass": 10, "fail": 0, "warn": 0, "skip": 11 },
  "signature": { "alg": "RS256", "key_id": "audit-export", "jws": "…" }
}
```

The signature covers the receipt serialized with the `signature` field absent;
verify it against the deployment's audit JWKS.

## Why the anti-vacuity tests exist

A green-only proof is not a proof. The doctor test suite breaks real
invariants in a disposable deployment and watches probes go red: dropping
`FORCE` from one table turns ISO-1 red; dropping an isolation policy turns
ISO-3 red — and the probes still clean up after themselves mid-failure. Both
are restored and watched go green in the same test.
