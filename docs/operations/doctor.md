# `trstctl doctor` — prove tenant isolation on your own deployment

Every vendor asks you to trust their CI. `trstctl doctor` runs the isolation
checks against **your** running deployment instead, and prints a receipt you can
keep. It is a read-only command by default, it exits non-zero when a check
fails, so you can run it in your own pipeline.

This is a **served** command in the shipping `trstctl` binary — not a library, not
a hosted service. It talks to the same PostgreSQL database your control plane
serves from.

## What it actually does

The command opens one connection to your database and runs a fixed list of
probes. Each probe answers one yes/no question about an architecture invariant,
reports `pass`, `fail`, `warn`, or `skip`, and — this is the part that matters —
states what it does **not** prove.

The probes are not a second copy of the test suite. Where a CI test contains the
canonical query, that query was lifted into a shared helper in `internal/store`
(`TenantTableRLSStates`, `USINGOnlyTenantPolicies`), and both the test and the
probe call it. They cannot drift, because there is only one of each query.

A probe that cannot run reports `skip` with the reason. **A skipped proof never
looks like a passed proof.** That rule is why the summary line reports skips
separately, and why the honest answer below is "10 pass, 11 skipped" rather than
a green tick.

## Running it

```bash
trstctl doctor --prove-isolation --write-probe --json receipt.json --sign
```

The database connection comes from `--postgres-dsn`, defaulting to
`$TRSTCTL_POSTGRES_DSN`. Without a DSN the command exits 2.

| Flag | Default | What it does |
|---|---|---|
| `--prove-isolation` | off | Runs the tenant-isolation probe group. All read-only groups run regardless; this flag is accepted for the documented surface. |
| `--write-probe` | off | Permits the two ephemeral probe tenants and the cross-tenant write attempts. **Required for a full proof.** Without it, ISO-3, ISO-4, and ISO-5 report `skip`. |
| `--json PATH` | none | Writes the machine-readable receipt (mode `0600`). |
| `--sign` | off | Signs the receipt with the deployment's existing audit-export key. |
| `--audit-key PATH` | `$TRSTCTL_AUDIT_SIGNING_KEY_FILE`, else `data/audit/signing-key.pem` | The audit key PEM. **Doctor never creates a key** — a missing file is a configuration error, not a reason to mint one. |
| `--signer-socket PATH` | none | Enables the SIG-2 socket posture probe. |
| `--fail-on fail\|warn` | `fail` | The exit-code threshold. |

Exit codes: **0** every probe passed · **1** at least one probe FAILED (or WARNed
under `--fail-on warn`) · **2** a configuration or connectivity error. Gate your
own CI on the exit code; that is the point at which this stops being a demo and
becomes a control.

## The safety model — read this before running it in production

Read-only is the default. The write probes are the only ones that touch data,
and they do so like this:

- **Reserved synthetic tenants.** Probe tenants use the id prefix
  `00000000-d0c7` — deliberately not a real UUIDv4 shape, so they are
  unmistakable in an audit log.
- **Cleanup is verified, not assumed.** ISO-CLEAN deletes the probe rows and then
  re-queries for residue. It reports `pass` only after observing zero rows. The
  test suite induces a mid-probe failure and asserts cleanup still ran.
- **A leaked probe tenant is a FAIL.** ISO-LEAK runs on every invocation,
  including read-only ones. Rows left under the reserved prefix by an earlier
  run fail the current run.
- **Probe activity is ordinary database activity** and may surface in your
  operational monitoring. It is not hidden. If you see two short-lived tenants
  under the reserved prefix, that was doctor.

## What each probe proves, and what it does not

### Tenant isolation (AN-1)

| ID | Proves | Does not prove |
|---|---|---|
| ISO-1 | Every tenant table has RLS `ENABLE`d **and** `FORCE`d, derived live from `pg_class` — never a hard-coded table list | The catalog posture right now, not the absence of RLS-bypassing SQL elsewhere |
| ISO-2 | No tenant policy is `USING`-only; every one carries `WITH CHECK` | Read symmetry, not that each expression is correct |
| ISO-3 | A second tenant's read of another tenant's rows returns zero rows | That the policy held for this table on this path, not that no bug exists anywhere |
| ISO-4 | A cross-tenant upsert-hijack is refused fail-closed and tenant A's row is intact | The one hijack shape attempted |
| ISO-5 | A cross-tenant foreign-key parent reference is rejected | This FK, not every FK |
| ISO-6 | Tenant work runs as the non-owner `trstctl_app` role with a transaction-local `trstctl.tenant_id` GUC, unset outside the transaction | The connection discipline of this client path |
| ISO-7 | *Skipped by design* | The RLS-bypass call-site inventory is pinned by a compile-time CI guard and is not derivable from a running deployment |

### The groups that mostly skip, and why

Doctor holds one seat: the database. That seat cannot honestly answer questions
about the signer process, the event log, or the serving process's memory. Rather
than guess, those probes skip with the reason stated:

- **Signer isolation (AN-4)** — SIG-1 skips because the signer's health RPC
  reports serving status, not a PID. SIG-3 skips because no dependency-closure
  fingerprint is compiled into the signer binary yet; until one is, AN-4's
  closure proof stays in CI (`cmd/trstctl-signer/core_boundary_test.go`). SIG-4
  skips because key-custody proof needs signer API credentials this seat does not
  hold. SIG-2 runs only when you pass `--signer-socket`.
- **Event integrity (AN-2)** — EVT-1 (audit hash chain), EVT-2 (projection
  checkpoint lag), and EVT-3 (read-model rows resolving to source events) all need
  the NATS event stream, which this seat has no credentials for. Verify the audit
  chain through the served audit export instead.
- **Durability and backpressure (AN-5/6/7)** — DUR-2 (outbox lane age) and
  FABRIC-1 (agent job queue age) run from the database. DUR-1, DUR-3, and DUR-4
  live in the serving process; query `GET /api/v1/operations/bulkheads` on the
  running control plane for pool depth.

  **FABRIC-1** sweeps work that is reserved for an agent and that no agent has
  claimed, and warns when the oldest has waited longer than fifteen minutes. It
  names the ROLE the waiting work demands, because that is usually the answer:
  a job stamped for a network relay in a fleet of host-only agents waits
  forever and looks exactly like a busy queue. Age rather than depth is the
  signal, for the same reason as DUR-2 — a deep queue that is draining is
  healthy, and a shallow one that is not is a stopped fabric.

  It is deliberately separate from DUR-2 rather than folded into it. A stalled
  outbox lane means the control plane is not delivering; a stalled agent queue
  means the control plane is correctly not touching the work and the fleet is
  not taking it. Those need different runbooks, and one number reporting both
  would send an operator to the wrong one. **Its limit:** it is an age sweep at
  one instant, over rows an agent is meant to claim. It cannot tell you whether
  a claiming agent is making progress — that is the credential-redemption age
  in `GET /api/v1/operations/jobs` and the `TrstctlCredentialRedemptionStuck`
  alert.

One probe outside those groups always runs: **POSTURE-1** reports the server's
`row_security` setting and version string — the deployment posture that makes the
ISO probes meaningful in the first place. It proves the server has not globally
disabled row security, not that any individual policy is correct.

**Do not read a skip as a weakness being present or absent.** It means doctor did
not look, and says so.

## The receipt

Below is a real receipt from a probe run against a migrated test deployment,
abridged to four probes. Values are as emitted; nothing here is illustrative.

```jsonc
{
  "schema": "trstctl.doctor.v1",
  "generated_at": "2026-08-01T17:31:08.082828Z",
  "deployment": {
    "version": "trstctl dev (commit none, built unknown, darwin/arm64, go1.26.5)",
    "write_probe": true
  },
  "probes": [
    { "id": "ISO-1", "group": "tenant-isolation (AN-1)", "status": "pass",
      "detail": "80/80 tenant tables ENABLE + FORCE row level security",
      "limits": "proves the catalog posture of every tenant table now, not the absence of RLS-bypassing SQL elsewhere",
      "evidence": { "source": "pg_class", "tables_checked": 80 } },
    { "id": "ISO-3", "group": "tenant-isolation (AN-1)", "status": "pass",
      "detail": "cross-tenant read returned 0 rows (expected 0)",
      "limits": "proves the policy held for this table and this path, not that no bug exists anywhere" },
    { "id": "ISO-CLEAN", "group": "tenant-isolation (AN-1)", "status": "pass",
      "detail": "probe tenants fully cleaned up (verified zero residue)" },
    { "id": "SIG-1", "group": "signer-isolation (AN-4)", "status": "skip",
      "detail": "the signer health RPC intentionally reports only serving status, not a PID; separate-process proof stays with the AN-4 dependency-closure gate in CI" }
  ],
  "summary": { "pass": 10, "fail": 0, "warn": 0, "skip": 11 }
}
```

With `--sign`, a `signature` object is appended carrying `alg` `RS256`, `key_id`
`audit-export`, and a compact JWS over the receipt's canonical JSON — the receipt
serialized with the signature field absent. This is the **same key and the same
signing path the audit bundle export already uses**. Doctor introduces no new key
type and no second signing path.

## How this page stays honest

`docs/doctor_doc_test.go` asserts that every probe id the code emits appears in
the tables above, that every flag the command parses is documented, and that the
exit-code contract stated here matches the code. Add a probe without documenting
it and the build fails.
