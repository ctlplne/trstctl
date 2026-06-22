# Database migrations & upgrades

trstctl owns its PostgreSQL schema and applies migrations itself. This page is the
operator runbook for upgrades: how migrations run, why concurrent instances are
safe, the forward-only policy and its safeguard, and the step-by-step upgrade and
rollback procedures.

## How migrations work

The schema is a sequence of numbered SQL migrations (`0001_init.sql`,
`0002_…`, …) embedded in the binary. An applied-versions ledger,
`schema_migrations`, records which have run. On `Migrate`, trstctl applies every
migration not yet in the ledger, **in order**. By default each migration runs
**in its own transaction together with its ledger row** — so if a run is
interrupted, the schema and the ledger stay consistent and the next run resumes
from exactly where it stopped. A migration may opt into
`-- migrate: no-transaction` only for PostgreSQL online DDL that is forbidden
inside a transaction, such as `CREATE INDEX CONCURRENTLY`; those files must be
idempotent before the ledger row is written. Migrations are idempotent where they
create cluster-global objects (for example the RLS role), so a partial run is
safe to retry.

## Concurrent instances are safe (advisory lock)

In a multi-replica deployment, several instances may boot at once and all try to
migrate. trstctl serializes the **entire** migration run on a PostgreSQL
**session-level advisory lock** (`pg_try_advisory_lock` over the same advisory-lock
family as `pg_advisory_lock`, with a fixed key shared by all instances of the
deployment). The first instance to acquire it migrates; any other instance waits by
polling with short try-lock probes until the first finishes, then sees the
migrations already applied and does nothing. This closes the replica-boot race
where two instances could otherwise apply the same migration concurrently and
collide, without leaving blocked waiters in open statement transactions while an
online index build runs.

You can see the lock while a migration is in flight:

```sql
SELECT * FROM pg_locks WHERE locktype = 'advisory';
```

The behavior is verified in CI: a test holds the lock from one session and asserts
`Migrate` waits for it rather than racing ahead, and a second test runs several
instances against one fresh database simultaneously and asserts the schema is
applied **exactly once** with no duplicate ledger rows.

## Forward-only policy and its safeguard

trstctl migrations are **forward-only**: there are no down-migrations. This is a
deliberate choice, not a gap.

- The relational store is a **projection of the event log**. The event log
  is the source of truth; the read model can be **rebuilt** from it at any time
  (see [Backup & disaster recovery](disaster-recovery.md)). Generic, automated
  rollback of arbitrary DDL is fragile theatre by comparison.
- Migrations are written to be **additive and non-destructive** (new tables and
  columns, not drops/renames of live data), so a forward roll is low-risk and an
  upgrade does not silently discard state.

The safeguard for forward-only is a **pre-migration backup gate**. Production
deployments can disable silent auto-migration and require migrations to be an
explicit, backed-up step:

```bash
# Disable automatic migration on boot (production).
export TRSTCTL_MIGRATE_AUTO=false
```

With `TRSTCTL_MIGRATE_AUTO=false`, a control plane that boots and finds pending
migrations **fails fast with guidance** instead of migrating — it will not change
the schema until an operator has taken a backup and applied the migration
deliberately. With the default `TRSTCTL_MIGRATE_AUTO=true` (convenient for
single-node eval and first boot), pending migrations are applied automatically on
startup, still under the advisory lock.

## Upgrade runbook

1. **Read the release notes** for the new version and note any migration callouts.
2. **Inspect the plan** — see exactly what the upgrade will apply, changing
   nothing:

    ```bash
    trstctl --migrate-status
    # -> "no pending migrations"  OR  "N pending migration(s): ..."
    ```

3. **Back up** before applying anything (the gate). Use the full DR artifact so
   the event log, independent PostgreSQL state, signer key store, audit key,
   signer authorization secret, CA certificate, and manifest hashes move together:

    ```bash
    scripts/dr/full-backup.sh /backups/trstctl-pre-migration-$(date +%F)
    # equivalent:
    trstctl --full-backup-dir=/backups/trstctl-pre-migration-$(date +%F)
    ```

4. **Apply the migrations** explicitly (safe to run from one instance; the advisory
   lock makes it safe even if others start):

    ```bash
    trstctl --migrate
    # -> "applied N migration(s)"
    ```

5. **Start (or roll) the new version.** With auto-migration on, simply deploying
   the new binary applies anything still pending on first boot; replicas booting
   together are serialized by the lock.
6. **Verify** `/readyz` is green and spot-check the inventory.

## Rolling back

Because migrations are forward-only, rollback is **restore from the pre-migration
backup**, not a down-migration:

1. Stop the control plane.
2. Restore the KEK from its separate custody backup, then run
   `trstctl --full-restore-dir=<pre-migration artifact>` from step 3.
3. Redeploy the **previous** binary version.
4. Confirm `/readyz` and the inventory.

This is why the backup gate exists: the backup taken before an upgrade **is** the
rollback path.

## Online-safe migrations on populated tables (expand–contract)

Every migration shipped to date creates each index *in the same migration as its
own empty table*, so it takes no meaningful lock — the table has no rows and no
other session is using it. The first migration that must add an index or a column
to a **large, already-populated** table, or change a live column's type, is
different: done naively it takes an `ACCESS EXCLUSIVE` lock for the duration of a
full table rewrite/scan, which stalls every reader and writer of that table — an
outage on a system of record. Use the patterns below, and the migration-safety
guard (a CI test over the embedded SQL) will keep you honest: a lock-heavy
statement against an existing table must either use the online-safe form or carry
a one-line `-- online-safe: <reason>` justification on the statement.

**Add an index → `CREATE INDEX CONCURRENTLY`.** It builds without blocking writes.
It cannot run inside a transaction, so the migration that uses it must be a
**no-transaction migration** (it manages its own statement boundaries) and must be
written to be re-runnable, because a failed `CONCURRENTLY` build leaves an
`INVALID` index that the next run must `DROP ... IF EXISTS` and rebuild:

```sql
-- migrate: no-transaction
-- online-safe: CONCURRENTLY builds without an ACCESS EXCLUSIVE lock; no-tx migration.
DROP INDEX CONCURRENTLY IF EXISTS certificates_expiry_idx;
CREATE INDEX CONCURRENTLY certificates_expiry_idx ON certificates (not_after);
```

**Add a NOT NULL column → add nullable, backfill, then constrain with `NOT VALID`
+ `VALIDATE`.** Adding `NOT NULL` directly (without a constant default) rewrites
the table under a long lock. Instead add the column nullable, backfill in batches,
add a `CHECK (col IS NOT NULL) NOT VALID` (a cheap metadata-only lock), then
`VALIDATE CONSTRAINT` (which scans under a weak `SHARE UPDATE EXCLUSIVE` lock that
does not block writes):

```sql
-- 0040: add nullable + backfill (batched in app code or a follow-up).
ALTER TABLE owners ADD COLUMN IF NOT EXISTS region text;
-- 0041:
-- online-safe: NOT VALID adds the constraint without scanning; VALIDATE scans under
-- a weak lock that does not block writes.
ALTER TABLE owners ADD CONSTRAINT owners_region_not_null CHECK (region IS NOT NULL) NOT VALID;
ALTER TABLE owners VALIDATE CONSTRAINT owners_region_not_null;
```

**Rename or retype a live column → expand–contract, never in place.** A rename or
`ALTER COLUMN ... TYPE` breaks in-flight queries and rewrites the table. Instead:
**expand** (add the new column/shape and have the app dual-write), **migrate**
(backfill), then **contract** (drop the old column) in a *later* release once no
running version reads it. Each step is its own additive, forward-only migration.

Because trstctl is forward-only, there is no down-migration to undo a bad online
change — the [pre-migration backup](#forward-only-policy-and-its-safeguard) is the
only rollback, so rehearse the pattern against a populated copy first.

## Adding a migration (for contributors)

Add a new numbered file to the store's migrations directory (next integer prefix);
never edit or renumber an already-shipped migration, since deployments track
applied versions by number. Keep migrations additive and non-destructive so the
forward-only policy stays low-risk; for a change to a populated table, follow the
[online-safe patterns above](#online-safe-migrations-on-populated-tables-expandcontract)
so it does not take a long `ACCESS EXCLUSIVE` lock. Any new persistent table is
tenant-scoped with row-level security and joins the backup set
([Backup & disaster recovery](disaster-recovery.md)).

See [Configuration → Datastores](configuration.md#datastores) for the Postgres
connection settings these commands use.
