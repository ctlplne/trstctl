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

## Applied migrations are content-checksummed (OPS-MIG-CKSUM-001)

The ledger records **what** ran, not merely that something ran. Alongside
`version` and `applied_at`, `schema_migrations` carries:

| column | meaning |
| --- | --- |
| `name` | the migration filename applied under this version |
| `checksum` | `sha256:<hex>` of that file's content |
| `checksum_adopted_at` | non-NULL if the digest was *adopted* rather than *observed at apply time* |
| `execution_plan` | non-NULL when a checksum-bound compatibility plan ran instead of the original transactional SQL |
| `execution_checksum` | digest of that plan’s ordered DDL, including conditional recovery steps |

On every run, before applying anything, the runner re-hashes each embedded file
whose version is already in the ledger and compares:

- **Digest matches** — nothing to do; the migration is not re-run.
- **Digest differs** — the run **fails closed** and the node does not start. A
  shipped migration was edited in place, so this node's schema and the file the
  binary is reading are no longer the same artefact, and the binary cannot know
  which half of the edit ran here.
- **A different filename claims an applied version** — the run fails closed with
  a version-collision error. This used to be a silent skip: the colliding
  migration never ran and nothing said so. Extension migrations must use the
  reserved `>= 900000` band.

The digest is taken over the file with line endings normalized to `\n` and
trailing newlines trimmed, so the same file checked out under a different
`core.autocrlf` does not read as an edit.

### Upgrading an existing install (no backfill step, no brick)

Deployments installed before checksums existed have ledger rows with
`checksum IS NULL`. The first run of a checksum-aware binary **adopts** the
on-disk digest for those rows and stamps `checksum_adopted_at` — it does not
fail. The upgrade is therefore an ordinary rolling upgrade: no data migration,
no manual backfill, no downtime, and no new flag.

Adoption is honest about its limit: it makes today's files the baseline and
closes the window from here on; it **cannot** detect an edit made *before* the
upgrade. The stamp is how you find the rows that carry that caveat:

```sql
SELECT version, name, checksum_adopted_at
  FROM schema_migrations
 WHERE checksum_adopted_at IS NOT NULL
 ORDER BY version;
```

Rolling *back* to a pre-checksum binary is also safe: the three columns are
nullable, the older binary ignores them, and the newer binary adopts
whatever the older one recorded on the next boot.

### If a node refuses to start (break-glass)

A mismatch stops the rollout with the previous nodes still serving — that is the
intent, not a failure of the upgrade. Do not reach for the override first:

1. **Diff the migration file** against the shipped release. If it was edited,
   revert the file and redeploy. Do not "fix" the ledger.
2. Only if you have **confirmed this node's schema is the one you want** — for
   example you knowingly hand-patched it — clear the recorded identity so the
   next boot re-adopts the current file. The re-adopted row is stamped and shows
   up in the query above:

    ```sql
    UPDATE schema_migrations SET name = NULL, checksum = NULL WHERE version = <N>;
    ```

There is deliberately no environment variable or flag for this: re-adoption is a
per-version, audited write to the ledger, not a switch that can be left on.

## Online execution of historical index migrations

Pending migrations `0211_connector_rollback_projection_order.sql` and
`0219_notification_delivery_routing.sql` build their indexes concurrently so a
populated control plane can continue database writes during index construction.
Their shipped SQL files and original checksums remain unchanged. A database that
already applied either file keeps its ledger row; startup does not re-run it.

For a pending version, the runner first matches the immutable file digest. It
commits the additive column expansion in a short transaction, then builds the
index outside a transaction with `CREATE INDEX CONCURRENTLY`. Migration 0211
adds its nonnegative-sequence check as `NOT VALID` and validates existing rows
after the index is ready. Existing tenant evidence and conservative defaults
are preserved. The five-second lock-wait limit still applies: column expansion
can briefly require an exclusive table lock, and long-running writers can make
a concurrent build wait. This is not a promise of a lock-free upgrade.

An interruption before the ledger insert is safe to retry. The runner checks
column types, defaults and constraints before using a completed expansion, and
checks the index’s table, columns, predicate, method and validity. It reuses an
exact valid index or drops and rebuilds an exact invalid index concurrently.
A same-name object with a different definition, partial column expansion, or
changed migration file causes startup to refuse the upgrade. Do not clear the
ledger or replace a conflicting object blindly; inspect the reported schema
and restore the expected definition before retrying the normal migration step.

Only after the columns, ready index and validated constraint are verified does
the runner record the original filename/checksum with
`execution_plan='historical-online-v1'` and the separate plan digest. That digest
identifies the DDL strategy, including conditional retry steps; it does not claim
that every statement was executed on every retry. Older transactional installs
retain NULL execution provenance rather than receiving invented history.

## SCIM subject bindings (0220–0221)

Migration 0220 adds nullable SCIM identity metadata without rewriting existing
membership rows. Legacy members remain unbound until explicitly provisioned.
Its object-shape check is added without scanning existing rows under the column
expansion's exclusive lock.

Migration 0221 builds the case-insensitive username index concurrently, scoped to
each tenant, then validates the object-shape check. Membership writes can continue
during the index build. An interrupted build is retried by dropping and rebuilding
the index concurrently; the migration ledger is written only after the index is
valid. Conflicting usernames prevent startup rather than silently weakening the
uniqueness rule. Inspect and reconcile the conflicting provisioning identities
before retrying. The usual pre-upgrade backup and bounded lock waits still apply.

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

### Migration 0153 requires a stopped control-plane fleet

Migration `0153_secret_sync_target_order.sql` is deliberately not a rolling
upgrade. It replaces database-allocation order with the immutable event sequence
for each tenant+secret-sync target. An old API process can still create a legacy
compatibility-queue row, and an old worker can select a newer same-target row
without the event-order predicate. The database trigger is a fail-closed safety
net for an old claim statement; it is not a liveness-compatible mixed-version
mode.

Before applying 0153:

1. Quiesce old-release producers first: put the control-plane ingress into
   maintenance/read-only mode and block every API or automation path that can
   enqueue a new `secret.sync.*` command. Keep the old worker processes running
   so already-recorded commands can drain. Do not start a new-release replica and
   do not use a rolling Deployment update.
2. While those old workers are still running, drain and reconcile through the
   supported old-release workflow until there are zero
   `secret_sync_jobs.status = 'pending'` commands. Never manufacture a terminal
   state with SQL: only a retained delivered/failed event may remove a FIFO
   barrier. A terminal job whose outbox row is still `pending` is the one
   recognized crash shape and may remain; the new worker acknowledges that cleanup
   row with zero receiver I/O. The migration refuses an active compatibility row
   without a projected job, malformed command binding, missing terminal pair, or
   any other job/outbox disagreement. PostgreSQL ids are not event or commit order,
   so do not infer safety from them.
3. Stop or scale to zero the final old control-plane process. Leave PostgreSQL,
   JetStream, and the signer running. After it has stopped, confirm no secret-sync
   claim remains in flight:

    ```sql
    SELECT tenant_id, id, destination, worker_id, lease_until
      FROM outbox
     WHERE status = 'processing'
       AND left(destination, 12) = 'secret.sync.';
    ```

   The result must contain zero rows. If it does not, keep producers quiesced,
   restart only the old release, let the lease expire or the old worker finish,
   reconcile it, then stop that last old process and repeat this check. Never run
   0153 while an old process is alive.
4. Reconfirm both the zero-pending-job condition from step 2 and the zero-processing
   condition from step 3. Then take the normal full pre-migration backup, run
   `trstctl --migrate` as a
   standalone maintenance step, and verify migration 0153 is recorded.
5. Start one new-release control plane and require its full retained-history
   validation to pass. Startup compares every terminal SQL fact with the canonical
   JetStream event and upgrades migration receipts only after exact evidence
   agreement. A mismatch fails closed before secret-sync workers start. Once that
   node is healthy, scale the rest of the new fleet normally.

The migration also installs command-global receiver authority on each secret-sync
outbox row. Receiver-start count only increases; `effect_possible` can become
failed authority only for the first and still-only typed no-network start. The
closed failure and its attempt count are frozen together. This state is included in
the independent PostgreSQL artifact. Restoring an older artifact never derives
secret-sync order from the outbox id: it must join the exact event-rebuilt job or
the restore fails closed.

An inherited failed command, or an inherited delivered command with more than one
old claim attempt, has no pre-0153 receiver-start receipt. Migration preserves that
uncertainty as `effect_possible`. The new worker may retire a leftover pending
outbox row with zero receiver I/O, but the terminal job remains a target-wide FIFO
barrier: a fresh command is recorded but cannot overtake it. Keep the target
blocked and escalate for provider-specific authenticated readback/reconciliation;
generic trstctl code cannot invent that proof, and tenant offboarding also refuses
while the possible receiver generation is unresolved. Do not edit the historical
row into `failure_authorized`. A single-attempt inherited delivery is the only
legacy terminal shape that releases a successor without additional reconciliation.

If 0153 fails its preflight, its transaction commits neither schema nor backfill.
Keep the fleet stopped, reconcile the exact reported secret-sync state using the
old release, and retry the migration from the beginning.

### Secret-sync recovery-authority migration 0162

Migration `0162_secret_sync_recovery_authority.sql` adds one deployment-local
singleton row. It is not tenant data and it is not copied from a source backup.
Think of it as a red/green power light for external secret-sync writes: normal
upgrades create it green, while an event-log restore turns it red before mutating
the recovered stream. Events contain the sealed command and terminal outcome, but
not the exact PostgreSQL receiver-start count, so an event-only target must not
perform receiver I/O.

The application role has no privileges on this table. The offline full-restore
coordinator is the only production path that may rebuild while red; that exception
does not bypass the receiver-start check. It imports and stably reconciles the
paired outbox authority, completes a final event replay, validates retained
history, and then turns the row green before readiness. If restore stops anywhere
earlier, leave the row red and resume the same full artifact. Do not manually
`UPDATE secret_sync_recovery_authority`: doing so converts missing external-effect
evidence into permission to write.

### Scheduled-rotation authority migrations 0155 and 0157

Migration `0155_secret_rotation_schedule_commands.sql` is transactional and adds
only new receiver tables, RLS policies, grants, and constraints. It creates the
per-due-edge child command, the one-row-per-tenant fair cursor, and the per-outer-key
tick that retains its database cutoff, row-start snapshot, ordered receipt, logical
budgets, and terminal response bytes. The tick has a composite foreign key to the
exact tenant/idempotency key with `ON DELETE CASCADE`; it has no foreign key to the
event-rebuilt schedule projection. Existing schedule rows and idempotency rows are
not rewritten.

Migration
`0157_secret_rotation_schedule_scan_index_no_transaction.sql` adds the UUID-ring
scan index to the already-populated `secret_rotation_schedules` table. It is a
no-transaction migration: the runner keeps the deployment-wide advisory lock but
runs `DROP INDEX CONCURRENTLY IF EXISTS` followed by `CREATE INDEX CONCURRENTLY`.
That means normal schedule writes can continue during the build, and retry after an
interrupted build first removes PostgreSQL's possible invalid same-name index. The
ledger row is written only after the valid build succeeds. No special fleet stop is
required for 0155 or 0157 beyond the normal pre-migration full backup gate.

### Scheduled-rotation history sanitation (application cutover)

The schema-v1 `secret.rotation_schedule.ran` error closure is an event-history
generation change, not a PostgreSQL migration and not migration 0163. Before the
new release starts, stop every older control-plane, worker, federation importer,
and export process that can touch this history. Set
`TRSTCTL_SECRET_ROTATION_HISTORY_FLEET_READY=true` only after that fleet-wide
quiescence is real, then start one new binary.

That binary takes the deployment-wide history operation/cutover walls, scans the
complete retained generation, and writes one deterministic signed rewrite per
affected tenant in sorted order. It replaces only an unsafe JSON `error` token;
sequence, envelope identity, subject, message ID, and every unrelated byte stay
fixed. Startup scans again before projection catch-up and installs a normal
append/import floor that rejects future v1 scheduler-run events. A crash resumes
through the existing generation-recovery proofs. If the assertion is absent,
history is malformed, signing/audit/backup fencing is unavailable, or any unsafe
record remains, the node stays unready and returns no legacy detail.

Live sanitation cannot alter an event export, backup, or signed/WORM audit archive
already copied elsewhere. Retain or destroy those artifacts under their existing
custody and retention policy; do not claim that this cutover erased them.

## Upgrade runbook

1. **Read the release notes** for the new version and note any migration callouts.
2. **Inspect the plan** — see exactly what the upgrade will apply, changing
   nothing:

    ```bash
    trstctl --migrate-status
    # -> "no pending migrations"  OR  "N pending migration(s): ..."
    ```

3. **Back up** before applying anything (the gate). Use the full DR artifact so
   the event log, independent PostgreSQL state, signer key store (including the
   sealed audit-evidence key),
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

5. **Start (or roll) the new version.** With auto-migration on, deploying
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

Indexes created with their own new empty table take no meaningful data lock. An
index added to an **already-populated** table is different: a normal build blocks
writes while it scans the table. Migration 0157's schedule UUID-ring index is the
concrete shipped example of the safe form below. The same rule applies to adding a
column or changing a live column's type when that operation can rewrite or scan a
large table. Use the patterns below, and the migration-safety guard (a CI test over
the embedded SQL) will keep you honest: a lock-heavy statement against an existing
table must either use the online-safe form or carry a one-line
`-- online-safe: <reason>` justification on the statement.

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
applied versions by number. This is no longer only a convention: the runner
records a content digest per applied version and refuses to start on a mismatch
(see [Applied migrations are content-checksummed](#applied-migrations-are-content-checksummed-ops-mig-cksum-001)). Keep migrations additive and non-destructive so the
forward-only policy stays low-risk; for a change to a populated table, follow the
[online-safe patterns above](#online-safe-migrations-on-populated-tables-expandcontract)
so it does not take a long `ACCESS EXCLUSIVE` lock. Any new tenant data table is
tenant-scoped with row-level security. A rare deployment-wide system singleton,
such as the 0162 restore light, must document its AN-1 exemption and expose no
tenant payload. Every new table joins the backup classification
([Backup & disaster recovery](disaster-recovery.md)).

See [Configuration → Datastores](configuration.md#datastores) for the Postgres
connection settings these commands use.

Migration 0168 adds the tenant-RLS `ownership_readiness_exceptions` event
projection and nullable owner verification-binding columns. Migration 0169 builds
the populated-owner cadence index concurrently in a no-transaction migration, so
upgrading does not stop owner writes while PostgreSQL scans existing rows.

Migration 0196 adds `ownership_assignments`, the tenant-RLS current projection for
asset-specific accountability decisions. The table stores only canonical inventory
ID, effective owner, event ID, event sequence, and assignment time. The attributed
reason and authenticated actor remain in the immutable `ownership.assigned` event.
Its bounded IDs and non-negative sequence constraints reject malformed projection
rows, and deleting an otherwise-unreferenced owner removes only this current
override; immutable history remains in the event log.

## Bounded lock waits (OPS-MIG-LOCK-001)

The migration runner pins its session to `lock_timeout = 5s`,
`statement_timeout = 0`, and `idle_in_transaction_session_timeout = 60s`.
A lock-heavy DDL that cannot acquire its table lock fails fast with SQLSTATE
`55P03` instead of queueing behind live traffic (where every later statement
would queue behind the waiting ACCESS EXCLUSIVE). Statement runtime stays
unbounded on purpose: legitimate migrations (`CREATE INDEX CONCURRENTLY` on a
large table) run long — the bound is on lock WAITS, not on work. On a `55P03`
failure, retry the migration in a quieter window; the advisory migration lock
and the per-file idempotency rules above make the retry safe.
