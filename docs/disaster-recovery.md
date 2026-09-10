# Backup, restore & disaster recovery

trstctl is **event-sourced**: the event log is the source of truth, and the
relational read model is a pure projection of it. That makes recovery concrete —
restore the event log, rebuild the read model, and the control plane's state is
reconstructed. This page covers what to back up, how to restore, the recovery
objectives, and the DR runbook.

Recovery must use the deployment's ownership-attestation cadence, just as normal
startup does. Otherwise replay can reject a deployment event that the running
server accepted. Both core and edition recovery use that configured cadence;
invalid configuration still fails rather than skipping the ownership check.

Read-model snapshot format 37 also restores the missing capture of AD CS service
and template posture, Kubernetes controller posture, migration runs, notification
routing policies and ownership exceptions. Startup discards older snapshot blobs
and installs a database floor that rejects inserts of earlier formats. This is not
a rolling-version fence: an older binary can currently lower that floor during
its own startup. Keep older replicas stopped during this upgrade. A fresh recovery
rebuilds from retained events.
This does not repair rows already lost by an earlier snapshot restore: a warm
restart can retain that restore's checkpoint and skip the missing history. Such a
deployment still needs an explicit full rebuild from complete retained events;
automatic repair of that upgrade path remains unresolved. This cache repair does
not replace the full backup set or establish that an operator's backup is complete.
Retain the event history needed for recovery.

## The backup set

Back up **all** of the following. The convention is that **any new persistent
store joins this set** — if a feature adds a datastore, its backup is part of this
list. This is **enforced, not assumed**: a manifest test classifies every
table the migrations create as recovered by replaying the event log, recovered from
the PostgreSQL dump, or ephemeral, and fails the build if a new table is left
unclassified — so a store cannot silently fall out of the recovery plan.

| What | Why | How |
| --- | --- | --- |
| **Event log** (NATS JetStream) | The **source of truth**. Restoring it reconstructs all event-sourced state (owners, issuers, identities, certificates, profile versions, OCSP/CRL responder rows, lifecycle, the attributed audit trail, and audit-feed configuration/cursor/receipt/failure projections). | `trstctl --full-backup-dir=/backups/trstctl-YYYY-MM-DD` writes `events.jsonl`; `trstctl --backup=events.jsonl` remains the event-log-only command. |
| **PostgreSQL independent state and restore receivers** | The read model is rebuildable from the log, but **independently retained operational state** lives here: API tokens, bootstrap tokens, CT config/checkpoints, CA lifecycle records, approvals, sealed credentials, stored secret rows, outstanding one-time secret-share rows, policy bindings, federation peer import cursors, queued outbox work, durable scheduled-rotation tick/cursor authority and due-edge commands, and durable privacy-erasure idempotency evidence. The paired artifact also carries logical audit checkpoints so restore can prove every hidden tenant prefix still exists in the event artifact before mutation; `audit.archived` v2 can reconstruct those checkpoint rows during an event-only projection rebuild. | `trstctl --full-backup-dir=/backups/trstctl-YYYY-MM-DD` writes `postgres-state.jsonl` with one manifest-covered row stream for every table in `RecoveredFromPostgresBackup`. |
| **Audit export signing key** | So pre-restore signed evidence bundles still verify (R2.1). | The key is a purpose-constrained `audit-export` handle inside the signer's sealed key store, captured with that store below. `TRSTCTL_AUDIT_SIGNING_KEY_FILE` names only the one-time legacy PEM migration path; new backups do not copy a separate plaintext key artifact. |
| **KEK** (key-encryption key) | The root of trust for everything sealed at rest: stored credentials (R3.1) **and** the signer's CA key (R3.2). Without it, sealed material cannot be opened. | Copy `TRSTCTL_SECRETS_KEK_FILE` to secure storage, separately from the sealed data it protects. |
| **Tenant-domain wrapper files** | Independently custodied roots that can unseal opted-in tenant domains without granting authority over neighboring domains. They are intentionally not captured inside the application backup they protect. | Back up every file named by `secrets.tenant_seal_local_wrappers` under separate operator custody. Restore the exact wrapper ID-to-file mapping before starting a tenant-domain restore; missing or wrong material fails only that tenant closed and never falls back to the deployment KEK. |
| **Signer authorization secret** | The signer-side content-authorization root for dual-control CA handles. Without it, restored privileged handles fail closed because the signer cannot verify approval tokens. | The full backup captures `TRSTCTL_SIGNER_AUTH_SECRET_FILE` as an encrypted artifact; keep the backup encryption key outside the backup directory. |
| **Signer key store** | The issuing CA and audit-evidence private keys, **sealed at rest** (R3.2/AUD-63). Restoring it preserves both identities. | The full backup encrypts the signer's key-store directory (`--keystore`) file-by-file and hashes the encrypted tree in `manifest.json`; the KEK is still restored separately. |
| **Issuing CA certificate** | So the control plane reuses the same CA cert across a restore (stable identity). | The full backup captures `TRSTCTL_CA_CERT_FILE`. |

The signer's CA key is now **persisted, sealed at rest** (R3.2) — it survives a
restart and is part of the backup set above. Restore it (the sealed key store) and
the KEK into a fresh signer to recover the CA identity; see Scenario B below. Keep
the **KEK separate** from the sealed data it protects.

## Full backup

Use the full DR command for production drills and release gates:

```bash
# Requires external Postgres and external NATS.
TRSTCTL_BACKUP_ENCRYPTION_KEY_FILE=/secure/trstctl-full-backup.key \
  scripts/dr/full-backup.sh /backups/trstctl-$(date +%F)
# equivalent:
trstctl \
  --backup-encryption-key-file=/secure/trstctl-full-backup.key \
  --full-backup-dir=/backups/trstctl-$(date +%F)
# -> "wrote full backup with <N> artifacts to ..."
```

The artifact directory contains:

- `events.jsonl`: the event log, with the same integrity trailer as
  `trstctl --backup`.
- `postgres-state.jsonl`: all tables classified as
  `RecoveredFromPostgresBackup`, written as JSONL with its own SHA-256 trailer.
- `files/`: the CA certificate in plaintext, plus `.enc` AES-256-GCM envelopes
  for the signer authorization secret and sealed signer key-store files. The
  audit-evidence key is one sealed handle inside that store.
- `manifest.json`: artifact hashes, byte counts, sensitivity flags, source paths,
  encryption metadata, plaintext hashes for encrypted artifacts, and recovery
  classes for every persistent table.

Full backup uses one explicit consistency cut across both stores. Tenant mutation
transactions hold the shared side of a PostgreSQL backup write fence before they
append to the event log. The backup path takes the exclusive side only long enough
to record the event-log head and pin a read-only repeatable-read PostgreSQL
snapshot, then releases it before streaming rows. It exports only events through
that head and writes `postgres-state.jsonl` from the pinned snapshot with the same
event-cut sequence in its header and trailer. Mutations after that cut are
intentionally absent from both artifacts and are captured by a later backup.

A subject erasure can briefly have sanitized replacement history ready while its
final PostgreSQL projection is still recoverable from a durable preparation row.
Every PostgreSQL-state export checks for that row inside the pinned snapshot and
refuses before writing artifact bytes. Standalone PostgreSQL-state exports hold the
shared cutover fence for their complete transaction. A full backup begins and pins
the snapshot while its session owns the exclusive consistency fence, then atomically
downgrades that same session to a transaction-scoped shared fence before streaming;
the preparation check reads that pinned view before any artifact byte. Retry after
startup has autonomously completed the preparation. The preparation table is still
classified as independent PostgreSQL recovery authority, so restore tooling never
silently drops a crash marker from an older or externally produced artifact.

**Full-backup encryption.** Full backups contain operational secrets,
so the production path requires `TRSTCTL_BACKUP_ENCRYPTION_KEY_FILE` (or the
equivalent `--backup-encryption-key-file`). The file is raw operator-held key
material and is **not copied into the artifact**. Each sensitive artifact is
encrypted with AES-256-GCM via the single crypto boundary, bound to its
manifest role as associated data, and recorded with ciphertext + plaintext hashes.
If a lab export truly must be plaintext, set
`TRSTCTL_BACKUP_ALLOW_UNENCRYPTED=true` or pass
`--allow-unencrypted-full-backup`; the manifest records that explicit override.

The deployment KEK is also **not copied into the artifact**. The manifest records
its configured path as a sensitive reference, and operators restore that file from
separate key custody before running full restore. This keeps ciphertext and the
key that opens it out of the same folder.

## Event-log-only backup

```bash
# Requires the external event store and the deployment's external PostgreSQL DSN.
trstctl --backup=/backups/trstctl-events-$(date +%F).jsonl
# -> "backed up <N> events to ..."
```

The PostgreSQL connection is not backup payload. It supplies the deployment-wide
shared history-generation barrier for the complete export, so a privacy rewrite
cannot switch the authoritative JetStream generation between the first and last
record. Event-only backup therefore fails closed unless both
`TRSTCTL_POSTGRES_MODE=external` / `TRSTCTL_POSTGRES_DSN` and
`TRSTCTL_NATS_MODE=external` / `TRSTCTL_NATS_URL` identify the live deployment.
The exporter preflights the entire pinned cut before writing even the JSONL
header. A malformed or unsanitized schema-v1 scheduled-rotation event therefore
fails with a fixed sanitation-required error and leaves a zero-byte destination;
filtering, a retention checkpoint, or a small result limit cannot hide it.

The backup is **newline-delimited JSON** — a self-describing, versioned header
followed by one record per event (id, type, tenant, time, data, and the recorded
actor), and a final **integrity trailer**. It is portable and inspectable, and it
captures the complete envelope so the recovered audit trail is intact.

**Integrity.** The trailer carries a **SHA-256** over the entire stream
(header + every record), so a bit-flip, a truncation, or a removed record is
detected — `--restore` recomputes the hash and **refuses a tampered or corrupt
backup, fail-closed**, before appending a single event. When the deployment KEK
exists (`TRSTCTL_SECRETS_KEK_FILE`), the trailer also carries an
**HMAC-SHA256** domain-derived from that key, binding the backup to this
deployment so an attacker who can rewrite the file cannot forge a matching
trailer. All hashing/MAC routes through the single crypto boundary; the
signer is not involved and no signing private key enters the control-plane
process. Restore the same KEK before verifying a keyed backup.

Restore now requires that deployment KEK. After the artifact HMAC verifies, the
recovery composition derives a second domain-separated authorization bound to the
exact event cut, artifact SHA-256, and a canonical digest of every sequence, gap,
subject, message ID, and stored envelope the restore will consume. The event log
accepts only an opaque Go capability whose MAC verifies under a key held in locked
memory; an ordinary caller cannot manufacture that capability from a digest or a
byte slice. It first validates the supplied history into a private disk spool,
recomputes the bound digest, and then restores only from that spool. This prevents
a callback from swapping a different history between authorization and mutation.
A nonempty digest, direct `Append`/`Import`, or a transplanted capability is not
restore authority.

Restore verification is streaming: `--restore` rolls the SHA-256/HMAC over each
line, writes validated event records to a temporary spool file, verifies the
trailer, and only then replays the spool into the empty target log. Memory usage
is bounded by the largest event line rather than by the full backup size, while a
corrupt trailer still rejects before the target event store is mutated.

## Restoring

Restore a full artifact into a **fresh, empty** event store and a migrated empty
PostgreSQL instance:

```bash
# Restore TRSTCTL_SECRETS_KEK_FILE from separate key custody first.
TRSTCTL_BACKUP_ENCRYPTION_KEY_FILE=/secure/trstctl-full-backup.key \
  scripts/dr/full-restore.sh /backups/trstctl-2026-05-31
# equivalent:
trstctl \
  --backup-encryption-key-file=/secure/trstctl-full-backup.key \
  --full-restore-dir=/backups/trstctl-2026-05-31
# -> "restored full backup from ... (<N> independent PostgreSQL rows)"
```

`--full-restore-dir` verifies the manifest hashes for captured keys/certs and the
signer key-store tree, decrypts encrypted sensitive artifacts with the backup
encryption key, restores the event log, rebuilds the read model from that log,
verifies `postgres-state.jsonl`, imports every independent PostgreSQL row, and then
performs one final projection rebuild. The ordering matters: the first rebuild lets
independent rows that reference rebuilt state resolve normally. The final rebuild
runs only after the PostgreSQL artifact has finished replacing independent state, so
an event that survived an append-ACK/projection-failure crash can recreate its
durable receiver instead of having that healed row erased by the later import.
Secret-sync receiver start counts and frozen failure evidence are independent
PostgreSQL authority, so current artifacts restore them exactly before the final
replay. For a pre-0153 artifact, unrelated outbox rows receive only the neutral
receiver tuple. A legacy `secret.sync.*` row must match an exact job already rebuilt
from the paired event cut; that job supplies causal order and terminal evidence,
while old claim attempts are conservatively retained as possible receiver starts.
A missing, partial, or mismatched pair aborts the restore instead of guessing from a
SQL allocation id. The restore exception is owner-only and transaction-local, so a
normal or application-role insert cannot forge receiver authority afterward.
Scheduled audit feeds use the same conservative rule. Replay rebuilds the tenant
configuration, cursor, lag, safe error, and collector-receipt projections. If a
queued event survived but its same-transaction outbox row did not, boot
reconciliation re-reads the exact audit sequence range with privacy overlays,
checks every recorded event ID plus the seed and head, and recreates only a
byte-identical destination/payload/idempotency tuple. A shortened or changed range
is an error, not permission to enqueue current records. The paired PostgreSQL
artifact retains already-claimed outbox attempts so a full restore does not pretend
the collector boundary was never crossed.
Scheduled-rotation command receivers deliberately have no foreign key to their
rebuildable schedule projection and restore before the final replay. The
version-2 terminal event carries the exact due-edge tuple, so replay advances
from `due_at` even when producer clocks move backward, without recreating or
re-executing an old edge. A schedule-CAS miss rolls back terminalization.
Retention removes an older terminal
receiver only when that exact event is still retained, the schedule is already
beyond the edge, and a newer command exists; the newest command remains as the
finite lineage fence, while claimed or ambiguous commands are never eligible.
The scheduler's outer idempotency row, tenant scan cursor, aggregate tick, and
child command are restored in that dependency order. The tick keeps the immutable
database cutoff, start/current cursor, wrap marker, row-started snapshot, ordered
partial receipt, and remaining 50/500 budgets. Its composite foreign key prevents
the bound outer idempotency row from being collected while recovery authority is
still live. Restore preserves byte-exact terminal `200`/`503` bodies; it does not
turn an interrupted tick into success or advance its cursor. An expired different
key can later freeze that tick as indeterminate, while the original key can replay
the retained receipt exactly.
Before writing any restored file or touching either datastore, a read-only preflight
fully verifies both state streams and requires their `event_cut_sequence` values to
match. Two individually valid artifacts from different backup cuts are not one
coherent recovery point and are rejected without mutation.
`privacy_subject_erasure_operations` is intentionally restored from this
PostgreSQL artifact and is never truncated by projection rebuild or snapshot
restore: it preserves the canonical response for a pending/retried
`Idempotency-Key` even after audit retention moves the corresponding live event
into the signed archive.

Full restore is resumable after the event-log phase. If a first run
restores `events.jsonl` and then fails later, retrying the same full artifact makes
trstctl verify that the already-present event log is byte-for-byte equivalent to
the same integrity-checked backup stream. Only then does it rebuild projections
and continue to `postgres-state.jsonl`. A different backup stream still fails
closed instead of being treated as a resume.

The same rule covers a process stop in the middle of exact event ingestion. The
target keeps a durable binding to the authenticated artifact digest and declared
cut. A retry with that same HMAC-verified artifact resumes and verifies the raw
prefix before scheduled-rotation sanitation runs; a different artifact is
rejected without advancing the prefix. Serving, backup, ordinary rebuild, and
sanitation refuse a target carrying this incomplete-restore binding. After the
exact cut is complete, restore clears the binding, sanitizes legacy scheduler
history, and only then rebuilds or exposes the recovered generation.

One bounded exception handles an authenticated pre-upgrade artifact whose first
restore completed and whose live generation was then sanitized before the retry.
Generic resume remains byte-exact. The exception requires the original artifact's
HMAC, exactly the deterministic scheduler error-token changes, one cryptographically
verified profiled receipt per affected tenant, recomputed envelope/mapping/target
content roots for every intermediate generation, a continuous operation/generation
chain, and a final target identity equal to the pinned active stream. A receipt
copied from another run with the same tenant, changed count, and cut is rejected.

The live rewrite never mutates older `events.jsonl` files or signed/WORM audit
archives. Those copies may still contain the source bytes and remain subject to
their original access, retention, legal-hold, and destruction controls.

The event-log-only command is still available for projection recovery or as the
first half of a manually coordinated datastore restore:

Restore into a **fresh, empty** event store and a PostgreSQL instance, then rebuild:

```bash
# Requires external Postgres and NATS, and an EMPTY event store.
trstctl --restore=/backups/trstctl-events-2026-05-31.jsonl
# -> "restored <N> events from ... and rebuilt the read model"
```

`--restore` re-appends every event in order (preserving ids, timestamps, and
actors) and then **rebuilds the relational read model purely from the restored
log** (the rebuild-from-log path). It refuses a non-empty event store so a
misdirected restore can never duplicate the stream. It deliberately leaves the
deployment-wide secret-sync recovery light red: events can recreate a queued or
terminal command, but cannot prove how many worker generations had already crossed
the external receiver boundary. Ordinary startup/readiness and the last receiver
start both refuse secret-sync I/O while that light is red. Do not clear the row by
SQL. Restore the paired PostgreSQL artifact with `--full-restore-dir`; its private
offline bootstrap imports exact receiver authority, performs a final replay, and
only then turns the light green before readiness is evaluated.

Full restore associates each retained `secret.sync.*` outbox row with its rebuilt
job by tenant, receiver idempotency key, destination, exact sealed payload, and
causal target order. It never treats the auto-increment outbox id as command
identity. This matters when concurrent source projections allocated SQL ids in the
opposite order from event history: the recovery database may allocate them in
event order during its first replay, then safely remap them to the artifact ids
without swapping jobs or receiver authority.

A backup → restore → rebuild drill is exercised in CI
(`TestBackupRestoreDRDrillReproducesState`): it asserts the recovered inventory
**matches the source** — the same rebuild-from-log equivalence the architecture
guarantees. The full-state drill
(`TestFullBackupRestoreIncludesPostgresState`) additionally seeds and restores at
least one row in every `RecoveredFromPostgresBackup` table, so auth, CA lifecycle
state, approvals, stored secrets, outstanding secret shares, policy bindings, and outbox work are proven
alongside the log-rebuilt read model. OCSP/CRL responder rows are not imported
from this PostgreSQL artifact; they are replayed from `certificate.*` /
`ca.certificate.*` / `ca.crl.published` / `ca.ocsp_responder.rotated` events.

The scheduled runtime drill uses the same `RunFullRestore` implementation, not
the narrower event-only command. It redirects all mutable destinations into an
isolated PostgreSQL database, private file-backed JetStream, and temporary signer
tree; restores the complete manifest; re-exports and compares every independent
table; starts the recovered signer and control-plane assembly; and requires the
real readiness probes to pass. Its attestation exposes those artifact, table, and
health receipts. A missing required artifact, an event-only replay, or any failed
recovered-runtime probe produces `failed`, never `restored`.

Licensed provider projections participate in all four recovery paths: normal
startup catch-up, `--restore`, `--full-restore-dir`/the scheduled isolated
drill, and `--rebuild`. The tagged composition root supplies a feature-neutral
projection factory after the recovery PostgreSQL and JetStream stores exist;
core still imports no `ee/` package. Before rebuilding, it captures uncovered
pre-event provider rows exactly once for rolling upgrades. The final rebuild
then treats the authority events as canonical for customer lifecycle,
delegation, quota, branding, and break-glass views. Those provider tables are
still carried in the PostgreSQL artifact for compatibility with backups made by
pre-event releases, but a licensed final rebuild overwrites their restored
snapshots from the event history; they are not a second source of truth.

## Recovery objectives (RPO / RTO)

These are **defaults to validate against your own infrastructure**, not promises —
they depend on how often you back up and how fast your datastores restore.

- **RPO (data loss window):** the age of your most recent backup. With a healthy
  external JetStream cluster honoring `TRSTCTL_NATS_REPLICAS` (default `3`), the
  event-log RPO approaches **zero** for acked events; if `/readyz` reports NATS
  durability degraded or `trstctl_event_log_replicas_actual` is below desired,
  treat that guarantee as broken until replication is restored. With periodic
  `trstctl --backup`, RPO equals the **backup interval** (e.g. 24 h). Back up at
  the cadence your RPO target requires. With cross-cluster federation enabled on a
  passive region, the passive-region RPO is bounded by the peer import interval
  (`TRSTCTL_FEDERATION_INTERVAL`) plus source JetStream health; use
  `TRSTCTL_FEDERATION_RPO` as the runbook target and do not promote until the peer
  cursor and projection lag are inside that target.
- **RTO (time to recover):** restore the datastores, run `trstctl --full-restore-dir`, and
  start serving. The rebuild is a single pass over the log (tens of milliseconds
  for thousands of events; minutes for very large logs). Plan an RTO that covers
  provisioning + full artifact restore + rebuild + independent PostgreSQL import
  + a smoke test. In a federated passive-region drill, RTO starts when you stop
  primary writes and move traffic; it ends when the passive region serves the
  replicated tenant and trust read state. The default operator target is
  `TRSTCTL_FEDERATION_RTO=30s`, but validate it against your ingress, DNS, and client
  retry behavior.

CAP-SCALE-02 exposes the active regional issuance posture at
`GET /api/v1/scale/ha-issuance` and `trstctl-cli scale ha-issuance`. Its 5s RPO and
30s RTO targets assume regional ingress only routes to healthy regions whose shared or
promoted PostgreSQL writer endpoint, replicated JetStream event log, idempotency table,
outbox leadership, and signer/HSM path are green. If any write fence is stale, the
runbook pauses issuance instead of allowing independent writers for the same tenant.

## High availability (multi-replica by default)

The default Helm chart runs the control plane **multi-replica** (`replicaCount: 2`)
with a no-downtime `RollingUpdate` (`maxUnavailable: 0`), a PodDisruptionBudget
(`minAvailable: 1`), and pod anti-affinity. A node failure
or a config rollout no longer takes issuance/validation offline. The operator-facing
HA contract is simple: leader election plus shared storage make running more than one
control-plane replica **safe**:

- **Leader election for the continuous workers.** A single leader — exactly one
  replica — runs the workers that mutate shared state on a continuous cadence:
  the outbox dispatcher, the audit-retention worker, the idempotency/outbox GC sweeps,
  the projection tailer, the CRL freshness scheduler, and the read-model snapshot
  worker. Leadership is a PostgreSQL **session-scoped advisory lock**: the leader
  holds it for as long as its connection lives, and PostgreSQL **releases it
  automatically** if the leader crashes or partitions, so a follower acquires it on
  its next campaign (failover) with no lease timer to tune. Every replica serves reads
  regardless. Toggle with `ha.leaderElection` (on by default; harmless on a single
  replica, which always wins the lock). The **boot projection catch-up** is
  independently safe on every replica: it takes a projection advisory lock (like
  migrations) so concurrent boots serialize and each resumes from the shared
  projection checkpoint.
- **A shared signer key store so every replica is the same CA.** The default control
  plane topology co-locates the signing service as a locked-down sidecar reachable only
  over a shared in-memory Unix domain socket. For HA the signer key store and
  the control-plane data dir default to **ReadWriteMany**
  (`persistence.signerKeysAccessMode` /
  `persistence.controlPlaneAccessMode`), so every pod's sidecar signer loads the SAME
  sealed issuing-CA key and every replica serves the same CA cert and verifies the
  same audit chain. First-boot CA provisioning is serialized by an advisory lock
  so exactly one replica generates the key; a follower
  signer that started first reloads it from the shared store on demand (reload-on-miss)
  rather than reporting it missing. Run an RWX-capable StorageClass (NFS/EFS/Filestore/
  Azure Files); set both back to `ReadWriteOnce` for a single-replica eval.
- **Constant-time boot via snapshots.** The leader periodically writes one
  **complete all-tenant snapshot generation** at the current projection checkpoint
  (`ha.snapshotInterval`, default ~5m). Every format-22 tenant row repeats the same
  random generation ID, covered event sequence, tenant count, and SHA-256 digest of
  the sorted tenant-ID set. On cold boot, restore recomputes the count and digest
  from the rows physically present and accepts the cache only when every row names
  that exact generation and checkpoint. A missing tenant, a partial write, mixed
  generation IDs, different covered sequences, a bad count/digest, or any legacy
  format makes the whole cache unusable and boot replays from event sequence zero.
  A corrupt or missing snapshot falls back to a full replay automatically.
  A valid generation rehydrates the read model and replays only the **tail**, so the
  fast path is `O(events-since-snapshot)` while the event log remains the AN-2
  source of truth.

  Privacy preparation deletes the erased tenant's snapshot row in the same
  PostgreSQL transaction that records its durable crash marker and sanitized
  evidence. That deletion makes every surviving neighbor fail the format-22
  count/digest proof, so recovery falls back to already-sanitized event history
  instead of skipping past it. After cutover completes, the worker may publish a
  new complete sanitized generation. Upgrade migration 0160 truncates disposable
  pre-v22 blobs and installs a database `format_version >= 22` floor, so a rolling
  old leader cannot repopulate the cache. Every later startup locks the snapshot
  table and, if any legacy row exists, `TRUNCATE`s the whole mixed relation before
  repairing a missing, unvalidated, or mismatched floor. It preserves v22 rows
  only when every row in the relation is already v22; PostgreSQL-state restore
  also truncates the ephemeral snapshot table.
  Legacy raw-erasure bytes are therefore removed rather than merely ignored by
  the decoder.

  If startup finds one idempotency key bound to two different receiver commands,
  it preserves the historical command, records a tenant-scoped quarantine, and
  continues unrelated recovery. Follow the
  [quarantined outbox reconciliation conflict runbook](runbooks/outbox-reconciliation-conflicts.md);
  never repair this condition with a direct outbox or checkpoint edit.

Durability still lives in the **datastores** (external PostgreSQL + replicated NATS):
the event log is the source of truth and a rebuilt pod re-derives state from it, so a
control-plane failure is an availability event, not a data-loss one.

**Optional isolated signer.** `signer.mode: isolated` renders the signer as
its own pod and has the control plane dial it over mutually pinned mTLS gRPC. It is not
required for the HA above — the shared-keystore sidecar model already gives a single,
consistent CA across replicas — but it lets operators move the signer into a separate
pod/network-policy boundary once they supply the `signer.mtls.*` trust material. The
chart fails fast if isolated mode is selected without that material, rather than
shipping a signer pod the control plane cannot authenticate. For a single-replica eval
set `replicaCount: 1` and the access modes to `ReadWriteOnce`; the PDB is then
irrelevant (disable it, since a `minAvailable: 1` PDB would block a single-replica node
drain).

## DR runbook

### Scenario A — loss of the datastore (PostgreSQL and/or NATS)

1. Provision fresh PostgreSQL and NATS (empty).
2. Point trstctl at them (`TRSTCTL_POSTGRES_*`, `TRSTCTL_NATS_*`).
3. Restore the KEK file from separate key custody to `TRSTCTL_SECRETS_KEK_FILE`.
4. Restore the full-backup encryption key outside the artifact directory and set
   `TRSTCTL_BACKUP_ENCRYPTION_KEY_FILE`.
5. Run `trstctl --full-restore-dir=<latest full artifact>` — this decrypts and
   restores captured key/cert files, restores or resumes the log, rebuilds the read
   model, and imports independent PostgreSQL state.
6. Start the control plane; confirm `/readyz` is green and spot-check inventory,
   token auth, rebuilt CA revocation/CRL responder state, approvals, secrets, and
   pending outbox work.

### Scenario B — loss of the signer host (recover the CA, no rotation)

The issuing CA key lives in the out-of-process signer, isolated from the API
process, persisted and sealed at rest (R3.2). A signer-host loss does not mean
a new CA — restore the sealed key store and its custody input and the same CA
is back. (The drilled step-by-step procedure is the
[signer-recovery runbook](runbooks/signer-recovery.md); the essentials:)

1. Provision a fresh signer host/container.
2. **Restore the signer's sealed key store** (`--keystore` directory) and the signer
   authorization secret (`TRSTCTL_SIGNER_AUTH_SECRET_FILE`) from backup. The key
   store and authorization secret are decrypted from the full backup with
   `TRSTCTL_BACKUP_ENCRYPTION_KEY_FILE`.
3. Restore the custody input for that key store. Local-KEK deployments restore the
   signer KEK Secret/file and start `trstctl-signer --keystore <dir> --kek <kek>
   --auth-secret <sign-auth>`. External-KMS deployments restore access to the same
   HSM/KMS key reference and wrapper adapter, then start `trstctl-signer
   --keystore <dir> --kms-provider <provider> --kms-key-ref <keyRef>
   --kms-wrap-command <adapter> --auth-secret <sign-auth>`.
4. Restore `TRSTCTL_CA_CERT_FILE` so the control plane reuses the same CA
   certificate. The signer reloads the sealed CA key, enforces content
   authorization, and the CA identity is unchanged; already-issued certificates keep
   verifying and no re-issuance is needed.

If the CA key **and** its backup are both lost (true catastrophe), fall back to a
planned CA rotation: already-issued certificates remain valid until expiry, stand
up a new CA, re-issue, and distribute the new bundle — see the
[incident-response runbook](runbooks/incident-response.md) and the m-of-n
[key-ceremony runbook](runbooks/key-ceremony.md). Helm `externalKMS` is wired for
signer key-store envelope custody: the chart renders `--kms-*` signer arguments and
omits the local KEK mount when `externalKMS.enabled=true`. A separately provisioned
online break-glass authority can issue and rotate during primary-CA recovery when its
tenant, persisted dual-control signer handle, authenticated operator roster, and
threshold are configured. Open an exact ceremony, collect approvals from distinct
operator tokens, then execute it; requests cannot supply approver names. Rotation
returns both cross-chain directions for a controlled overlap/rollback window.
Recovery reconciliation remains served at `POST /api/v1/breakglass/reconcile` after
operators bring signed emergency bundles back to the control plane.

See [Configuration → Datastores](configuration.md#datastores) and
[Configuration → Signer](configuration.md#signer-topology-and-ca-custody) for the
settings these procedures use.
