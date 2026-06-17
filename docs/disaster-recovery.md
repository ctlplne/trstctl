# Backup, restore & disaster recovery

trstctl is **event-sourced** (AN-2): the event log is the source of truth, and the
relational read model is a pure projection of it. That makes recovery concrete —
restore the event log, rebuild the read model, and the control plane's state is
reconstructed. This page covers what to back up, how to restore, the recovery
objectives, and the DR runbook.

## The backup set

Back up **all** of the following. The convention is that **any new persistent
store joins this set** — if a feature adds a datastore, its backup is part of this
list. This is **enforced, not assumed**: a manifest test
(`internal/backup` `TestBackupManifestCoversEveryPersistentStore`) classifies every
table the migrations create as recovered by replaying the event log, recovered from
the PostgreSQL dump, or ephemeral, and fails the build if a new table is left
unclassified — so a store cannot silently fall out of the recovery plan.

| What | Why | How |
| --- | --- | --- |
| **Event log** (NATS JetStream) | The **source of truth** (AN-2). Restoring it reconstructs all event-sourced state (owners, issuers, identities, certificates, profile versions, lifecycle, and the attributed audit trail). | `trstctl --full-backup-dir=/backups/trstctl-YYYY-MM-DD` writes `events.jsonl`; `trstctl --backup=events.jsonl` remains the event-log-only command. |
| **PostgreSQL independent state** | The read model is rebuildable from the log, but **non-event state** lives here: API tokens, bootstrap tokens, CT config/checkpoints, CA lifecycle records, approvals, sealed credentials, secret rows, policy bindings, and queued outbox work. | `trstctl --full-backup-dir=/backups/trstctl-YYYY-MM-DD` writes `postgres-state.jsonl` with one manifest-covered row stream for every table in `RecoveredFromPostgresBackup`. |
| **Audit export signing key** | So pre-restore signed evidence bundles still verify (R2.1). | The full backup captures `TRSTCTL_AUDIT_SIGNING_KEY_FILE` and records its hash in `manifest.json`. |
| **KEK** (key-encryption key) | The root of trust for everything sealed at rest: stored credentials (R3.1) **and** the signer's CA key (R3.2). Without it, sealed material cannot be opened. | Copy `TRSTCTL_SECRETS_KEK_FILE` to secure storage, separately from the sealed data it protects. |
| **Signer authorization secret** | The signer-side content-authorization root for dual-control CA handles (SIGNER-001). Without it, restored privileged handles fail closed because the signer cannot verify approval tokens. | The full backup captures `TRSTCTL_SIGNER_AUTH_SECRET_FILE`; keep custody equivalent to the signer key store. |
| **Signer CA key store** | The issuing CA's private key, **sealed at rest** (R3.2). Restoring it preserves the CA identity. | The full backup copies the signer's key-store directory (`--keystore`) and hashes the tree in `manifest.json`; it holds only ciphertext. |
| **Issuing CA certificate** | So the control plane reuses the same CA cert across a restore (stable identity). | The full backup captures `TRSTCTL_CA_CERT_FILE`. |

The signer's CA key is now **persisted, sealed at rest** (R3.2) — it survives a
restart and is part of the backup set above. Restore it (the sealed key store) and
the KEK into a fresh signer to recover the CA identity; see Scenario B below. Keep
the **KEK separate** from the sealed data it protects.

## Full backup

Use the full DR command for production drills and release gates:

```bash
# Requires external Postgres and external NATS.
scripts/dr/full-backup.sh /backups/trstctl-$(date +%F)
# equivalent:
trstctl --full-backup-dir=/backups/trstctl-$(date +%F)
# -> "wrote full backup with <N> artifacts to ..."
```

The artifact directory contains:

- `events.jsonl`: the event log, with the same integrity trailer as
  `trstctl --backup`.
- `postgres-state.jsonl`: all tables classified as
  `RecoveredFromPostgresBackup`, written as JSONL with its own SHA-256 trailer.
- `files/`: the audit signing key, signer authorization secret, CA certificate,
  and sealed signer key store.
- `manifest.json`: artifact hashes, byte counts, sensitivity flags, source paths,
  and recovery classes for every persistent table.

The deployment KEK is **not copied into the artifact**. The manifest records its
configured path as a sensitive reference, and operators restore that file from a
separate key-custody backup before running full restore. This keeps ciphertext and
the key that opens it out of the same folder.

## Event-log-only backup

```bash
# Requires the external event store (TRSTCTL_NATS_MODE=external).
trstctl --backup=/backups/trstctl-events-$(date +%F).jsonl
# -> "backed up <N> events to ..."
```

The backup is **newline-delimited JSON** — a self-describing, versioned header
followed by one record per event (id, type, tenant, time, data, and the recorded
actor), and a final **integrity trailer**. It is portable and inspectable, and it
captures the complete envelope so the recovered audit trail is intact.

**Integrity (OPS-006).** The trailer carries a **SHA-256** over the entire stream
(header + every record), so a bit-flip, a truncation, or a removed record is
detected — `--restore` recomputes the hash and **refuses a tampered or corrupt
backup, fail-closed**, before appending a single event. When the deployment has a
persisted audit signing key (`TRSTCTL_AUDIT_SIGNING_KEY_FILE`), the trailer also
carries an **HMAC-SHA256** derived from that key, binding the backup to this
deployment so an attacker who can rewrite the file cannot forge a matching
trailer. All hashing/MAC routes through the `internal/crypto` boundary (AN-3); the
signer is not involved (AN-4). Keep the audit key with your backups so a keyed
backup verifies on the recovery host.

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
scripts/dr/full-restore.sh /backups/trstctl-2026-05-31
# equivalent:
trstctl --full-restore-dir=/backups/trstctl-2026-05-31
# -> "restored full backup from ... (<N> independent PostgreSQL rows)"
```

`--full-restore-dir` verifies the manifest hashes for captured keys/certs and the
signer key-store tree, restores the event log, rebuilds the read model from that
log, verifies `postgres-state.jsonl`, and imports every independent PostgreSQL row.
The ordering matters: projections are rebuilt before independent rows are imported,
so any independent rows that reference rebuilt state can resolve normally.

The event-log-only command is still available for a projection-only recovery or a
manual datastore restore:

Restore into a **fresh, empty** event store and a PostgreSQL instance, then rebuild:

```bash
# Requires external Postgres and NATS, and an EMPTY event store.
trstctl --restore=/backups/trstctl-events-2026-05-31.jsonl
# -> "restored <N> events from ... and rebuilt the read model"
```

`--restore` re-appends every event in order (preserving ids, timestamps, and
actors) and then **rebuilds the relational read model purely from the restored
log** (the AN-2 rebuild). It refuses a non-empty event store so a misdirected
restore can never duplicate the stream.

A backup → restore → rebuild drill is exercised in CI
(`TestBackupRestoreDRDrillReproducesState`): it asserts the recovered inventory
**matches the source** — the same rebuild-from-log equivalence the architecture
guarantees. The full-state drill
(`TestFullBackupRestoreIncludesPostgresState`) additionally seeds and restores at
least one row in every `RecoveredFromPostgresBackup` table, so auth, CA state,
approvals, secret rows, policy bindings, and outbox work are proven alongside the
read model.

## Recovery objectives (RPO / RTO)

These are **defaults to validate against your own infrastructure**, not promises —
they depend on how often you back up and how fast your datastores restore.

- **RPO (data loss window):** the age of your most recent backup. With a healthy
  external JetStream cluster honoring `TRSTCTL_NATS_REPLICAS` (default `3`), the
  event-log RPO approaches **zero** for acked events; if `/readyz` reports NATS
  durability degraded or `trstctl_event_log_replicas_actual` is below desired,
  treat that guarantee as broken until replication is restored. With periodic
  `trstctl --backup`, RPO equals the **backup interval** (e.g. 24 h). Back up at
  the cadence your RPO target requires.
- **RTO (time to recover):** restore the datastores, run `trstctl --full-restore-dir`, and
  start serving. The rebuild is a single pass over the log (tens of milliseconds
  for thousands of events; minutes for very large logs). Plan an RTO that covers
  provisioning + full artifact restore + rebuild + independent PostgreSQL import
  + a smoke test.

## High availability (multi-replica by default)

The default Helm chart runs the control plane **multi-replica** (`replicaCount: 2`)
with a no-downtime `RollingUpdate` (`maxUnavailable: 0`), a PodDisruptionBudget
(`minAvailable: 1`), and pod anti-affinity (RESIL-002 / EXC-RESIL-01). A node failure
or a config rollout no longer takes issuance/validation offline. Three mechanisms make
running more than one control-plane replica **safe**:

- **Leader election for the continuous workers (RESIL-004).** A single leader (via
  leader election) — exactly one replica —
  the **leader** — runs the workers that mutate shared state on a continuous cadence:
  the outbox dispatcher, the audit-retention worker, the idempotency/outbox GC sweeps,
  the projection tailer, the CRL freshness scheduler, and the read-model snapshot
  worker. Leadership is a PostgreSQL **session-scoped advisory lock**
  (`store.LeaderAdvisoryLockKey`, "ctllea"): the leader holds it for as long as its
  connection lives, and PostgreSQL **releases it automatically** if the leader crashes
  or partitions, so a follower acquires it on its next campaign (failover) with no
  lease timer to tune. Every replica serves reads regardless. Toggle with
  `ha.leaderElection` (on by default; harmless on a single replica, which always wins
  the lock). The **boot projection catch-up** is independently safe on every replica:
  it takes the projection advisory lock (`ProjectionAdvisoryLockKey`, like migrations)
  so concurrent boots serialize and each resumes from the shared projection checkpoint
  (SPINE-007).
- **A shared signer key store so every replica is the same CA.** The default control
  plane topology co-locates the signing service as a locked-down sidecar reachable only
  over a shared in-memory Unix domain socket (AN-4). For HA the signer key store and
  the control-plane data dir default to **ReadWriteMany**
  (`persistence.signerKeysAccessMode` /
  `persistence.controlPlaneAccessMode`), so every pod's sidecar signer loads the SAME
  sealed issuing-CA key and every replica serves the same CA cert and verifies the
  same audit chain. First-boot CA provisioning is serialized by an advisory lock
  (`CAProvisionAdvisoryLockKey`) so exactly one replica generates the key; a follower
  signer that started first reloads it from the shared store on demand (reload-on-miss)
  rather than reporting it missing. Run an RWX-capable StorageClass (NFS/EFS/Filestore/
  Azure Files); set both back to `ReadWriteOnce` for a single-replica eval.
- **Constant-time boot via snapshots (SPINE-007).** The leader periodically writes a
  per-tenant read-model snapshot at the current projection checkpoint
  (`ha.snapshotInterval`, default ~5m). On a cold boot / DR restore the read model is
  rehydrated from the latest snapshot and only the **tail** after it is replayed, so
  startup is `O(events-since-snapshot)`, not a full-log replay. The event log remains
  the source of truth (AN-2): a snapshot is reproducible by a full `Rebuild`, and a
  corrupt or missing snapshot falls back to a full replay automatically.

Durability still lives in the **datastores** (external PostgreSQL + replicated NATS):
the event log is the source of truth and a rebuilt pod re-derives state from it, so a
control-plane failure is an availability event, not a data-loss one.

**Optional isolated signer (SIGNER-005).** `signer.mode: isolated` renders the signer as
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
4. Run `trstctl --full-restore-dir=<latest full artifact>` — this restores
   captured key/cert files, restores the log, rebuilds the read model, and imports
   independent PostgreSQL state.
5. Start the control plane; confirm `/readyz` is green and spot-check inventory,
   token auth, CA revocation/CRL state, approvals, secrets, and pending outbox work.

### Scenario B — loss of the signer host (recover the CA, no rotation)

The issuing CA key lives in the out-of-process signer (AN-4) and is now
**persisted, sealed at rest** (R3.2). A signer-host loss does **not** mean a new CA
— restore the sealed key store and the KEK and the **same CA is back**:

1. Provision a fresh signer host/container.
2. **Restore the signer's sealed key store** (`--keystore` directory), the
   **KEK** (`TRSTCTL_SECRETS_KEK_FILE`), and the signer authorization secret
   (`TRSTCTL_SIGNER_AUTH_SECRET_FILE`) from backup. Keep them from separate
   backups — the KEK opens sealed keys, and the authorization secret lets the
   signer verify dual-control tokens for restored privileged handles.
3. Start `trstctl-signer --keystore <dir> --kek <kek> --auth-secret <sign-auth>`;
   it reloads the sealed CA key and enforces content authorization. Restore
   `TRSTCTL_CA_CERT_FILE` so the control plane reuses the same CA certificate.
   The CA identity is unchanged; already-issued certificates keep verifying and
   no re-issuance is needed.

If the CA key **and** its backup are both lost (true catastrophe), fall back to a
planned CA rotation: already-issued certificates remain valid until expiry, stand
up a new CA, re-issue, and distribute the new bundle — see the
[incident-response runbook](runbooks/incident-response.md) and the m-of-n
[key-ceremony runbook](runbooks/key-ceremony.md). HSM/KMS-backed custody and a
served break-glass flow remain future work.

See [Configuration → Datastores](configuration.md#datastores) and
[Configuration → Signer](configuration.md#signer-topology--ca-custody) for the
settings these procedures use.
