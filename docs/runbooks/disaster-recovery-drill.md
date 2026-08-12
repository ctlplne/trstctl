# Runbook: disaster recovery drill

This runbook rehearses a full trstctl recovery without waiting for an outage. It
uses the same backup and restore commands as production recovery, restores into a
fresh target environment, and records evidence that the event log, independent
PostgreSQL state, signer material, and audit material can be recovered together.

Use the broader [backup and disaster recovery](../disaster-recovery.md) page for
the backup set and recovery objectives. Use this page for the drill procedure.

## Drill scope

Run the drill at least quarterly and before major storage, signer, or chart
changes. The target environment must be isolated from production clients. It may
use smaller infrastructure, but it must use external PostgreSQL and external NATS
so the restore path matches the production topology.

The drill proves:

- a full artifact can be written with `trstctl --full-backup-dir`;
- the wrapper script `scripts/dr/full-backup.sh` invokes the same production path;
- `manifest.json` verifies every captured artifact and sensitive file hash;
- `events.jsonl` restores the event log before projections rebuild;
- `postgres-state.jsonl` restores independent PostgreSQL rows after projection
  rebuild;
- the signer key store, KEK, signer authorization secret, and CA certificate keep
  the same issuing identity;
- a restored control plane can pass a smoke test without contacting production
  clients.

The built-in scheduled drill performs this same full-set predicate automatically.
It creates an isolated PostgreSQL database and private file-backed JetStream,
redirects every mutable signer/key/certificate path to a temporary directory,
restores `manifest.json` through the production full-restore function, compares a
re-export of every independent PostgreSQL table, starts the recovered signer and
control-plane assembly, and calls the real `/readyz` handler. Its signed
attestation cannot say `restored` unless all of those checks pass. The separate
event-log-only restore remains useful for projection recovery, but it is never a
full DR verdict.

The scheduled result is not a volatile health flag. The control plane signs a
versioned JSON statement through the isolated `audit-export` signer handle. The
signed statement includes the measured result, configured RPO/RTO thresholds,
and the alert reason derived from them, so event tampering cannot silence a red
drill. The control plane then
appends `backup.restore_drill.recorded`, verifies it while projecting, and keeps a
newest-first tenant history. Failed, skipped, over-RPO, and over-RTO results also
enqueue `notification.restore_drill` through the ordinary notification fanout in
the same transaction as the history row.

Configure the cadence and measured-objective alert thresholds explicitly when the
defaults do not match the recovery plan:

```sh
export TRSTCTL_BACKUP_DIRECTORY=/backups/trstctl-current
export TRSTCTL_BACKUP_DRILL_INTERVAL=24h
export TRSTCTL_BACKUP_DRILL_RPO=24h
export TRSTCTL_BACKUP_DRILL_RTO=1h
```

`TRSTCTL_BACKUP_DRILL_INTERVAL=0` disables the automatic drill. A zero RPO or
RTO objective does not disable alerting; it makes every positive measurement a
breach. Negative or malformed objective durations fail configuration validation.

## Prerequisites

- A healthy source environment: `/readyz` returns `200`, NATS durability is not
  degraded, and `trstctl_signer_up == 1`.
- A current backup encryption key in operator custody, not inside the backup
  directory.
- A fresh target PostgreSQL database and a fresh target NATS stream. The event log
  restore refuses to run against a non-empty target.
- The target uses the same chart values for CA certificate paths, signer key-store
  paths, signer authorization secret path, and KEK path.
- Record source baselines before the drill:

```sh
curl -fksS https://cp.example.com/readyz
curl -fksS https://cp.example.com/metrics | grep 'trstctl_signer_up\|trstctl_event_log_replicas'
trstctl-cli certificates list --limit 50
trstctl-cli agents list
```

## Step 1: take the full backup

Set the backup path and encryption key, then use the wrapper script. The direct
command is shown too; both write the same full-backup artifact.

```sh
export DR_ARTIFACT=/backups/trstctl-drill-$(date +%F)
export TRSTCTL_BACKUP_ENCRYPTION_KEY_FILE=/secure/trstctl-full-backup.key

scripts/dr/full-backup.sh "$DR_ARTIFACT"

# Equivalent direct command:
trstctl \
  --backup-encryption-key-file="$TRSTCTL_BACKUP_ENCRYPTION_KEY_FILE" \
  --full-backup-dir="$DR_ARTIFACT"
```

Expected files:

```sh
test -f "$DR_ARTIFACT/manifest.json"
test -f "$DR_ARTIFACT/events.jsonl"
test -f "$DR_ARTIFACT/postgres-state.jsonl"
find "$DR_ARTIFACT/files" -type f | sort
```

Record the artifact size, event count, PostgreSQL row count, and manifest hash in
the drill ticket:

```sh
wc -l "$DR_ARTIFACT/events.jsonl" "$DR_ARTIFACT/postgres-state.jsonl"
sha256sum "$DR_ARTIFACT/manifest.json"
```

## Step 2: prepare the restore target

Point the target environment at empty datastores and restore the KEK from its
separate custody location. Do not copy the backup encryption key into the artifact
directory or into the restored data directory.

```sh
export TRSTCTL_POSTGRES_DSN='postgres://trstctl:<password>@restore-db:5432/trstctl?sslmode=require'
export TRSTCTL_NATS_URL='nats://restore-nats:4222'
export TRSTCTL_SECRETS_KEK_FILE=/etc/trstctl/kek/kek.bin
install -m 0400 /secure/restored-kek.bin "$TRSTCTL_SECRETS_KEK_FILE"
```

Run config validation before restore so a path typo fails before any data is
imported:

```sh
trstctl --check-config
```

## Step 3: restore the artifact

Use the wrapper script first. It invokes the same full restore path as the direct
command and is what operators normally run during a time-boxed incident.

```sh
scripts/dr/full-restore.sh "$DR_ARTIFACT"

# Equivalent direct command:
trstctl \
  --backup-encryption-key-file="$TRSTCTL_BACKUP_ENCRYPTION_KEY_FILE" \
  --full-restore-dir="$DR_ARTIFACT"
```

Expected result:

- manifest hashes verify before files are restored;
- sensitive artifacts decrypt with the backup encryption key;
- the event log imports from `events.jsonl`;
- projections rebuild from the restored event log;
- independent PostgreSQL rows import from `postgres-state.jsonl`;
- a retry with the same artifact is safe after the event-log phase because the
  restored stream must match the artifact byte-for-byte.

## Step 4: start the restored control plane

Start the target control plane with production-like chart values, then wait for
readiness and signer health:

```sh
helm upgrade --install trstctl deploy/helm/trstctl \
  --namespace trstctl-restore --create-namespace \
  -f trstctl-values.restore.yaml \
  --wait --timeout=10m

kubectl -n trstctl-restore rollout status deployment/trstctl --timeout=10m
curl -fksS https://restore-cp.example.com/readyz
curl -fksS https://restore-cp.example.com/metrics | grep trstctl_signer_up
```

If isolated signer mode is enabled, also wait for the signer deployment:

```sh
kubectl -n trstctl-restore rollout status deployment/trstctl-signer --timeout=10m
```

## Step 5: smoke test the restore

Run read-only checks first, then one low-risk mutation in a drill tenant. The
smoke test should prove the restored API, read model, signer, idempotency path,
and outbox path can operate.

```sh
trstctl-cli certificates list --limit 50
trstctl-cli agents list

cat > owner.json <<'JSON'
{"kind":"service","name":"dr-drill-owner"}
JSON
trstctl-cli --idempotency-key dr-drill-owner-$(date +%s) owners create -f owner.json
```

For a signer smoke test, issue a short-lived certificate in a non-production
tenant and verify it appears in inventory:

```sh
trstctl-cli certificates list --limit 50
```

Do not point restored agents, ACME clients, notification channels, or deployment
connectors at production systems during a drill. Keep external endpoints disabled
or routed to test sinks.

## Abort criteria

Stop the drill and preserve logs when any of these happen:

- `trstctl --full-restore-dir` reports a manifest or stream integrity failure.
- The target event log is not empty before restore.
- `/readyz` stays `503` after datastores and signer are available.
- `trstctl_signer_up` remains `0` after signer rollout.
- Restored inventory is empty when the source baseline was not.
- The smoke test succeeds only after disabling auth, tenant scoping, idempotency,
  or signer verification.

## Evidence to retain

Attach these to the drill ticket:

1. Source `/readyz` and signer metric output.
2. Backup command output and `sha256sum "$DR_ARTIFACT/manifest.json"`.
3. `wc -l` output for `events.jsonl` and `postgres-state.jsonl`.
4. Restore command output.
5. Target `/readyz` and signer metric output.
6. Before/after inventory counts.
7. Smoke-test request IDs and idempotency keys.
8. Any rollback, retry, or manual step needed to finish the drill.

For the built-in scheduled drill, retain the product evidence rather than a
screenshot:

```sh
trstctl platform dr-posture > restore-drill-history.json
```

The `drill_history` array is newest first. Each row reports
`signature_verified`, `signer_key_id`, and `signer_algorithm`, and its
`signed_evidence` member contains the complete compact JWS plus public JWKS for
auditor handoff. The Platform console exposes the same rows and downloads that
exact JSON evidence. A tampered projected row makes the API fail closed instead
of rendering a green badge; replaying the retained event rebuilds the original
verified row.

## Passing result

The drill passes when the restored environment reaches `/readyz`, signer health
is `1`, inventory is present, and the smoke test completes without weakening the
runtime checks. If any manual step was needed, keep the drill marked failed until
the runbook or automation is corrected and the drill is repeated.
