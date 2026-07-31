// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// backupIntegrityLabel domain-separates the derived backup HMAC key from any other
// use of the audit signing-key material.
const backupIntegrityLabel = "trstctl/backup-integrity/v1"

// backupIntegrityKey derives the HMAC integrity key for the event-log backup
// (OPS-006) from the deployment's audit export signing key, so a valid keyed
// backup is bound to THIS deployment and a tamperer cannot forge the trailer's
// MAC without the key. It returns nil (a checksum-only, still-tamper-evident
// backup) when no audit signing key is configured, so the backup CLI keeps
// working on a minimal config. Derivation routes through the crypto boundary
// (HMAC-SHA256, AN-3); the signer is never involved (AN-4). It reads only the
// already-at-rest PEM bytes — it does not import a private key into a long-lived
// in-memory signer.
func backupIntegrityKey(cfg *config.Config) ([]byte, error) {
	path := cfg.Audit.SigningKeyFile
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No persisted audit key yet (e.g. a never-started fresh deployment):
			// fall back to a checksum-only backup rather than failing the CLI.
			return nil, nil
		}
		return nil, fmt.Errorf("read audit signing key for backup integrity: %w", err)
	}
	return crypto.HMACSHA256(pem, []byte(backupIntegrityLabel)), nil
}

// RunBackup writes a portable backup of the event log (the AN-2 source of truth)
// to path and returns the number of events backed up. It requires an external
// event store — the datastore an operator actually backs up — and fails fast
// otherwise (a bundled/embedded store is per-process and not a backup target).
func RunBackup(ctx context.Context, cfg *config.Config, path string) (int, error) {
	if cfg.NATS.Mode != config.NATSExternal || cfg.NATS.URL == "" {
		return 0, errors.New("backup requires an external event store (set TRSTCTL_NATS_MODE=external and TRSTCTL_NATS_URL)")
	}
	if cfg.Postgres.Mode != config.PostgresExternal || cfg.Postgres.DSN == "" {
		return 0, errors.New("backup requires external Postgres coordination (set TRSTCTL_POSTGRES_MODE=external and TRSTCTL_POSTGRES_DSN); an event-only backup must hold the deployment history read barrier")
	}
	st, err := store.Open(ctx, cfg.Postgres.DSN)
	if err != nil {
		return 0, fmt.Errorf("open store for event backup coordination: %w", err)
	}
	defer st.Close()
	auditKey, err := audit.LoadOrCreateSigningKey(cfg.Audit.SigningKeyFile, "audit-export")
	if err != nil {
		return 0, fmt.Errorf("audit signing key: %w", err)
	}
	log, err := openHistoryAwareEventLog(ctx, cfg.NATS, st, auditKey)
	if err != nil {
		return 0, fmt.Errorf("open event log: %w", err)
	}
	defer func() { _ = log.Close() }()

	key, err := backupIntegrityKey(cfg)
	if err != nil {
		return 0, err
	}

	var n int
	err = withRecoveredBackupHistoryRead(ctx, log, st, func(readCtx context.Context) error {
		cut, err := log.LastSequence(readCtx)
		if err != nil {
			return fmt.Errorf("capture event backup cut: %w", err)
		}
		f, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("create backup file: %w", err)
		}
		defer func() { _ = f.Close() }()

		// The outer shared history view stays held for the complete export. A
		// generation cutover therefore cannot move authority between the first
		// and last exported record.
		n, err = backup.WriteLogWithKeyThrough(readCtx, log, f, key, cut)
		if err != nil {
			return err
		}
		if uint64(n) != cut {
			return fmt.Errorf(
				"event backup contains %d live records through cut %d; logical audit retention creates no source gaps, so refusing legacy or externally damaged history",
				n, cut,
			)
		}
		if err := f.Close(); err != nil { // flush before releasing the read view
			return fmt.Errorf("close backup file: %w", err)
		}
		return nil
	})
	return n, err
}

type auditCheckpointInventory interface {
	audit.CheckpointSource
	ListAuditCheckpointTenants(context.Context) ([]string, error)
}

// withRecoveredBackupHistoryRead proves every logical audit checkpoint still has
// its complete AN-2 source prefix before a backup pins history. Older builds
// physically pruned that shared source; silently finishing such a prune would
// make projection rebuild lossy. The outer history-operation lock stays held
// through validation and export so retention/rewrite cannot move the boundary.
func withRecoveredBackupHistoryRead(
	ctx context.Context,
	log *events.Log,
	checkpoints auditCheckpointInventory,
	fn func(context.Context) error,
) error {
	if log == nil {
		return errors.New("backup history recovery requires an event log")
	}
	if checkpoints == nil {
		return errors.New("backup history recovery requires an audit checkpoint source")
	}
	if fn == nil {
		return errors.New("backup history recovery requires an export callback")
	}
	return log.WithHistoryOperation(ctx, func(operationCtx context.Context) error {
		if err := verifyRetainedAuditCheckpointSources(operationCtx, log, checkpoints); err != nil {
			return err
		}
		return log.WithHistoryRead(operationCtx, fn)
	})
}

func verifyRetainedAuditCheckpointSources(
	ctx context.Context,
	log *events.Log,
	checkpoints auditCheckpointInventory,
) error {
	ordered, err := checkpoints.ListAuditCheckpointTenants(ctx)
	if err != nil {
		return fmt.Errorf("list audit checkpoint tenants before backup: %w", err)
	}
	sort.Strings(ordered)
	for _, tenantID := range ordered {
		checkpoint, ok, err := checkpoints.LatestAuditCheckpoint(ctx, tenantID)
		if err != nil {
			return fmt.Errorf("read audit checkpoint for tenant %s: %w", tenantID, err)
		}
		if !ok {
			return fmt.Errorf("audit checkpoint inventory named tenant %s without a checkpoint", tenantID)
		}
		if checkpoint.TenantID != tenantID {
			return fmt.Errorf(
				"audit checkpoint tenant mismatch: requested %s, got %s",
				tenantID, checkpoint.TenantID,
			)
		}
		if err := audit.VerifyCheckpointSourceRetained(ctx, log, checkpoint); err != nil {
			return fmt.Errorf("verify audit checkpoint source before backup: %w", err)
		}
	}
	return nil
}

// RunFullBackup writes a complete trstctl disaster-recovery artifact directory:
// event log, independent PostgreSQL state, required key/certificate files, and a
// manifest with hashes and recovery classes.
func RunFullBackup(ctx context.Context, cfg *config.Config, dir string) (backup.FullManifest, error) {
	if cfg.Postgres.Mode != config.PostgresExternal || cfg.Postgres.DSN == "" {
		return backup.FullManifest{}, errors.New("full backup requires an external Postgres (set TRSTCTL_POSTGRES_MODE=external and TRSTCTL_POSTGRES_DSN)")
	}
	if cfg.NATS.Mode != config.NATSExternal || cfg.NATS.URL == "" {
		return backup.FullManifest{}, errors.New("full backup requires an external event store (set TRSTCTL_NATS_MODE=external and TRSTCTL_NATS_URL)")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return backup.FullManifest{}, fmt.Errorf("create full backup dir: %w", err)
	}
	enc, err := fullBackupEncryptionFromConfig(cfg)
	if err != nil {
		return backup.FullManifest{}, err
	}
	defer enc.wipe()
	if !enc.enabled() && !enc.allowUnencrypted {
		return backup.FullManifest{}, errors.New("full backup requires TRSTCTL_BACKUP_ENCRYPTION_KEY_FILE because the artifact captures signer/audit secrets; set TRSTCTL_BACKUP_ALLOW_UNENCRYPTED=true only for an explicit lab override")
	}

	st, err := store.Open(ctx, cfg.Postgres.DSN)
	if err != nil {
		return backup.FullManifest{}, fmt.Errorf("open store for full backup: %w", err)
	}
	defer st.Close()

	auditKey, err := audit.LoadOrCreateSigningKey(cfg.Audit.SigningKeyFile, "audit-export")
	if err != nil {
		return backup.FullManifest{}, fmt.Errorf("audit signing key: %w", err)
	}
	log, err := openHistoryAwareEventLog(ctx, cfg.NATS, st, auditKey)
	if err != nil {
		return backup.FullManifest{}, fmt.Errorf("open event log for full backup: %w", err)
	}
	defer func() { _ = log.Close() }()

	var (
		tx            pgx.Tx
		eventCut      uint64
		eventArtifact backup.Artifact
	)
	key, err := backupIntegrityKey(cfg)
	if err != nil {
		return backup.FullManifest{}, err
	}
	if err := withRecoveredBackupHistoryRead(ctx, log, st, func(readCtx context.Context) error {
		if err := st.WithBackupWriteFence(readCtx, func(fenceCtx context.Context) error {
			var err error
			eventCut, err = log.LastSequence(fenceCtx)
			if err != nil {
				return fmt.Errorf("capture full backup event cut: %w", err)
			}
			tx, err = backup.BeginPostgresStateSnapshot(fenceCtx, st)
			if err != nil {
				return fmt.Errorf("begin full backup postgres snapshot: %w", err)
			}
			return nil
		}); err != nil {
			return err
		}

		eventsPath := filepath.Join(dir, "events.jsonl")
		eventsFile, err := os.Create(eventsPath)
		if err != nil {
			return fmt.Errorf("create event log backup: %w", err)
		}
		eventRecords, err := backup.WriteLogWithKeyThrough(readCtx, log, eventsFile, key, eventCut)
		if err != nil {
			_ = eventsFile.Close()
			return err
		}
		if uint64(eventRecords) != eventCut {
			_ = eventsFile.Close()
			return fmt.Errorf(
				"full backup event history contains %d live records through cut %d; refusing legacy or externally damaged source gaps",
				eventRecords, eventCut,
			)
		}
		if err := eventsFile.Close(); err != nil {
			return fmt.Errorf("close event log backup: %w", err)
		}
		eventArtifact, err = fileArtifact("event-log", "event-log", eventsPath, eventsPath, true, true, false, true, dir, nil)
		if err != nil {
			return err
		}
		return nil
	}); err != nil {
		if tx != nil {
			_ = tx.Rollback(ctx)
		}
		return backup.FullManifest{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	artifacts := []backup.Artifact{eventArtifact}

	pgPath := filepath.Join(dir, "postgres-state.jsonl")
	pgFile, err := os.OpenFile(pgPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return backup.FullManifest{}, fmt.Errorf("create postgres state backup: %w", err)
	}
	if _, err := backup.WritePostgresStateTx(ctx, tx, pgFile, eventCut); err != nil {
		_ = pgFile.Close()
		return backup.FullManifest{}, err
	}
	if err := pgFile.Close(); err != nil {
		return backup.FullManifest{}, fmt.Errorf("close postgres state backup: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return backup.FullManifest{}, fmt.Errorf("finish full backup postgres snapshot: %w", err)
	}
	a, err := fileArtifact("postgres-state", "postgres-state", pgPath, pgPath, true, true, false, true, dir, nil)
	if err != nil {
		return backup.FullManifest{}, err
	}
	artifacts = append(artifacts, a)

	staticArtifacts, err := captureFullBackupFiles(cfg, dir, enc)
	if err != nil {
		return backup.FullManifest{}, err
	}
	artifacts = append(artifacts, staticArtifacts...)

	manifest := backup.NewFullManifest(artifacts)
	manifest.Encryption = enc.manifestEncryption()
	if err := backup.WriteFullManifest(filepath.Join(dir, backup.FullManifestName), manifest); err != nil {
		return backup.FullManifest{}, err
	}
	return manifest, nil
}

func captureFullBackupFiles(
	cfg *config.Config,
	dir string,
	enc *fullBackupEncryption,
) ([]backup.Artifact, error) {
	var artifacts []backup.Artifact
	for _, spec := range []struct {
		name      string
		role      string
		src       string
		dst       string
		capture   bool
		sensitive bool
		required  bool
	}{
		{"audit-signing-key", "audit-signing-key", cfg.Audit.SigningKeyFile, filepath.Join(dir, "files", "audit-signing-key.pem"), true, true, true},
		{"signer-auth-secret", "signer-auth-secret", cfg.Signer.AuthSecretFile, filepath.Join(dir, "files", "signer-auth-secret.bin"), true, true, true},
		{"ca-certificate", "ca-certificate", cfg.CA.CertFile, filepath.Join(dir, "files", "issuing-ca.crt"), true, false, true},
		{"kek-reference", "kek-reference", cfg.Secrets.KEKFile, "", false, true, true},
	} {
		a, err := fileArtifact(spec.name, spec.role, spec.src, spec.dst, spec.capture, false, spec.sensitive, spec.required, dir, enc)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, a)
	}
	keyStoreArtifact, err := dirArtifact("signer-keystore", "signer-keystore", cfg.Signer.KeyStoreDir, filepath.Join(dir, "files", "signer-keystore"), true, true, true, dir, enc)
	if err != nil {
		return nil, err
	}
	artifacts = append(artifacts, keyStoreArtifact)
	return artifacts, nil
}

// RunRestore restores the event log from a backup at path and rebuilds the read
// model purely from it (AN-2 / R1.1) — reconstructing the control plane's state.
// It requires external Postgres and NATS (the recovered datastores), and the
// event store must be empty. It returns the number of events restored.
func RunRestore(ctx context.Context, cfg *config.Config, path string) (int, error) {
	return restoreEventLog(ctx, cfg, path, false)
}

func restoreEventLog(ctx context.Context, cfg *config.Config, path string, resumeIfMatching bool) (int, error) {
	if cfg.NATS.Mode != config.NATSExternal || cfg.NATS.URL == "" {
		return 0, errors.New("restore requires an external event store (set TRSTCTL_NATS_MODE=external and TRSTCTL_NATS_URL)")
	}
	if cfg.Postgres.Mode != config.PostgresExternal || cfg.Postgres.DSN == "" {
		return 0, errors.New("restore requires an external Postgres (set TRSTCTL_POSTGRES_MODE=external and TRSTCTL_POSTGRES_DSN)")
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open backup file: %w", err)
	}
	defer func() { _ = f.Close() }()
	key, err := backupIntegrityKey(cfg)
	if err != nil {
		return 0, err
	}
	preflight, err := backup.VerifyEventLogBackupWithKey(f, key)
	if err != nil {
		return 0, fmt.Errorf("restore event-log preflight: %w", err)
	}
	if preflight.HasGaps {
		return 0, errors.New(
			"restore event history contains unexplained deleted positions; " +
				"logical audit retention retains AN-2 source envelopes, so refusing before datastore mutation",
		)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("rewind verified event backup: %w", err)
	}

	st, err := store.Open(ctx, cfg.Postgres.DSN)
	if err != nil {
		return 0, fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return 0, fmt.Errorf("migrate: %w", err)
	}

	// Capture whether this recovery host already possesses the source deployment
	// key before LoadOrCreate supplies the verifier needed by event-log recovery.
	// A bare host still verifies the checksum-only portable backup contract; a
	// pre-provisioned host additionally enforces the deployment-bound HMAC.
	auditKey, err := audit.LoadOrCreateSigningKey(cfg.Audit.SigningKeyFile, "audit-export")
	if err != nil {
		return 0, fmt.Errorf("audit signing key: %w", err)
	}
	log, err := openHistoryAwareEventLog(ctx, cfg.NATS, st, auditKey)
	if err != nil {
		return 0, fmt.Errorf("open event log: %w", err)
	}
	defer func() { _ = log.Close() }()

	// Verify integrity before appending anything (OPS-006). The SHA-256 trailer is
	// always enforced; when this recovery host already holds the deployment's audit
	// signing key we additionally require the backup's HMAC to verify under it.
	// (On a bare recovery host without the key yet, the checksum still guards
	// against truncation/bit-flips so a corrupt artifact is rejected.)
	n, err := backup.RestoreLogWithKey(ctx, log, f, key)
	if err != nil {
		if resumeIfMatching && errors.Is(err, backup.ErrRestoreTargetNotEmpty) {
			if _, seekErr := f.Seek(0, 0); seekErr != nil {
				return n, fmt.Errorf("rewind backup file for resume verification: %w", seekErr)
			}
			n, err = backup.VerifyLogMatchesWithKey(ctx, log, f, key)
			if err != nil {
				return n, fmt.Errorf("resume full restore event log: %w", err)
			}
			if err := projections.New(st).Rebuild(ctx, log); err != nil {
				return n, fmt.Errorf("rebuild read model from resumed log: %w", err)
			}
			return n, nil
		}
		return n, err
	}
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		return n, fmt.Errorf("rebuild read model from restored log: %w", err)
	}
	return n, nil
}

// RunFullRestore restores a full DR artifact directory created by RunFullBackup.
// The deployment KEK is deliberately not copied into the artifact; operators must
// restore it separately at cfg.Secrets.KEKFile before invoking this function.
func RunFullRestore(ctx context.Context, cfg *config.Config, dir string) (backup.PostgresStateSummary, error) {
	manifest, err := backup.ReadFullManifest(filepath.Join(dir, backup.FullManifestName))
	if err != nil {
		return backup.PostgresStateSummary{}, err
	}
	enc, err := fullBackupEncryptionFromConfig(cfg)
	if err != nil {
		return backup.PostgresStateSummary{}, err
	}
	defer enc.wipe()
	if err := requireFullBackupEncryptionForRestore(manifest, enc); err != nil {
		return backup.PostgresStateSummary{}, err
	}
	if err := requireExistingFile(cfg.Secrets.KEKFile, "deployment KEK"); err != nil {
		return backup.PostgresStateSummary{}, err
	}
	if err := verifyFileArtifact(manifest, "event-log", filepath.Join(dir, "events.jsonl")); err != nil {
		return backup.PostgresStateSummary{}, err
	}
	if err := verifyFileArtifact(manifest, "postgres-state", filepath.Join(dir, "postgres-state.jsonl")); err != nil {
		return backup.PostgresStateSummary{}, err
	}
	eventFile, err := os.Open(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return backup.PostgresStateSummary{}, fmt.Errorf("open event log for full-restore preflight: %w", err)
	}
	postgresFile, err := os.Open(filepath.Join(dir, "postgres-state.jsonl"))
	if err != nil {
		_ = eventFile.Close()
		return backup.PostgresStateSummary{}, fmt.Errorf("open postgres state for full-restore preflight: %w", err)
	}
	preflightErr := verifyFullRestoreArtifactPair(eventFile, postgresFile)
	eventCloseErr := eventFile.Close()
	postgresCloseErr := postgresFile.Close()
	if preflightErr != nil {
		return backup.PostgresStateSummary{}, preflightErr
	}
	if eventCloseErr != nil {
		return backup.PostgresStateSummary{}, fmt.Errorf("close event log after full-restore preflight: %w", eventCloseErr)
	}
	if postgresCloseErr != nil {
		return backup.PostgresStateSummary{}, fmt.Errorf("close postgres state after full-restore preflight: %w", postgresCloseErr)
	}
	for _, spec := range []struct {
		name string
		src  string
		dst  string
	}{
		{"audit-signing-key", filepath.Join(dir, "files", "audit-signing-key.pem"), cfg.Audit.SigningKeyFile},
		{"signer-auth-secret", filepath.Join(dir, "files", "signer-auth-secret.bin"), cfg.Signer.AuthSecretFile},
		{"ca-certificate", filepath.Join(dir, "files", "issuing-ca.crt"), cfg.CA.CertFile},
	} {
		if err := restoreFileArtifact(manifest, spec.name, dir, spec.src, spec.dst, enc.key); err != nil {
			return backup.PostgresStateSummary{}, err
		}
	}
	if err := restoreDirArtifact(manifest, "signer-keystore", dir, filepath.Join(dir, "files", "signer-keystore"), cfg.Signer.KeyStoreDir, enc.key); err != nil {
		return backup.PostgresStateSummary{}, fmt.Errorf("restore signer keystore: %w", err)
	}

	if _, err := restoreEventLog(ctx, cfg, filepath.Join(dir, "events.jsonl"), true); err != nil {
		return backup.PostgresStateSummary{}, err
	}
	st, err := store.Open(ctx, cfg.Postgres.DSN)
	if err != nil {
		return backup.PostgresStateSummary{}, fmt.Errorf("open store for postgres state restore: %w", err)
	}
	defer st.Close()
	f, err := os.Open(filepath.Join(dir, "postgres-state.jsonl"))
	if err != nil {
		return backup.PostgresStateSummary{}, fmt.Errorf("open postgres state backup: %w", err)
	}
	defer func() { _ = f.Close() }()
	summary, err := backup.RestorePostgresState(ctx, st, f)
	if err != nil {
		return summary, err
	}

	// restoreEventLog rebuilds once before PostgreSQL state is imported because
	// independent rows may reference the rebuilt model. Importing that state can
	// deliberately replace an event-populated durable receiver with the backup
	// cut's older contents. Rebuild once more after the import so a source event
	// that survived an append-ACK/projection-failure crash heals the receiver
	// AFTER the PostgreSQL artifact has finished replacing independent state.
	//
	// Rebuild preserves independent tables, so rows present in the PostgreSQL
	// artifact remain intact while any missing event-derived receiver is restored.
	auditKey, err := audit.LoadOrCreateSigningKey(cfg.Audit.SigningKeyFile, "audit-export")
	if err != nil {
		return summary, fmt.Errorf("audit signing key for final full-restore rebuild: %w", err)
	}
	log, err := openHistoryAwareEventLog(ctx, cfg.NATS, st, auditKey)
	if err != nil {
		return summary, fmt.Errorf("open event log for final full-restore rebuild: %w", err)
	}
	defer func() { _ = log.Close() }()
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		return summary, fmt.Errorf("final read-model rebuild after postgres state restore: %w", err)
	}
	return summary, nil
}

// verifyFullRestoreArtifactPair is the mutation-free wall before full restore.
// Each artifact must be independently integrity/structure valid, and both must
// name the exact same event cut. Otherwise sequence-bound PostgreSQL evidence
// could be attached to a different event history even though each file is valid
// in isolation.
func verifyFullRestoreArtifactPair(
	eventArtifact io.Reader,
	postgresArtifact io.Reader,
) error {
	postgresSummary, err := backup.VerifyPostgresState(postgresArtifact)
	if err != nil {
		return fmt.Errorf("full restore postgres-state preflight: %w", err)
	}
	eventSummary, err := backup.VerifyEventLogBackupWithAuditCheckpoints(
		eventArtifact,
		nil,
		postgresSummary.AuditCheckpoints,
	)
	if err != nil {
		return fmt.Errorf("full restore event-log preflight: %w", err)
	}
	if eventSummary.EventCutSequence != postgresSummary.EventCutSequence {
		return fmt.Errorf(
			"full restore artifact cut mismatch: event log names cut %d but postgres state names cut %d; refusing before any restore mutation",
			eventSummary.EventCutSequence,
			postgresSummary.EventCutSequence,
		)
	}
	if eventSummary.HasGaps {
		return errors.New(
			"full restore event history contains unexplained deleted positions; " +
				"logical audit retention retains AN-2 source envelopes, so this is a legacy or externally damaged artifact; refusing before any restore mutation",
		)
	}
	return nil
}

// RunRebuild atomically re-derives the read model from the event log already
// present (RESIL-003) and returns the number of events replayed. Unlike RunRestore
// it does NOT require an empty event store: it is the recovery path when the read
// model has diverged or a prior restore was interrupted, re-projecting from the
// intact log without re-appending anything. The rebuild is atomic (truncate +
// replay in one transaction), so an interrupted rebuild rolls back to the prior read
// model rather than leaving a partial inventory. It requires external Postgres and
// NATS (the operational datastores), like restore.
func RunRebuild(ctx context.Context, cfg *config.Config) (int, error) {
	if cfg.NATS.Mode != config.NATSExternal || cfg.NATS.URL == "" {
		return 0, errors.New("rebuild requires an external event store (set TRSTCTL_NATS_MODE=external and TRSTCTL_NATS_URL)")
	}
	if cfg.Postgres.Mode != config.PostgresExternal || cfg.Postgres.DSN == "" {
		return 0, errors.New("rebuild requires an external Postgres (set TRSTCTL_POSTGRES_MODE=external and TRSTCTL_POSTGRES_DSN)")
	}
	st, err := store.Open(ctx, cfg.Postgres.DSN)
	if err != nil {
		return 0, fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return 0, fmt.Errorf("migrate: %w", err)
	}

	auditKey, err := audit.LoadOrCreateSigningKey(cfg.Audit.SigningKeyFile, "audit-export")
	if err != nil {
		return 0, fmt.Errorf("audit signing key: %w", err)
	}
	log, err := openHistoryAwareEventLog(ctx, cfg.NATS, st, auditKey)
	if err != nil {
		return 0, fmt.Errorf("open event log: %w", err)
	}
	defer func() { _ = log.Close() }()

	// Count what we replay so the operator gets a concrete confirmation.
	n := 0
	if err := log.Replay(ctx, 0, func(events.Event) error { n++; return nil }); err != nil {
		return 0, fmt.Errorf("count event log: %w", err)
	}
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		return 0, fmt.Errorf("rebuild read model: %w", err)
	}
	return n, nil
}

type fullBackupEncryption struct {
	key              []byte
	keyID            string
	allowUnencrypted bool
}

func fullBackupEncryptionFromConfig(cfg *config.Config) (*fullBackupEncryption, error) {
	enc := &fullBackupEncryption{allowUnencrypted: cfg.Backup.AllowUnencrypted}
	if cfg.Backup.EncryptionKeyFile == "" {
		return enc, nil
	}
	key, err := os.ReadFile(cfg.Backup.EncryptionKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read full-backup encryption key: %w", err)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("read full-backup encryption key: key file is empty")
	}
	keyID, err := backup.BackupArtifactKeyID(key)
	if err != nil {
		secret.Wipe(key)
		return nil, err
	}
	enc.key = key
	enc.keyID = keyID
	return enc, nil
}

func (e *fullBackupEncryption) enabled() bool {
	return e != nil && len(e.key) > 0
}

func (e *fullBackupEncryption) wipe() {
	if e != nil {
		secret.Wipe(e.key)
	}
}

func (e *fullBackupEncryption) manifestEncryption() backup.FullBackupEncryption {
	if e.enabled() {
		return backup.FullBackupEncryption{
			Mode:                        "operator-key-file",
			Algorithm:                   backup.FullBackupArtifactEncryptionAlgorithm,
			KeyID:                       e.keyID,
			SensitiveArtifactsEncrypted: true,
		}
	}
	return backup.FullBackupEncryption{
		Mode:                        "explicit-plaintext-override",
		SensitiveArtifactsEncrypted: false,
		AllowUnencryptedSensitiveArtifactsOverride: true,
	}
}

func fileArtifact(name, role, src, dst string, capture, requireCaptured, sensitive, required bool, backupDir string, enc *fullBackupEncryption) (backup.Artifact, error) {
	a := backup.Artifact{Name: name, Role: role, SourcePath: src, Sensitive: sensitive, Required: required}
	if src == "" {
		if required {
			return a, fmt.Errorf("backup: required artifact %s has no configured source path", name)
		}
		return a, nil
	}
	sum, n, err := backup.HashFile(src)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !required {
			return a, nil
		}
		return a, fmt.Errorf("backup: hash %s: %w", name, err)
	}
	a.Exists = true
	a.SHA256 = sum
	a.Bytes = n
	if capture {
		if sensitive && enc != nil && enc.enabled() {
			target := dst + ".enc"
			plainSHA, plainBytes, storedSHA, storedBytes, err := backup.WriteEncryptedFile(src, target, enc.key, backup.FullBackupArtifactAAD(name), 0o600)
			if err != nil {
				return a, fmt.Errorf("backup: encrypt %s: %w", name, err)
			}
			a.PlaintextSHA256 = plainSHA
			a.PlaintextBytes = plainBytes
			a.SHA256 = storedSHA
			a.Bytes = storedBytes
			a.Encryption = &backup.ArtifactEncryption{
				Algorithm: backup.FullBackupArtifactEncryptionAlgorithm,
				KeyID:     enc.keyID,
				AAD:       backup.FullBackupArtifactAAD(name),
			}
			a.Captured = true
			a.Path = backupManifestPath(backupDir, target)
			return a, nil
		}
		if src != dst {
			if err := backup.CopyFile(src, dst, 0o600); err != nil {
				return a, fmt.Errorf("backup: copy %s: %w", name, err)
			}
		}
		a.Captured = true
		a.Path = backupManifestPath(backupDir, dst)
	} else {
		if requireCaptured {
			return a, fmt.Errorf("backup: required artifact %s was not captured", name)
		}
		a.Path = src
	}
	return a, nil
}

func dirArtifact(name, role, src, dst string, capture, sensitive, required bool, backupDir string, enc *fullBackupEncryption) (backup.Artifact, error) {
	a := backup.Artifact{Name: name, Role: role, SourcePath: src, Sensitive: sensitive, Required: required}
	if src == "" {
		if required {
			return a, fmt.Errorf("backup: required artifact %s has no configured source path", name)
		}
		return a, nil
	}
	sum, n, err := backup.HashTree(src)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !required {
			return a, nil
		}
		return a, fmt.Errorf("backup: hash %s: %w", name, err)
	}
	a.Exists = true
	a.SHA256 = sum
	a.Bytes = n
	if capture {
		if sensitive && enc != nil && enc.enabled() {
			target := dst + ".enc"
			plainSHA, plainBytes, storedSHA, storedBytes, err := backup.WriteEncryptedTree(src, target, enc.key, backup.FullBackupArtifactAAD(name))
			if err != nil {
				return a, fmt.Errorf("backup: encrypt %s: %w", name, err)
			}
			a.PlaintextSHA256 = plainSHA
			a.PlaintextBytes = plainBytes
			a.SHA256 = storedSHA
			a.Bytes = storedBytes
			a.Encryption = &backup.ArtifactEncryption{
				Algorithm: backup.FullBackupArtifactEncryptionAlgorithm,
				KeyID:     enc.keyID,
				AAD:       backup.FullBackupArtifactAAD(name),
			}
			a.Captured = true
			a.Path = backupManifestPath(backupDir, target)
			return a, nil
		}
		if err := backup.CopyTree(src, dst); err != nil {
			return a, fmt.Errorf("backup: copy %s: %w", name, err)
		}
		a.Captured = true
		a.Path = backupManifestPath(backupDir, dst)
	}
	return a, nil
}

func backupManifestPath(baseDir, path string) string {
	if baseDir != "" {
		if rel, err := filepath.Rel(baseDir, path); err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(path)
}

func requireExistingFile(path, name string) error {
	if path == "" {
		return fmt.Errorf("restore requires %s path to be configured", name)
	}
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("restore requires %s at %s: %w", name, path, err)
	}
	if st.IsDir() {
		return fmt.Errorf("restore requires %s at %s to be a file", name, path)
	}
	return nil
}

func verifyFileArtifact(m backup.FullManifest, name, path string) error {
	a, ok := manifestArtifact(m, name)
	if !ok {
		return fmt.Errorf("restore: manifest missing artifact %s", name)
	}
	sum, n, err := backup.HashFile(path)
	if err != nil {
		return fmt.Errorf("restore: hash artifact %s: %w", name, err)
	}
	if sum != a.SHA256 || n != a.Bytes {
		return fmt.Errorf("restore: artifact %s hash/size mismatch", name)
	}
	return nil
}

func restoreFileArtifact(m backup.FullManifest, name, backupDir, fallbackSrc, dst string, encryptionKey []byte) error {
	a, ok := manifestArtifact(m, name)
	if !ok {
		return fmt.Errorf("restore: manifest missing artifact %s", name)
	}
	src := artifactPath(backupDir, a, fallbackSrc)
	if err := verifyStoredFileArtifact(a, name, src); err != nil {
		return err
	}
	if a.Encryption != nil {
		if len(encryptionKey) == 0 {
			return fmt.Errorf("restore: artifact %s is encrypted but no full-backup encryption key is configured", name)
		}
		if err := validateArtifactEncryption(a, name); err != nil {
			return err
		}
		sum, n, err := backup.RestoreEncryptedFile(src, dst, encryptionKey, a.Encryption.AAD, 0o600)
		if err != nil {
			return fmt.Errorf("restore %s: %w", dst, err)
		}
		if sum != a.PlaintextSHA256 || n != a.PlaintextBytes {
			return fmt.Errorf("restore: artifact %s plaintext hash/size mismatch", name)
		}
		return nil
	}
	if err := backup.CopyFile(src, dst, 0o600); err != nil {
		return fmt.Errorf("restore %s: %w", dst, err)
	}
	return nil
}

func restoreDirArtifact(m backup.FullManifest, name, backupDir, fallbackSrc, dst string, encryptionKey []byte) error {
	a, ok := manifestArtifact(m, name)
	if !ok {
		return fmt.Errorf("restore: manifest missing artifact %s", name)
	}
	src := artifactPath(backupDir, a, fallbackSrc)
	if err := verifyStoredDirArtifact(a, name, src); err != nil {
		return err
	}
	if a.Encryption != nil {
		if len(encryptionKey) == 0 {
			return fmt.Errorf("restore: artifact %s is encrypted but no full-backup encryption key is configured", name)
		}
		if err := validateArtifactEncryption(a, name); err != nil {
			return err
		}
		sum, n, err := backup.RestoreEncryptedTree(src, dst, encryptionKey, a.Encryption.AAD)
		if err != nil {
			return err
		}
		if sum != a.PlaintextSHA256 || n != a.PlaintextBytes {
			return fmt.Errorf("restore: artifact %s plaintext hash/size mismatch", name)
		}
		return nil
	}
	if err := backup.CopyTree(src, dst); err != nil {
		return err
	}
	return nil
}

func verifyStoredFileArtifact(a backup.Artifact, name, path string) error {
	sum, n, err := backup.HashFile(path)
	if err != nil {
		return fmt.Errorf("restore: hash artifact %s: %w", name, err)
	}
	if sum != a.SHA256 || n != a.Bytes {
		return fmt.Errorf("restore: artifact %s hash/size mismatch", name)
	}
	return nil
}

func verifyStoredDirArtifact(a backup.Artifact, name, path string) error {
	sum, n, err := backup.HashTree(path)
	if err != nil {
		return fmt.Errorf("restore: hash artifact %s: %w", name, err)
	}
	if sum != a.SHA256 || n != a.Bytes {
		return fmt.Errorf("restore: artifact %s hash/size mismatch", name)
	}
	return nil
}

func artifactPath(backupDir string, a backup.Artifact, fallback string) string {
	if a.Path == "" {
		return fallback
	}
	path := filepath.FromSlash(a.Path)
	if filepath.IsAbs(path) {
		if _, err := os.Stat(path); err == nil {
			return path
		}
		return fallback
	}
	return filepath.Join(backupDir, path)
}

func validateArtifactEncryption(a backup.Artifact, name string) error {
	if a.Encryption.Algorithm != backup.FullBackupArtifactEncryptionAlgorithm {
		return fmt.Errorf("restore: artifact %s uses unsupported encryption algorithm %q", name, a.Encryption.Algorithm)
	}
	if a.Encryption.AAD == "" || a.Encryption.KeyID == "" {
		return fmt.Errorf("restore: artifact %s encryption metadata is incomplete", name)
	}
	if a.PlaintextSHA256 == "" || a.PlaintextBytes < 0 {
		return fmt.Errorf("restore: artifact %s missing plaintext digest metadata", name)
	}
	return nil
}

func requireFullBackupEncryptionForRestore(m backup.FullManifest, enc *fullBackupEncryption) error {
	for _, a := range m.Artifacts {
		if !a.Sensitive || !a.Captured {
			continue
		}
		if a.Encryption != nil {
			if !enc.enabled() {
				return fmt.Errorf("restore: sensitive artifact %s is encrypted; set TRSTCTL_BACKUP_ENCRYPTION_KEY_FILE", a.Name)
			}
			if a.Encryption.KeyID != enc.keyID {
				return fmt.Errorf("restore: full-backup encryption key does not match artifact %s", a.Name)
			}
			continue
		}
		if enc == nil || !enc.allowUnencrypted {
			return fmt.Errorf("restore: sensitive artifact %s is unencrypted; set TRSTCTL_BACKUP_ALLOW_UNENCRYPTED=true for an explicit legacy/lab restore", a.Name)
		}
	}
	return nil
}

func manifestArtifact(m backup.FullManifest, name string) (backup.Artifact, bool) {
	for _, a := range m.Artifacts {
		if a.Name == name {
			return a, true
		}
	}
	return backup.Artifact{}, false
}
