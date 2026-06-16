package server

import (
	"context"
	"errors"
	"fmt"
	"os"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
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
	log, err := events.Open(ctx, cfg.NATS)
	if err != nil {
		return 0, fmt.Errorf("open event log: %w", err)
	}
	defer func() { _ = log.Close() }()

	key, err := backupIntegrityKey(cfg)
	if err != nil {
		return 0, err
	}

	f, err := os.Create(path)
	if err != nil {
		return 0, fmt.Errorf("create backup file: %w", err)
	}
	defer func() { _ = f.Close() }()

	// The stream carries a SHA-256 integrity trailer always, and an HMAC bound to
	// this deployment's audit key when one is configured (OPS-006), so a tampered
	// or truncated backup is rejected on restore.
	n, err := backup.WriteLogWithKey(ctx, log, f, key)
	if err != nil {
		return n, err
	}
	if err := f.Close(); err != nil { // flush to disk before reporting success
		return n, fmt.Errorf("close backup file: %w", err)
	}
	return n, nil
}

// RunRestore restores the event log from a backup at path and rebuilds the read
// model purely from it (AN-2 / R1.1) — reconstructing the control plane's state.
// It requires external Postgres and NATS (the recovered datastores), and the
// event store must be empty. It returns the number of events restored.
func RunRestore(ctx context.Context, cfg *config.Config, path string) (int, error) {
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

	st, err := store.Open(ctx, cfg.Postgres.DSN)
	if err != nil {
		return 0, fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return 0, fmt.Errorf("migrate: %w", err)
	}

	log, err := events.Open(ctx, cfg.NATS)
	if err != nil {
		return 0, fmt.Errorf("open event log: %w", err)
	}
	defer func() { _ = log.Close() }()

	// Verify integrity before appending anything (OPS-006). The SHA-256 trailer is
	// always enforced; when this recovery host already holds the deployment's audit
	// signing key we additionally require the backup's HMAC to verify under it.
	// (On a bare recovery host without the key yet, the checksum still guards
	// against truncation/bit-flips so a corrupt artifact is rejected.)
	key, err := backupIntegrityKey(cfg)
	if err != nil {
		return 0, err
	}
	n, err := backup.RestoreLogWithKey(ctx, log, f, key)
	if err != nil {
		return n, err
	}
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		return n, fmt.Errorf("rebuild read model from restored log: %w", err)
	}
	return n, nil
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

	log, err := events.Open(ctx, cfg.NATS)
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
