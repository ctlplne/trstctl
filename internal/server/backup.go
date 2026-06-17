package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

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

	var artifacts []backup.Artifact
	eventsPath := filepath.Join(dir, "events.jsonl")
	if _, err := RunBackup(ctx, cfg, eventsPath); err != nil {
		return backup.FullManifest{}, err
	}
	a, err := fileArtifact("event-log", "event-log", eventsPath, eventsPath, true, true, false, true)
	if err != nil {
		return backup.FullManifest{}, err
	}
	artifacts = append(artifacts, a)

	st, err := store.Open(ctx, cfg.Postgres.DSN)
	if err != nil {
		return backup.FullManifest{}, fmt.Errorf("open store for full backup: %w", err)
	}
	defer st.Close()
	pgPath := filepath.Join(dir, "postgres-state.jsonl")
	pgFile, err := os.OpenFile(pgPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return backup.FullManifest{}, fmt.Errorf("create postgres state backup: %w", err)
	}
	if _, err := backup.WritePostgresState(ctx, st, pgFile); err != nil {
		_ = pgFile.Close()
		return backup.FullManifest{}, err
	}
	if err := pgFile.Close(); err != nil {
		return backup.FullManifest{}, fmt.Errorf("close postgres state backup: %w", err)
	}
	a, err = fileArtifact("postgres-state", "postgres-state", pgPath, pgPath, true, true, false, true)
	if err != nil {
		return backup.FullManifest{}, err
	}
	artifacts = append(artifacts, a)

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
		a, err := fileArtifact(spec.name, spec.role, spec.src, spec.dst, spec.capture, false, spec.sensitive, spec.required)
		if err != nil {
			return backup.FullManifest{}, err
		}
		artifacts = append(artifacts, a)
	}
	keyStoreArtifact, err := dirArtifact("signer-keystore", "signer-keystore", cfg.Signer.KeyStoreDir, filepath.Join(dir, "files", "signer-keystore"), true, true, true)
	if err != nil {
		return backup.FullManifest{}, err
	}
	artifacts = append(artifacts, keyStoreArtifact)

	manifest := backup.NewFullManifest(artifacts)
	if err := backup.WriteFullManifest(filepath.Join(dir, backup.FullManifestName), manifest); err != nil {
		return backup.FullManifest{}, err
	}
	return manifest, nil
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

// RunFullRestore restores a full DR artifact directory created by RunFullBackup.
// The deployment KEK is deliberately not copied into the artifact; operators must
// restore it separately at cfg.Secrets.KEKFile before invoking this function.
func RunFullRestore(ctx context.Context, cfg *config.Config, dir string) (backup.PostgresStateSummary, error) {
	manifest, err := backup.ReadFullManifest(filepath.Join(dir, backup.FullManifestName))
	if err != nil {
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
	for _, spec := range []struct {
		name string
		src  string
		dst  string
	}{
		{"audit-signing-key", filepath.Join(dir, "files", "audit-signing-key.pem"), cfg.Audit.SigningKeyFile},
		{"signer-auth-secret", filepath.Join(dir, "files", "signer-auth-secret.bin"), cfg.Signer.AuthSecretFile},
		{"ca-certificate", filepath.Join(dir, "files", "issuing-ca.crt"), cfg.CA.CertFile},
	} {
		if err := verifyFileArtifact(manifest, spec.name, spec.src); err != nil {
			return backup.PostgresStateSummary{}, err
		}
		if err := backup.CopyFile(spec.src, spec.dst, 0o600); err != nil {
			return backup.PostgresStateSummary{}, fmt.Errorf("restore %s: %w", spec.dst, err)
		}
	}
	if err := verifyDirArtifact(manifest, "signer-keystore", filepath.Join(dir, "files", "signer-keystore")); err != nil {
		return backup.PostgresStateSummary{}, err
	}
	if err := backup.CopyTree(filepath.Join(dir, "files", "signer-keystore"), cfg.Signer.KeyStoreDir); err != nil {
		return backup.PostgresStateSummary{}, fmt.Errorf("restore signer keystore: %w", err)
	}

	if _, err := RunRestore(ctx, cfg, filepath.Join(dir, "events.jsonl")); err != nil {
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
	return backup.RestorePostgresState(ctx, st, f)
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

func fileArtifact(name, role, src, dst string, capture, requireCaptured, sensitive, required bool) (backup.Artifact, error) {
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
		if src != dst {
			if err := backup.CopyFile(src, dst, 0o600); err != nil {
				return a, fmt.Errorf("backup: copy %s: %w", name, err)
			}
		}
		a.Captured = true
		a.Path = filepath.ToSlash(dst)
	} else {
		if requireCaptured {
			return a, fmt.Errorf("backup: required artifact %s was not captured", name)
		}
		a.Path = src
	}
	return a, nil
}

func dirArtifact(name, role, src, dst string, capture, sensitive, required bool) (backup.Artifact, error) {
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
		if err := backup.CopyTree(src, dst); err != nil {
			return a, fmt.Errorf("backup: copy %s: %w", name, err)
		}
		a.Captured = true
		a.Path = filepath.ToSlash(dst)
	}
	return a, nil
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

func verifyDirArtifact(m backup.FullManifest, name, path string) error {
	a, ok := manifestArtifact(m, name)
	if !ok {
		return fmt.Errorf("restore: manifest missing artifact %s", name)
	}
	sum, n, err := backup.HashTree(path)
	if err != nil {
		return fmt.Errorf("restore: hash artifact %s: %w", name, err)
	}
	if sum != a.SHA256 || n != a.Bytes {
		return fmt.Errorf("restore: artifact %s hash/size mismatch", name)
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
