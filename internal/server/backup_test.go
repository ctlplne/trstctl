// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
)

func TestRunBackupRequiresExternalPostgresHistoryCoordinator(t *testing.T) {
	cfg := config.Default()
	cfg.NATS.Mode = config.NATSExternal
	cfg.NATS.URL = "nats://127.0.0.1:1"
	cfg.Postgres.Mode = config.PostgresBundled
	cfg.Postgres.DSN = ""

	_, err := RunBackup(context.Background(), cfg, filepath.Join(t.TempDir(), "events.jsonl"))
	if err == nil || !strings.Contains(err.Error(), "external Postgres coordination") {
		t.Fatalf("RunBackup error = %v, want external Postgres history-barrier failure", err)
	}
}

func TestBackupHistoryReadRetainsCheckpointedSourceBeforePinningExport(t *testing.T) {
	ctx := context.Background()
	const (
		tenantA = "11111111-1111-1111-1111-111111111111"
		tenantB = "22222222-2222-2222-2222-222222222222"
	)
	log, err := events.Open(ctx, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	pending, err := log.Append(ctx, events.Event{
		ID: "backup-pending-prune", Type: "owner.created", TenantID: tenantA,
	})
	if err != nil {
		t.Fatal(err)
	}
	other, err := log.Append(ctx, events.Event{
		ID: "backup-other-tenant", Type: "owner.created", TenantID: tenantB,
	})
	if err != nil {
		t.Fatal(err)
	}
	survivor, err := log.Append(ctx, events.Event{
		ID: "backup-after-boundary", Type: "owner.updated", TenantID: tenantA,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkpoints := &backupCheckpointSource{byTenant: map[string]audit.Checkpoint{
		tenantA: {
			TenantID: tenantA, BoundarySeq: pending.Sequence,
			BoundaryHash: "archived-head", RecordCount: 1, ArchiveURI: "memory://archive",
		},
	}}

	competingEntered := make(chan struct{})
	competingDone := make(chan error, 1)
	err = withRecoveredBackupHistoryRead(ctx, log, checkpoints, func(readCtx context.Context) error {
		var live []events.Event
		if err := log.Replay(readCtx, 0, func(event events.Event) error {
			live = append(live, event)
			return nil
		}); err != nil {
			return err
		}
		if len(live) != 3 ||
			live[0].ID != pending.ID || live[0].Sequence != pending.Sequence ||
			live[1].ID != other.ID || live[1].Sequence != other.Sequence ||
			live[2].ID != survivor.ID || live[2].Sequence != survivor.Sequence {
			return fmt.Errorf("pinned backup history = %+v, want all source records at sequences 1, 2, and 3", live)
		}

		// The recovery operation must remain held through the pinned export. A
		// retention/rewrite operation queued here may enter only after fn returns.
		go func() {
			competingDone <- log.WithHistoryOperation(ctx, func(context.Context) error {
				close(competingEntered)
				return nil
			})
		}()
		select {
		case <-competingEntered:
			return errors.New("competing history operation entered during pinned backup export")
		case <-time.After(100 * time.Millisecond):
			return nil
		}
	})
	if err != nil {
		t.Fatalf("withRecoveredBackupHistoryRead: %v", err)
	}
	select {
	case err := <-competingDone:
		if err != nil {
			t.Fatalf("competing history operation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("competing history operation did not continue after backup released")
	}
	if strings.Join(checkpoints.queried, ",") != tenantA {
		t.Fatalf("checkpoint lookup order = %v, want checkpoint tenant A", checkpoints.queried)
	}
	var exact []events.BackupHistoryRecord
	if err := log.ExportBackupHistoryThrough(ctx, survivor.Sequence, func(record events.BackupHistoryRecord) error {
		exact = append(exact, record)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(exact) != 3 || exact[0].IsGap() ||
		exact[0].Sequence != pending.Sequence || exact[0].Event.ID != pending.ID {
		t.Fatalf("pre-backup history = %+v, want retained source event at sequence 1", exact)
	}
}

func TestBackupHistoryReadFailsClosedOnCheckpointBeyondEventHead(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	log, err := events.Open(ctx, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	event, err := log.Append(ctx, events.Event{
		ID: "backup-head", Type: "owner.created", TenantID: tenantID,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkpoints := &backupCheckpointSource{byTenant: map[string]audit.Checkpoint{
		tenantID: {
			TenantID: tenantID, BoundarySeq: event.Sequence + 1,
			BoundaryHash: "ahead", RecordCount: 1, ArchiveURI: "memory://ahead",
		},
	}}
	exported := false
	err = withRecoveredBackupHistoryRead(ctx, log, checkpoints, func(context.Context) error {
		exported = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "outside event head") {
		t.Fatalf("withRecoveredBackupHistoryRead error = %v, want ahead-of-log rejection", err)
	}
	if exported {
		t.Fatal("backup export started with an incoherent checkpoint boundary")
	}
	got, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got != event.Sequence {
		t.Fatalf("failed recovery changed event head to %d, want %d", got, event.Sequence)
	}
}

func TestBackupHistoryReadRejectsLegacyCheckpointedPruneWithoutDeletingMore(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	log, err := events.Open(ctx, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	first, err := log.Append(ctx, events.Event{
		ID: "legacy-pruned-one", Type: "tenant.registered", TenantID: tenantID,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := log.Append(ctx, events.Event{
		ID: "legacy-pruned-two", Type: "owner.created", TenantID: tenantID,
	})
	if err != nil {
		t.Fatal(err)
	}
	//nolint:staticcheck // Model a legacy physical-retention artifact at the served restore boundary.
	if err := log.PruneTenantThroughCheckpoint(ctx, tenantID, second.Sequence, nil); err != nil {
		t.Fatalf("simulate legacy physical retention: %v", err)
	}
	checkpoints := &backupCheckpointSource{byTenant: map[string]audit.Checkpoint{
		tenantID: {
			TenantID: tenantID, BoundarySeq: second.Sequence,
			BoundaryHash: "legacy-head", RecordCount: 2, ArchiveURI: "memory://legacy",
		},
	}}
	exported := false
	err = withRecoveredBackupHistoryRead(ctx, log, checkpoints, func(context.Context) error {
		exported = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "retained 0 of 2") {
		t.Fatalf("legacy prune error = %v, want incomplete retained-source rejection", err)
	}
	if exported {
		t.Fatal("backup export began after legacy retention removed its AN-2 source")
	}
	var history []events.BackupHistoryRecord
	if err := log.ExportBackupHistoryThrough(ctx, second.Sequence, func(record events.BackupHistoryRecord) error {
		history = append(history, record)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || !history[0].IsGap() ||
		history[0].Sequence != first.Sequence || history[0].GapThrough != second.Sequence {
		t.Fatalf("legacy history changed during rejection: %+v", history)
	}
}

type backupCheckpointSource struct {
	byTenant map[string]audit.Checkpoint
	queried  []string
}

func (s *backupCheckpointSource) ListAuditCheckpointTenants(context.Context) ([]string, error) {
	tenants := make([]string, 0, len(s.byTenant))
	for tenantID := range s.byTenant {
		tenants = append(tenants, tenantID)
	}
	sort.Strings(tenants)
	return tenants, nil
}

func (s *backupCheckpointSource) LatestAuditCheckpoint(
	_ context.Context,
	tenantID string,
) (audit.Checkpoint, bool, error) {
	s.queried = append(s.queried, tenantID)
	checkpoint, ok := s.byTenant[tenantID]
	return checkpoint, ok, nil
}

func TestFullBackupEncryptsSensitiveArtifacts(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "signer-auth-secret.bin")
	secretBytes := []byte("signer-auth-token-material")
	if err := os.WriteFile(src, secretBytes, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	defer secret.Wipe(key)
	keyID, err := backup.BackupArtifactKeyID(key)
	if err != nil {
		t.Fatalf("BackupArtifactKeyID: %v", err)
	}
	enc := &fullBackupEncryption{key: key, keyID: keyID}

	artifact, err := fileArtifact(
		"signer-auth-secret",
		"signer-auth-secret",
		src,
		filepath.Join(dir, "backup", "files", "signer-auth-secret.bin"),
		true,
		false,
		true,
		true,
		filepath.Join(dir, "backup"),
		enc,
	)
	if err != nil {
		t.Fatalf("fileArtifact: %v", err)
	}
	if artifact.Encryption == nil {
		t.Fatal("sensitive artifact was captured without encryption metadata")
	}
	stored, err := os.ReadFile(filepath.Join(dir, "backup", filepath.FromSlash(artifact.Path)))
	if err != nil {
		t.Fatalf("read encrypted artifact: %v", err)
	}
	if bytes.Contains(stored, secretBytes) {
		t.Fatal("encrypted backup artifact still contains signer auth material in plaintext")
	}
	if artifact.PlaintextSHA256 == "" || artifact.PlaintextBytes == 0 {
		t.Fatal("encrypted artifact manifest must keep plaintext digest metadata for restore verification")
	}
}

func TestFullRestoreDecryptsEncryptedArtifact(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "audit-signing-key.pem")
	want := []byte("audit-signing-private-key")
	if err := os.WriteFile(src, want, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	key := []byte("abcdef0123456789abcdef0123456789")
	defer secret.Wipe(key)
	keyID, err := backup.BackupArtifactKeyID(key)
	if err != nil {
		t.Fatalf("BackupArtifactKeyID: %v", err)
	}
	enc := &fullBackupEncryption{key: key, keyID: keyID}
	backupDir := filepath.Join(dir, "backup")

	artifact, err := fileArtifact(
		"audit-signing-key",
		"audit-signing-key",
		src,
		filepath.Join(backupDir, "files", "audit-signing-key.pem"),
		true,
		false,
		true,
		true,
		backupDir,
		enc,
	)
	if err != nil {
		t.Fatalf("fileArtifact: %v", err)
	}
	manifest := backup.NewFullManifest([]backup.Artifact{artifact})
	restored := filepath.Join(dir, "restore", "audit-signing-key.pem")
	if err := restoreFileArtifact(manifest, "audit-signing-key", backupDir, "files/audit-signing-key.pem", restored, key); err != nil {
		t.Fatalf("restoreFileArtifact: %v", err)
	}
	got, err := os.ReadFile(restored)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("restored artifact = %q, want %q", got, want)
	}
}

func TestFullRestoreArtifactPairPreflightRequiresMatchingCuts(t *testing.T) {
	eventArtifact := fullRestoreEmptyEventArtifact(t)
	matchedPostgres := fullRestoreEmptyPostgresArtifact(t, 0)
	if err := verifyFullRestoreArtifactPair(
		bytes.NewReader(eventArtifact),
		bytes.NewReader(matchedPostgres),
	); err != nil {
		t.Fatalf("matching full-restore artifacts rejected: %v", err)
	}

	mismatchedPostgres := fullRestoreEmptyPostgresArtifact(t, 1)
	err := verifyFullRestoreArtifactPair(
		bytes.NewReader(eventArtifact),
		bytes.NewReader(mismatchedPostgres),
	)
	if err == nil {
		t.Fatal("full-restore preflight accepted event cut 0 paired with postgres cut 1")
	}
	for _, want := range []string{"cut mismatch", "event log names cut 0", "postgres state names cut 1", "before any restore mutation"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("mismatch error = %v, want %q", err, want)
		}
	}
}

func fullRestoreEmptyEventArtifact(t *testing.T) []byte {
	t.Helper()
	type eventHeader struct {
		Format           string    `json:"format"`
		Version          int       `json:"version"`
		CreatedAt        time.Time `json:"created_at"`
		EventCutSequence uint64    `json:"event_cut_sequence,omitempty"`
		HistoryLayout    string    `json:"history_layout,omitempty"`
	}
	type eventTrailer struct {
		Format           string `json:"format"`
		SHA256           string `json:"sha256"`
		Records          int    `json:"records"`
		Entries          int    `json:"entries,omitempty"`
		EventCutSequence uint64 `json:"event_cut_sequence,omitempty"`
		HistoryLayout    string `json:"history_layout,omitempty"`
	}
	var prefix bytes.Buffer
	if err := json.NewEncoder(&prefix).Encode(eventHeader{
		Format: "trstctl-event-log-backup", Version: 2,
		CreatedAt: time.Unix(0, 0).UTC(), HistoryLayout: "exact-sequence-v1",
	}); err != nil {
		t.Fatal(err)
	}
	var artifact bytes.Buffer
	artifact.Write(prefix.Bytes())
	if err := json.NewEncoder(&artifact).Encode(eventTrailer{
		Format:        "trstctl-event-log-backup-trailer",
		SHA256:        crypto.SHA256Hex(prefix.Bytes()),
		Records:       0,
		HistoryLayout: "exact-sequence-v1",
	}); err != nil {
		t.Fatal(err)
	}
	return artifact.Bytes()
}

func fullRestoreEmptyPostgresArtifact(t *testing.T, cut uint64) []byte {
	t.Helper()
	type postgresHeader struct {
		Format           string    `json:"format"`
		Version          int       `json:"version"`
		CreatedAt        time.Time `json:"created_at"`
		Tables           []string  `json:"tables"`
		EventCutSequence uint64    `json:"event_cut_sequence,omitempty"`
	}
	type postgresTrailer struct {
		Format           string         `json:"format"`
		SHA256           string         `json:"sha256"`
		Records          int            `json:"records"`
		Tables           map[string]int `json:"tables"`
		EventCutSequence uint64         `json:"event_cut_sequence,omitempty"`
	}
	tables := append([]string(nil), backup.RecoveredFromPostgresBackup...)
	sort.Strings(tables)
	var prefix bytes.Buffer
	if err := json.NewEncoder(&prefix).Encode(postgresHeader{
		Format: "trstctl-postgres-state-backup", Version: 1,
		CreatedAt: time.Unix(0, 0).UTC(), Tables: tables,
		EventCutSequence: cut,
	}); err != nil {
		t.Fatal(err)
	}
	var artifact bytes.Buffer
	artifact.Write(prefix.Bytes())
	if err := json.NewEncoder(&artifact).Encode(postgresTrailer{
		Format:  "trstctl-postgres-state-backup-trailer",
		SHA256:  crypto.SHA256Hex(prefix.Bytes()),
		Records: 0, Tables: map[string]int{},
		EventCutSequence: cut,
	}); err != nil {
		t.Fatal(err)
	}
	return artifact.Bytes()
}

func TestFullBackupDirectoryArtifactsRestoreAndVerify(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "event-log")
	if err := os.MkdirAll(filepath.Join(src, "stream"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "stream", "events.dat"), []byte("event log bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(dir, "backup")

	artifact, err := dirArtifact("event-log", "event-log", src, filepath.Join(backupDir, "event-log"), true, false, true, backupDir, nil)
	if err != nil {
		t.Fatalf("dirArtifact: %v", err)
	}
	if !artifact.Captured || artifact.Path != "event-log" || artifact.SHA256 == "" || artifact.Bytes == 0 {
		t.Fatalf("captured directory artifact incomplete: %+v", artifact)
	}
	if err := verifyStoredDirArtifact(artifact, "event-log", filepath.Join(backupDir, filepath.FromSlash(artifact.Path))); err != nil {
		t.Fatalf("verifyStoredDirArtifact: %v", err)
	}
	restored := filepath.Join(dir, "restore", "event-log")
	if err := restoreDirArtifact(backup.NewFullManifest([]backup.Artifact{artifact}), "event-log", backupDir, "", restored, nil); err != nil {
		t.Fatalf("restoreDirArtifact: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(restored, "stream", "events.dat"))
	if err != nil {
		t.Fatalf("read restored tree: %v", err)
	}
	if string(got) != "event log bytes" {
		t.Fatalf("restored tree content = %q", got)
	}
	bad := artifact
	bad.SHA256 = "sha256:not-the-tree"
	if err := verifyStoredDirArtifact(bad, "event-log", filepath.Join(backupDir, filepath.FromSlash(artifact.Path))); err == nil {
		t.Fatal("verifyStoredDirArtifact accepted a mismatched digest")
	}
	if _, ok := manifestArtifact(backup.NewFullManifest([]backup.Artifact{artifact}), "event-log"); !ok {
		t.Fatal("manifestArtifact did not find captured event-log")
	}
	if got := artifactPath(backupDir, backup.Artifact{Path: "event-log"}, "fallback"); got != filepath.Join(backupDir, "event-log") {
		t.Fatalf("artifactPath relative = %q", got)
	}
}

func TestFullBackupEncryptedDirectoryAndRestorePolicy(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "signer-keystore")
	if err := os.MkdirAll(src, 0o700); err != nil {
		t.Fatal(err)
	}
	secretBytes := []byte("sealed signer keystore bytes")
	if err := os.WriteFile(filepath.Join(src, "keystore.bin"), secretBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	defer secret.Wipe(key)
	keyID, err := backup.BackupArtifactKeyID(key)
	if err != nil {
		t.Fatalf("BackupArtifactKeyID: %v", err)
	}
	enc := &fullBackupEncryption{key: key, keyID: keyID}
	backupDir := filepath.Join(dir, "backup")

	artifact, err := dirArtifact("signer-keystore", "signer-keystore", src, filepath.Join(backupDir, "signer-keystore"), true, true, true, backupDir, enc)
	if err != nil {
		t.Fatalf("encrypted dirArtifact: %v", err)
	}
	if artifact.Encryption == nil || artifact.PlaintextSHA256 == "" || !strings.HasSuffix(artifact.Path, ".enc") {
		t.Fatalf("encrypted directory artifact incomplete: %+v", artifact)
	}
	containsPlaintext, err := treeContainsBytes(filepath.Join(backupDir, filepath.FromSlash(artifact.Path)), secretBytes)
	if err != nil {
		t.Fatalf("inspect encrypted tree artifact: %v", err)
	}
	if containsPlaintext {
		t.Fatal("encrypted directory artifact contains plaintext keystore bytes")
	}
	if err := restoreDirArtifact(backup.NewFullManifest([]backup.Artifact{artifact}), "signer-keystore", backupDir, "", filepath.Join(dir, "restored-keystore"), key); err != nil {
		t.Fatalf("restore encrypted dirArtifact: %v", err)
	}
	if err := validateArtifactEncryption(artifact, "signer-keystore"); err != nil {
		t.Fatalf("validateArtifactEncryption: %v", err)
	}
	if err := requireFullBackupEncryptionForRestore(backup.NewFullManifest([]backup.Artifact{artifact}), &fullBackupEncryption{key: key, keyID: "wrong"}); err == nil {
		t.Fatal("restore policy accepted the wrong backup encryption key")
	}
	if err := requireFullBackupEncryptionForRestore(backup.NewFullManifest([]backup.Artifact{{Name: "plain", Sensitive: true, Captured: true}}), &fullBackupEncryption{allowUnencrypted: true}); err != nil {
		t.Fatalf("restore policy rejected explicit plaintext override: %v", err)
	}
	keyFile := filepath.Join(dir, "backup.key")
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		t.Fatal(err)
	}
	fromConfig, err := fullBackupEncryptionFromConfig(&config.Config{Backup: config.Backup{EncryptionKeyFile: keyFile}})
	if err != nil {
		t.Fatalf("fullBackupEncryptionFromConfig: %v", err)
	}
	defer fromConfig.wipe()
	if !fromConfig.enabled() || fromConfig.manifestEncryption().KeyID != keyID || !fromConfig.manifestEncryption().SensitiveArtifactsEncrypted {
		t.Fatalf("encryption config did not produce manifest metadata: %+v", fromConfig.manifestEncryption())
	}
	plain, err := fullBackupEncryptionFromConfig(&config.Config{Backup: config.Backup{AllowUnencrypted: true}})
	if err != nil {
		t.Fatalf("plaintext fullBackupEncryptionFromConfig: %v", err)
	}
	if plain.enabled() || !plain.manifestEncryption().AllowUnencryptedSensitiveArtifactsOverride {
		t.Fatalf("plaintext backup override metadata = %+v", plain.manifestEncryption())
	}
}

func treeContainsBytes(root string, needle []byte) (bool, error) {
	found := false
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || found || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, needle) {
			found = true
		}
		return nil
	})
	return found, err
}
