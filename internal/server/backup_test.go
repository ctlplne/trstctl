// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
)

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
