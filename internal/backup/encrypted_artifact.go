// SPDX-License-Identifier: BUSL-1.1

package backup

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	cryptoutil "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const (
	FullBackupArtifactEncryptionAlgorithm = "AES-256-GCM"
	backupArtifactEnvelopeFormat          = "trstctl-full-backup-artifact"
	backupArtifactEnvelopeVersion         = 1
	backupArtifactKeyLabel                = "trstctl/full-backup/artifact-encryption/v1"
	backupArtifactAADPrefix               = "trstctl/full-backup/artifact/v1/"
)

type encryptedArtifactEnvelope struct {
	Format     string `json:"format"`
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	KeyID      string `json:"key_id"`
	AAD        string `json:"aad"`
	Ciphertext []byte `json:"ciphertext"`
}

// FullBackupArtifactAAD returns the associated-data string that binds one
// manifest artifact to its ciphertext. Moving an encrypted signer secret into the
// audit-key slot, for example, then fails authentication instead of restoring.
func FullBackupArtifactAAD(name string) string {
	return backupArtifactAADPrefix + name
}

// BackupArtifactKeyID returns a short stable identifier for the operator-supplied
// full-backup encryption key. The raw key never appears in the manifest.
func BackupArtifactKeyID(key []byte) (string, error) {
	derived, err := deriveBackupArtifactKey(key)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(derived)
	return cryptoutil.SHA256Hex(derived)[:16], nil
}

func deriveBackupArtifactKey(key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("backup: full-backup encryption key is empty")
	}
	return cryptoutil.HMACSHA256(key, []byte(backupArtifactKeyLabel)), nil
}

// WriteEncryptedFile writes src into dst as a JSON AES-GCM envelope and returns
// both plaintext and stored-ciphertext digests. Plaintext bytes are wiped after the
// envelope is written; the ciphertext is what remains in the backup directory.
func WriteEncryptedFile(src, dst string, key []byte, aad string, mode fs.FileMode) (plainSHA string, plainBytes int64, storedSHA string, storedBytes int64, err error) {
	plaintext, err := os.ReadFile(src) // #nosec G304 -- operator-invoked backup/restore over its own configured directory (CWE-22)
	if err != nil {
		return "", 0, "", 0, err
	}
	defer secret.Wipe(plaintext)
	plainSHA = cryptoutil.SHA256Hex(plaintext)
	plainBytes = int64(len(plaintext))
	if err := writeEncryptedBytes(dst, key, aad, plaintext, mode); err != nil {
		return "", 0, "", 0, err
	}
	storedSHA, storedBytes, err = HashFile(dst)
	if err != nil {
		return "", 0, "", 0, err
	}
	return plainSHA, plainBytes, storedSHA, storedBytes, nil
}

// RestoreEncryptedFile decrypts src into dst, verifies the envelope metadata and
// AES-GCM tag, and returns the digest of the restored plaintext.
func RestoreEncryptedFile(src, dst string, key []byte, aad string, mode fs.FileMode) (plainSHA string, plainBytes int64, err error) {
	plaintext, err := readEncryptedBytes(src, key, aad)
	if err != nil {
		return "", 0, err
	}
	defer secret.Wipe(plaintext)
	if err := writePlainFile(dst, plaintext, mode); err != nil {
		return "", 0, err
	}
	return HashFile(dst)
}

// WriteEncryptedTree encrypts each file under src into the same relative path
// under dst. Each file's AAD includes its relative path so one file cannot be
// swapped for another inside the signer keystore.
func WriteEncryptedTree(src, dst string, key []byte, aadBase string) (plainSHA string, plainBytes int64, storedSHA string, storedBytes int64, err error) {
	plainSHA, plainBytes, err = HashTree(src)
	if err != nil {
		return "", 0, "", 0, err
	}
	if err := os.RemoveAll(dst); err != nil {
		return "", 0, "", 0, err
	}
	err = filepath.WalkDir(src, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		_, _, _, _, err = WriteEncryptedFile(path, target, key, treeArtifactAAD(aadBase, rel), info.Mode().Perm())
		return err
	})
	if err != nil {
		return "", 0, "", 0, err
	}
	storedSHA, storedBytes, err = HashTree(dst)
	if err != nil {
		return "", 0, "", 0, err
	}
	return plainSHA, plainBytes, storedSHA, storedBytes, nil
}

// RestoreEncryptedTree decrypts an encrypted tree created by WriteEncryptedTree.
func RestoreEncryptedTree(src, dst string, key []byte, aadBase string) (plainSHA string, plainBytes int64, err error) {
	if err := os.RemoveAll(dst); err != nil {
		return "", 0, err
	}
	err = filepath.WalkDir(src, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		_, _, err = RestoreEncryptedFile(path, target, key, treeArtifactAAD(aadBase, rel), info.Mode().Perm())
		return err
	})
	if err != nil {
		return "", 0, err
	}
	return HashTree(dst)
}

func treeArtifactAAD(base, rel string) string {
	rel = filepath.ToSlash(rel)
	if rel == "." || rel == "" {
		return base
	}
	return base + "/" + rel
}

func writeEncryptedBytes(dst string, key []byte, aad string, plaintext []byte, mode fs.FileMode) error {
	derived, err := deriveBackupArtifactKey(key)
	if err != nil {
		return err
	}
	defer secret.Wipe(derived)
	keyID := cryptoutil.SHA256Hex(derived)[:16]
	ciphertext, err := cryptoutil.AESGCMSeal(derived, plaintext, []byte(aad))
	if err != nil {
		return fmt.Errorf("backup: encrypt artifact: %w", err)
	}
	env := encryptedArtifactEnvelope{
		Format:     backupArtifactEnvelopeFormat,
		Version:    backupArtifactEnvelopeVersion,
		Algorithm:  FullBackupArtifactEncryptionAlgorithm,
		KeyID:      keyID,
		AAD:        aad,
		Ciphertext: ciphertext,
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode) // #nosec G304 -- operator-invoked backup/restore over its own configured directory (CWE-22)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(f).Encode(env); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

func readEncryptedBytes(src string, key []byte, aad string) ([]byte, error) {
	f, err := os.Open(src) // #nosec G304 -- operator-invoked backup/restore over its own configured directory (CWE-22)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var env encryptedArtifactEnvelope
	if err := json.NewDecoder(f).Decode(&env); err != nil {
		return nil, fmt.Errorf("backup: decode encrypted artifact: %w", err)
	}
	if env.Format != backupArtifactEnvelopeFormat || env.Version != backupArtifactEnvelopeVersion {
		return nil, fmt.Errorf("backup: unsupported encrypted artifact format %q version %d", env.Format, env.Version)
	}
	if env.Algorithm != FullBackupArtifactEncryptionAlgorithm {
		return nil, fmt.Errorf("backup: unsupported encrypted artifact algorithm %q", env.Algorithm)
	}
	if env.AAD != aad {
		return nil, fmt.Errorf("backup: encrypted artifact AAD mismatch")
	}
	derived, err := deriveBackupArtifactKey(key)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(derived)
	if got := cryptoutil.SHA256Hex(derived)[:16]; got != env.KeyID {
		return nil, fmt.Errorf("backup: encrypted artifact key id mismatch")
	}
	plaintext, err := cryptoutil.AESGCMOpen(derived, env.Ciphertext, []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("backup: decrypt artifact: %w", err)
	}
	return plaintext, nil
}

func writePlainFile(dst string, plaintext []byte, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode) // #nosec G304 -- operator-invoked backup/restore over its own configured directory (CWE-22)
	if err != nil {
		return err
	}
	if _, err := f.Write(plaintext); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}
