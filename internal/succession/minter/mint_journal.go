// SPDX-License-Identifier: BUSL-1.1

package minter

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/fsatomic"
	"trstctl.com/trstctl/internal/signing"
)

const mintJournalVersion = 1

// MintJournal holds the signer's first-writer intent and exact public result.
// The intent is durable before successor key generation; the completed result
// is durable before the epoch floor advances or the RPC response escapes.
type MintJournal interface {
	Load(key string) (MintJournalEntry, bool, error)
	Begin(key string, entry MintJournalEntry) error
	Complete(key string, entry MintJournalEntry) error
}

type MintJournalEntry struct {
	Version        int                `json:"version"`
	Key            string             `json:"key"`
	RequestHash    string             `json:"request_hash"`
	State          string             `json:"state"`
	BreakGlassUsed bool               `json:"break_glass_used,omitempty"`
	DelegationPath string             `json:"delegation_path,omitempty"`
	AttestDigest   []byte             `json:"attest_digest,omitempty"`
	AttestType     string             `json:"attest_type,omitempty"`
	Result         signing.MintResult `json:"result,omitempty"`
}

type durableMintJournal struct {
	dir     string
	wrapper seal.KeyWrapper
}

// MintRequestHash binds the whole signer command, including one-time approval
// bytes, custody attestation, predecessor handle and validity window. The public
// result is reusable only for this exact command.
func MintRequestHash(req signing.MintRequest) (string, error) {
	encoded, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(encoded)
	return crypto.SHA256Hex(encoded), nil
}

// NewDurableMintJournal creates a sealed, signer-local journal. A nil wrapper is
// refused: a modified first-writer intent could otherwise authorize a different
// request after a restart.
func NewDurableMintJournal(custodyDir string, wrapper seal.KeyWrapper) (MintJournal, error) {
	if custodyDir == "" || wrapper == nil {
		return nil, errors.New("minter: durable mint journal needs signer custody dir and key wrapper")
	}
	dir := filepath.Join(custodyDir, "pcas-mint-operations")
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("minter: create mint journal: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("minter: mint journal path is not a real directory")
	}
	if err := fsatomic.SyncDirectory(custodyDir); err != nil {
		return nil, fmt.Errorf("minter: sync mint journal parent: %w", err)
	}
	return &durableMintJournal{dir: dir, wrapper: wrapper}, nil
}

func (j *durableMintJournal) path(key string) string {
	return crypto.SHA256Hex([]byte(key)) + ".result"
}

func (j *durableMintJournal) aad(key string) []byte {
	return []byte("trstctl:pcas:mint-result:v1\x00" + key)
}

func (j *durableMintJournal) Load(key string) (MintJournalEntry, bool, error) {
	root, err := os.OpenRoot(j.dir)
	if err != nil {
		return MintJournalEntry{}, false, err
	}
	defer func() { _ = root.Close() }()
	sealed, err := root.ReadFile(j.path(key))
	if errors.Is(err, os.ErrNotExist) {
		return MintJournalEntry{}, false, nil
	}
	if err != nil {
		return MintJournalEntry{}, false, err
	}
	defer secret.Wipe(sealed)
	plain, err := seal.Open(j.wrapper, sealed, j.aad(key))
	if err != nil {
		return MintJournalEntry{}, false, fmt.Errorf("minter: open mint journal: %w", err)
	}
	defer secret.Wipe(plain)
	var entry MintJournalEntry
	if err := json.Unmarshal(plain, &entry); err != nil {
		return MintJournalEntry{}, false, err
	}
	if entry.Version != mintJournalVersion || entry.Key != key ||
		(entry.State != "executing" && entry.State != "completed") {
		return MintJournalEntry{}, false, errors.New("minter: mint journal binding or state invalid")
	}
	return entry, true, nil
}

func (j *durableMintJournal) Begin(key string, entry MintJournalEntry) error {
	entry.Version, entry.Key, entry.State = mintJournalVersion, key, "executing"
	entry.Result = signing.MintResult{}
	sealed, err := j.seal(entry)
	if err != nil {
		return err
	}
	defer secret.Wipe(sealed)
	file, err := os.CreateTemp(j.dir, ".mint-intent-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(sealed); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	// The hard link is the first-writer fence: its final name appears atomically
	// only after the complete sealed intent file was fsynced.
	if err := os.Link(file.Name(), filepath.Join(j.dir, j.path(key))); err != nil {
		return fmt.Errorf("minter: first-writer mint intent: %w", err)
	}
	return fsatomic.SyncDirectory(j.dir)
}

func (j *durableMintJournal) Complete(key string, entry MintJournalEntry) error {
	prior, found, err := j.Load(key)
	if err != nil {
		return err
	}
	if !found || prior.State != "executing" || prior.RequestHash != entry.RequestHash {
		return errors.New("minter: mint journal intent does not match completion")
	}
	entry.Version, entry.Key, entry.State = mintJournalVersion, key, "completed"
	sealed, err := j.seal(entry)
	if err != nil {
		return err
	}
	defer secret.Wipe(sealed)
	file, err := os.CreateTemp(j.dir, ".mint-result-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(sealed); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), filepath.Join(j.dir, j.path(key))); err != nil {
		return err
	}
	return fsatomic.SyncDirectory(j.dir)
}

func (j *durableMintJournal) seal(entry MintJournalEntry) ([]byte, error) {
	encoded, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(encoded)
	return seal.Seal(j.wrapper, encoded, j.aad(entry.Key))
}
