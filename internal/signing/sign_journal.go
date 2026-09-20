// SPDX-License-Identifier: BUSL-1.1

package signing

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
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

const signJournalVersion = 1

var (
	errSignOperationConflict = errors.New("signing: operation id already binds a different signing tuple")
)

type signJournalRecord struct {
	Version     int    `json:"version"`
	OperationID string `json:"operation_id"`
	RequestHash string `json:"request_hash"`
	State       string `json:"state"`
	Signature   []byte `json:"signature,omitempty"`
}

type signJournalIntent struct {
	Handle  string              `json:"handle"`
	Digest  []byte              `json:"digest"`
	Hash    signerpb.Hash       `json:"hash"`
	Padding signerpb.RSAPadding `json:"padding"`
	Purpose signerpb.KeyPurpose `json:"purpose"`
}

func signRequestHash(req *signerpb.SignRequest) (string, error) {
	body, err := json.Marshal(signJournalIntent{
		Handle: req.GetHandle().GetId(), Digest: req.GetDigest(), Hash: req.GetHash(),
		Padding: req.GetRsaPadding(), Purpose: req.GetPurpose(),
	})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(body)
	return crypto.SHA256Hex(body), nil
}

func (ks *KeyStore) signJournalDir() string { return filepath.Join(ks.dir, "sign-operations") }

func (ks *KeyStore) signJournalPath(operationID string) string {
	return filepath.Join(ks.signJournalDir(), crypto.SHA256Hex([]byte(operationID))+".result")
}

func signJournalAAD(operationID string) []byte {
	return []byte("trstctl:signer-sign-result:v1\x00" + operationID)
}

// beginSignOperation creates the durable executing marker before the private-key
// operation. A completed record returns the exact prior signature. An executing
// record is resumed while the caller holds KeyStore.lockSignOperation. A
// signature cannot escape before the completed record's fsync+rename, so an
// executing record after restart represents a call that returned no signature.
func (ks *KeyStore) beginSignOperation(req *signerpb.SignRequest) ([]byte, bool, error) {
	operationID := req.GetOperationId()
	requestHash, err := signRequestHash(req)
	if err != nil {
		return nil, false, err
	}
	record := signJournalRecord{
		Version: signJournalVersion, OperationID: operationID,
		RequestHash: requestHash, State: "executing",
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, false, err
	}
	defer secret.Wipe(encoded)
	sealed, err := seal.Seal(ks.wrapper, encoded, signJournalAAD(operationID))
	if err != nil {
		return nil, false, err
	}
	defer secret.Wipe(sealed)
	if err := ks.ensureSignJournalDirectory(syncDirectory); err != nil {
		return nil, false, err
	}
	file, err := os.OpenFile(ks.signJournalPath(operationID), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if _, writeErr := file.Write(sealed); writeErr != nil {
			_ = file.Close()
			return nil, false, writeErr
		}
		if syncErr := file.Sync(); syncErr != nil {
			_ = file.Close()
			return nil, false, syncErr
		}
		if closeErr := file.Close(); closeErr != nil {
			return nil, false, closeErr
		}
		if err := syncDirectory(ks.signJournalDir()); err != nil {
			return nil, false, err
		}
		return nil, false, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return nil, false, err
	}
	existing, err := ks.readSignOperation(operationID)
	if err != nil {
		return nil, false, err
	}
	if existing.RequestHash != requestHash {
		return nil, false, errSignOperationConflict
	}
	switch existing.State {
	case "completed":
		if len(existing.Signature) == 0 {
			return nil, false, errors.New("signing: completed operation has no signature")
		}
		return append([]byte(nil), existing.Signature...), true, nil
	case "executing":
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("signing: unsupported journal state %q", existing.State)
	}
}

func (ks *KeyStore) ensureSignJournalDirectory(syncDir func(string) error) error {
	ks.journalDirMu.Lock()
	defer ks.journalDirMu.Unlock()

	if err := os.MkdirAll(ks.signJournalDir(), 0o700); err != nil {
		return err
	}
	parent, directory, err := ks.statSignJournalDirectory()
	if err != nil {
		return err
	}
	// Only the directory's creation belongs to its parent. Every intent and
	// completed result still syncs its file and the journal directory. Remember
	// successful parent durability for these exact filesystem identities, and
	// repeat it after restart or replacement of either directory.
	if ks.journalParent != nil && ks.journalDirectory != nil &&
		os.SameFile(ks.journalParent, parent) && os.SameFile(ks.journalDirectory, directory) {
		return nil
	}
	ks.journalParent, ks.journalDirectory = nil, nil
	if err := syncDir(ks.dir); err != nil {
		return err
	}
	afterParent, afterDirectory, err := ks.statSignJournalDirectory()
	if err != nil {
		return err
	}
	if !os.SameFile(parent, afterParent) || !os.SameFile(directory, afterDirectory) {
		return errors.New("signing: journal directory changed during durability sync")
	}
	ks.journalParent, ks.journalDirectory = afterParent, afterDirectory
	return nil
}

func (ks *KeyStore) statSignJournalDirectory() (os.FileInfo, os.FileInfo, error) {
	parent, err := os.Stat(ks.dir)
	if err != nil {
		return nil, nil, err
	}
	directory, err := os.Stat(ks.signJournalDir())
	if err != nil {
		return nil, nil, err
	}
	if !parent.IsDir() || !directory.IsDir() {
		return nil, nil, errors.New("signing: journal paths must be directories")
	}
	return parent, directory, nil
}

func (ks *KeyStore) completeSignOperation(req *signerpb.SignRequest, signature []byte) error {
	requestHash, err := signRequestHash(req)
	if err != nil {
		return err
	}
	record := signJournalRecord{
		Version: signJournalVersion, OperationID: req.GetOperationId(),
		RequestHash: requestHash, State: "completed",
		Signature: append([]byte(nil), signature...),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	defer secret.Wipe(encoded)
	sealed, err := seal.Seal(ks.wrapper, encoded, signJournalAAD(record.OperationID))
	if err != nil {
		return err
	}
	defer secret.Wipe(sealed)
	temp, err := os.CreateTemp(ks.signJournalDir(), ".sign-result-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(sealed); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, ks.signJournalPath(record.OperationID)); err != nil {
		return err
	}
	return syncDirectory(ks.signJournalDir())
}

func (ks *KeyStore) readSignOperation(operationID string) (signJournalRecord, error) {
	sealed, err := os.ReadFile(ks.signJournalPath(operationID))
	if err != nil {
		return signJournalRecord{}, err
	}
	plain, err := seal.Open(ks.wrapper, sealed, signJournalAAD(operationID))
	if err != nil {
		return signJournalRecord{}, fmt.Errorf("signing: open sign result journal: %w", err)
	}
	defer secret.Wipe(plain)
	var record signJournalRecord
	if err := json.Unmarshal(plain, &record); err != nil {
		return signJournalRecord{}, err
	}
	if record.Version != signJournalVersion || record.OperationID != operationID {
		return signJournalRecord{}, errors.New("signing: sign result journal binding mismatch")
	}
	return record, nil
}

// syncDirectory makes the create/rename directory entry durable, not merely the
// file contents. Without it, a power loss can forget the executing marker or the
// completed replacement even though file.Sync succeeded. The implementation
// lives in the shared stdlib-only fsatomic package so the keystore, the sign
// journal, and the transit keyring run ONE copy of the pattern (AUD-201
// follow-up B4/V5).
func syncDirectory(path string) error { return fsatomic.SyncDirectory(path) }
