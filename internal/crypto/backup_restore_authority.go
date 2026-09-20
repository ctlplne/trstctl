// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
)

const backupRestoreAuthorityDomain = "trstctl/backup-restore-authority/v2\x00"

// BackupRestoreIntent is the exact verified artifact identity permitted to use
// the event log's restore-only ingress. It authorizes no ordinary append/import.
type BackupRestoreIntent struct {
	EventCutSequence uint64
	ArtifactSHA256   string
	HistorySHA256    string
}

func (intent BackupRestoreIntent) canonicalBytes() ([]byte, error) {
	artifactDigest := strings.TrimSpace(intent.ArtifactSHA256)
	if !isCanonicalSHA256Hex(artifactDigest) || artifactDigest != intent.ArtifactSHA256 {
		return nil, errors.New("crypto: backup restore artifact digest must be canonical SHA-256")
	}
	historyDigest := strings.TrimSpace(intent.HistorySHA256)
	if !isCanonicalSHA256Hex(historyDigest) || historyDigest != intent.HistorySHA256 {
		return nil, errors.New("crypto: backup restore history digest must be canonical SHA-256")
	}
	payload := make([]byte, 0, len(backupRestoreAuthorityDomain)+8+8+len(artifactDigest)+len(historyDigest))
	payload = append(payload, backupRestoreAuthorityDomain...)
	var cut [8]byte
	binary.BigEndian.PutUint64(cut[:], intent.EventCutSequence)
	payload = append(payload, cut[:]...)
	payload = appendLenPrefixed(payload, []byte(artifactDigest))
	payload = appendLenPrefixed(payload, []byte(historyDigest))
	return payload, nil
}

func isCanonicalSHA256Hex(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

// BackupRestoreGrant is an opaque, one-artifact capability for the event log's
// restore-only ingress. Its MAC bytes and bound intent are deliberately private:
// ordinary callers cannot turn an arbitrary digest or byte slice into restore
// authority at the Go API boundary.
type BackupRestoreGrant struct {
	intent BackupRestoreIntent
	token  []byte
}

// Intent returns the immutable public identity bound into this capability. The
// receiving event log independently recomputes HistorySHA256 from a private
// spool before it verifies or uses the grant.
func (grant *BackupRestoreGrant) Intent() BackupRestoreIntent {
	if grant == nil {
		return BackupRestoreIntent{}
	}
	return grant.intent
}

// Destroy wipes the capability MAC when the one restore call has finished.
func (grant *BackupRestoreGrant) Destroy() {
	if grant == nil {
		return
	}
	secret.Wipe(grant.token)
	grant.token = nil
	grant.intent = BackupRestoreIntent{}
}

// BackupRestoreAuthorization derives a one-artifact restore capability. The
// caller invokes it only after verifying the artifact HMAC under the same
// deployment key. A random or empty key cannot produce a grant accepted by the
// Log's independently configured verifier.
func BackupRestoreAuthorization(key []byte, intent BackupRestoreIntent) (*BackupRestoreGrant, error) {
	if len(key) < 16 {
		return nil, errors.New("crypto: backup restore authority key must be at least 16 bytes")
	}
	payload, err := intent.canonicalBytes()
	if err != nil {
		return nil, err
	}
	return &BackupRestoreGrant{
		intent: intent,
		token:  HMACSHA256(key, payload),
	}, nil
}

// BackupRestoreAuthorizer verifies restore capabilities while holding the
// deployment key in locked, non-dumpable memory (AN-8).
type BackupRestoreAuthorizer struct {
	key *secret.Buffer
}

func NewBackupRestoreAuthorizer(key []byte) (*BackupRestoreAuthorizer, error) {
	if len(key) < 16 {
		return nil, errors.New("crypto: backup restore authority key must be at least 16 bytes")
	}
	buffer, err := secret.NewFrom(key)
	if err != nil {
		return nil, err
	}
	return &BackupRestoreAuthorizer{key: buffer}, nil
}

func (authorizer *BackupRestoreAuthorizer) Verify(grant *BackupRestoreGrant) bool {
	if authorizer == nil || authorizer.key == nil || grant == nil || len(grant.token) == 0 {
		return false
	}
	payload, err := grant.intent.canonicalBytes()
	if err != nil {
		return false
	}
	var want []byte
	if err := authorizer.key.Use(func(key []byte) error {
		want = HMACSHA256(key, payload)
		return nil
	}); err != nil {
		return false
	}
	defer secret.Wipe(want)
	return ConstantTimeEqual(want, grant.token)
}

func (authorizer *BackupRestoreAuthorizer) Destroy() {
	if authorizer != nil && authorizer.key != nil {
		authorizer.key.Destroy()
	}
}
