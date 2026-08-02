// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"trstctl.com/trstctl/ee/agentid/taskenv"
)

// B-7: the broker's single-hop path could not carry an AGID-05 task envelope,
// so a broker-issued agent credential could not be scoped to one authorized
// task — only the chain-bound delegation path could. This is the licensed gate
// the core broker consults through its feature-neutral seam.
//
// It reuses the same in-signer verification the delegation gate runs
// (taskenv.VerifySignatureAndExpiry): requester signature over the canonical
// bytes, resolved through a trust lookup the CALLER cannot inject into, plus
// the expiry window. Nothing here performs a key operation, and the digest it
// returns is the envelope's own canonical digest — the value the credential
// binds and the caller can independently recompute.

// ErrNoBrokerTaskEnvelopeTrust is returned when the gate holds no requester
// trust lookup. Without one there is no way to know whose signature a valid-
// looking envelope carries, so the gate refuses rather than accepting an
// envelope signed by anyone.
var ErrNoBrokerTaskEnvelopeTrust = errors.New("delegation: broker task-envelope gate has no requester trust lookup")

// NewBrokerTaskEnvelopeGate builds the gate over a requester trust lookup. The
// returned function matches the core's BrokerTaskEnvelopeGate seam shape
// without the core importing ee/.
func NewBrokerTaskEnvelopeGate(trust taskenv.TrustLookup) func(ctx context.Context, tenantID string, envelope []byte, now time.Time) ([]byte, error) {
	return func(_ context.Context, _ string, envelope []byte, now time.Time) ([]byte, error) {
		if trust == nil {
			return nil, ErrNoBrokerTaskEnvelopeTrust
		}
		if len(envelope) == 0 {
			return nil, taskenv.ErrNoIntent
		}
		var env taskenv.Envelope
		if err := json.Unmarshal(envelope, &env); err != nil {
			return nil, err
		}
		if err := taskenv.VerifySignatureAndExpiry(env, now, trust); err != nil {
			return nil, err
		}
		// The digest is computed from the envelope we just verified, so the
		// value bound into the credential is the value that passed the check —
		// a substituted envelope cannot be bound in place of the signed one.
		return env.Digest()
	}
}

const durableBrokerTaskRequesterDir = "agid-task-requester-keys"

// DurableTaskEnvelopeTrustStore is the operator-provisioned registry of task
// REQUESTER public keys, mirroring the reachability-verdict trust store: the
// operator writes public SubjectPublicKeyInfo DER into the signer floor, and
// the gate reads it per verification. The requester cannot supply its own key
// alongside the envelope — that is the whole point of a trust lookup, and why
// a caller cannot forge a task binding by signing with a key it chose.
type DurableTaskEnvelopeTrustStore struct {
	floorDir string
}

func NewDurableTaskEnvelopeTrustStore(floorDir string) *DurableTaskEnvelopeTrustStore {
	return &DurableTaskEnvelopeTrustStore{floorDir: floorDir}
}

// PutRequesterKey provisions one trusted task-requester public key.
func (s *DurableTaskEnvelopeTrustStore) PutRequesterKey(_ context.Context, keyID string, publicDER []byte) error {
	path, err := s.path(keyID)
	if err != nil {
		return err
	}
	if len(publicDER) == 0 {
		return errors.New("delegation: task requester public DER is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("delegation: create task requester trust directory: %w", err)
	}
	if err := os.WriteFile(path, append([]byte(nil), publicDER...), 0o600); err != nil {
		return fmt.Errorf("delegation: write task requester public key: %w", err)
	}
	return nil
}

// TrustLookup implements taskenv.TrustLookup. An unknown key id resolves to
// (nil,false) and the envelope is refused fail-closed.
func (s *DurableTaskEnvelopeTrustStore) TrustLookup(keyID string) ([]byte, bool) {
	path, err := s.path(keyID)
	if err != nil {
		return nil, false
	}
	publicDER, err := readUnderRoot(path)
	if err != nil || len(publicDER) == 0 {
		return nil, false
	}
	return append([]byte(nil), publicDER...), true
}

func (s *DurableTaskEnvelopeTrustStore) path(keyID string) (string, error) {
	if s == nil || s.floorDir == "" {
		return "", errors.New("delegation: task requester trust store floor directory is not configured")
	}
	if !safeAnchorSegment(keyID) {
		return "", fmt.Errorf("delegation: unsafe task requester key id %q", keyID)
	}
	return filepath.Join(s.floorDir, durableBrokerTaskRequesterDir, keyID+".der"), nil
}
