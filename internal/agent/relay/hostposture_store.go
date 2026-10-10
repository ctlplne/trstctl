// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
)

const hostPostureStateVersion = 1

var ErrHostPostureConflict = errors.New("relay: this host target has a different unfinished TLS posture migration")

// hostPostureState is kept on the enrolled host before its listener is changed.
// The ciphertext is bound to tenant and target, so a reboot or a lost report
// cannot make the agent guess the predecessor from a new server-side plan.
type hostPostureState struct {
	Version        int                  `json:"version"`
	TenantID       string               `json:"tenant_id"`
	RunID          string               `json:"run_id"`
	TargetID       string               `json:"target_id"`
	TargetRevision string               `json:"target_revision"`
	Previous       connector.TLSPosture `json:"previous"`
	Desired        connector.TLSPosture `json:"desired"`
	Status         string               `json:"status"`
}

func (s *HostRollbackStore) posturePath(targetID string) string {
	name := trstcrypto.SHA256Hex([]byte("posture\x00" + s.tenantID + "\x00" + targetID))
	return filepath.Join(s.root, name+".posture")
}

func (s *HostRollbackStore) postureAAD(targetID string) []byte {
	return []byte("trstctl.host.posture.v1\x00" + s.tenantID + "\x00" + targetID)
}

func (s *HostRollbackStore) loadPosture(targetID string) (*hostPostureState, error) {
	ciphertext, err := secretfile.Load(s.posturePath(targetID))
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(ciphertext)
	var plaintext []byte
	if err := s.withKey(func(key []byte) error {
		var openErr error
		plaintext, openErr = trstcrypto.AESGCMOpen(key, ciphertext, s.postureAAD(targetID))
		return openErr
	}); err != nil {
		return nil, fmt.Errorf("relay: open host TLS posture predecessor: %w", err)
	}
	defer secret.Wipe(plaintext)
	var state hostPostureState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return nil, fmt.Errorf("relay: decode host TLS posture predecessor: %w", err)
	}
	if state.Version != hostPostureStateVersion || state.TenantID != s.tenantID || state.TargetID != targetID ||
		state.RunID == "" || state.TargetRevision == "" ||
		(state.Status != "prepared" && state.Status != "applied" && state.Status != "rolled_back") {
		return nil, ErrHostRollbackStateMismatch
	}
	if err := connector.ValidateObservedTLSPosture(state.Previous); err != nil {
		return nil, ErrHostRollbackStateMismatch
	}
	if err := connector.ValidateTLSPosture(state.Desired); err != nil {
		return nil, ErrHostRollbackStateMismatch
	}
	return &state, nil
}

func (s *HostRollbackStore) savePosture(state *hostPostureState) error {
	plaintext, err := json.Marshal(state)
	if err != nil {
		return err
	}
	defer secret.Wipe(plaintext)
	var ciphertext []byte
	if err := s.withKey(func(key []byte) error {
		var sealErr error
		ciphertext, sealErr = trstcrypto.AESGCMSeal(key, plaintext, s.postureAAD(state.TargetID))
		return sealErr
	}); err != nil {
		return fmt.Errorf("relay: seal host TLS posture predecessor: %w", err)
	}
	defer secret.Wipe(ciphertext)
	return writeHostRollbackStateAtomic(s.posturePath(state.TargetID), ciphertext)
}

func validateHostPostureIdentity(runID, targetID, revision string) error {
	if strings.TrimSpace(runID) != runID || strings.TrimSpace(targetID) != targetID ||
		strings.TrimSpace(revision) != revision || runID == "" || targetID == "" || revision == "" {
		return errors.New("relay: host TLS posture requires exact run, target, and revision")
	}
	return nil
}

func sameHostPosture(state *hostPostureState, runID, revision string, desired connector.TLSPosture) bool {
	return state.RunID == runID && state.TargetRevision == revision && connector.EqualTLSPosture(state.Desired, desired)
}

// PreparePosture must finish its encrypted, fsynced write before any native
// receiver mutation. A retry of the same command keeps the original observed
// predecessor; a competing command cannot replace it after an ambiguous crash.
func (s *HostRollbackStore) PreparePosture(runID, targetID, revision string, previous, desired connector.TLSPosture) error {
	if s == nil {
		return errors.New("relay: host TLS posture predecessor store is unavailable")
	}
	if err := validateHostPostureIdentity(runID, targetID, revision); err != nil {
		return err
	}
	if err := connector.ValidateObservedTLSPosture(previous); err != nil {
		return err
	}
	if err := connector.ValidateTLSPosture(desired); err != nil {
		return err
	}
	lock := s.targetLock("pqc-posture", targetID)
	lock.Lock()
	defer lock.Unlock()
	state, err := s.loadPosture(targetID)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if state != nil && state.Status != "rolled_back" {
		if !sameHostPosture(state, runID, revision, desired) || !connector.EqualTLSPosture(state.Previous, previous) {
			return ErrHostPostureConflict
		}
		return nil
	}
	return s.savePosture(&hostPostureState{
		Version: hostPostureStateVersion, TenantID: s.tenantID, RunID: runID,
		TargetID: targetID, TargetRevision: revision, Previous: previous, Desired: desired, Status: "prepared",
	})
}

func (s *HostRollbackStore) PreparedPosture(runID, targetID, revision string, desired connector.TLSPosture) (connector.TLSPosture, error) {
	if s == nil {
		return connector.TLSPosture{}, errors.New("relay: host TLS posture predecessor store is unavailable")
	}
	if err := validateHostPostureIdentity(runID, targetID, revision); err != nil {
		return connector.TLSPosture{}, err
	}
	lock := s.targetLock("pqc-posture", targetID)
	lock.Lock()
	defer lock.Unlock()
	state, err := s.loadPosture(targetID)
	if err != nil {
		return connector.TLSPosture{}, err
	}
	if !sameHostPosture(state, runID, revision, desired) || state.Status == "rolled_back" {
		return connector.TLSPosture{}, ErrHostPostureConflict
	}
	return state.Previous, nil
}

func (s *HostRollbackStore) CommitPosture(runID, targetID, revision string, observed connector.TLSPosture) error {
	if s == nil {
		return errors.New("relay: host TLS posture predecessor store is unavailable")
	}
	if err := validateHostPostureIdentity(runID, targetID, revision); err != nil {
		return err
	}
	lock := s.targetLock("pqc-posture", targetID)
	lock.Lock()
	defer lock.Unlock()
	state, err := s.loadPosture(targetID)
	if err != nil {
		return err
	}
	if !sameHostPosture(state, runID, revision, observed) || state.Status == "rolled_back" {
		return ErrHostPostureConflict
	}
	state.Status = "applied"
	return s.savePosture(state)
}

// RestorePosture keeps the predecessor until native restore and readback both
// succeed. The callback runs under the target lock and must reject drift from
// Desired; merely accepting an HTTP PUT is not a completed rollback.
func (s *HostRollbackStore) RestorePosture(runID, targetID, revision string, restore func(previous, desired connector.TLSPosture) error) error {
	if s == nil || restore == nil {
		return errors.New("relay: host TLS posture restore requires store and callback")
	}
	if err := validateHostPostureIdentity(runID, targetID, revision); err != nil {
		return err
	}
	lock := s.targetLock("pqc-posture", targetID)
	lock.Lock()
	defer lock.Unlock()
	state, err := s.loadPosture(targetID)
	if err != nil {
		return err
	}
	if state.RunID != runID || state.TargetRevision != revision {
		return ErrHostPostureConflict
	}
	if err := restore(state.Previous, state.Desired); err != nil {
		return err
	}
	state.Status = "rolled_back"
	return s.savePosture(state)
}
