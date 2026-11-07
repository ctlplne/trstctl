// SPDX-License-Identifier: BUSL-1.1
package servicedependents

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/crypto"
)

const MaxInverseRecoveryDepth = 128

// StepRecoveryBinding adds explicit inverse work without rewriting its original
// failed/uncertain source, lease or native observation.
type StepRecoveryBinding struct {
	Depth          int    `json:"depth"`
	Version        int    `json:"version"`
	RootStepID     string `json:"root_step_id"`
	PreviousStepID string `json:"previous_step_id"`
}

func validRecoveryStepID(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 16 && value == strings.ToLower(value) && strings.Trim(value, "0") != ""
}
func RecoveryStepID(rotationID, previousStepID string) string {
	return crypto.SHA256Hex([]byte("trstctl.service-dependent.inverse-recovery-step.v1\x00" + rotationID + "\x00" + previousStepID))[:32]
}
func RecoverySourceID(rotationID, previousStepID string) string {
	return StepSourceID(rotationID, RecoveryStepID(rotationID, previousStepID))
}

// NewInverseRecoveryStep preserves the exact reviewed native effect. The queue
// separately validates canonical failure/expiry and restored-directory authority.
func NewInverseRecoveryStep(previous RotationStep, challenge string, now time.Time) (RotationStep, error) {
	if previous.Validate() != nil || previous.Direction != Inverse || previous.Challenge == "" || previous.NotBefore.IsZero() || !canonicalID(challenge) || challenge == previous.Challenge || now.IsZero() || now.Before(previous.NotBefore) {
		return RotationStep{}, errors.New("service dependents: exact retained inverse lease and fresh recovery challenge required")
	}
	raw, err := json.Marshal(previous)
	if err != nil {
		return RotationStep{}, err
	}
	var next RotationStep
	if err := json.Unmarshal(raw, &next); err != nil {
		return RotationStep{}, err
	}
	depth := 1
	root := previous.ID
	if previous.Recovery != nil {
		root = previous.Recovery.RootStepID
		depth = previous.Recovery.Depth + 1
	}
	next.Recovery = &StepRecoveryBinding{Version: 1, Depth: depth, RootStepID: root, PreviousStepID: previous.ID}
	next.ID = RecoveryStepID(previous.RotationID, previous.ID)
	next.Challenge = challenge
	next.NotBefore = now.UTC()
	next.Deadline = next.NotBefore.Add(2 * time.Minute)
	if err := next.Validate(); err != nil {
		return RotationStep{}, err
	}
	return next, nil
}
