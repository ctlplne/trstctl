// SPDX-License-Identifier: BUSL-1.1

package sshtrustrollout

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

const MaxReportBytes = 16 << 10

// Report contains closed facts from one host attempt, with no local paths,
// commands, stderr, public-key bytes or secret values. The outer job receipt
// signs these exact JSON bytes together with job ID, attempt and peer identity.
type Report struct {
	RolloutID               string    `json:"rollout_id"`
	AgentID                 string    `json:"agent_id"`
	PlanDigest              string    `json:"plan_digest"`
	ReadinessDigest         string    `json:"readiness_digest"`
	CAFingerprint           string    `json:"ca_fingerprint"`
	State                   string    `json:"state"`
	ReasonCode              string    `json:"reason_code,omitempty"`
	Phase                   string    `json:"phase"`
	Rollback                string    `json:"rollback"`
	Changed                 bool      `json:"changed"`
	CAReadBack              bool      `json:"ca_read_back"`
	EffectiveConfigReadBack bool      `json:"effective_config_read_back"`
	TrustFileSHA256         string    `json:"trust_file_sha256,omitempty"`
	ConfigFileSHA256        string    `json:"config_file_sha256,omitempty"`
	Validated               bool      `json:"validated"`
	Reloaded                bool      `json:"reloaded"`
	Healthy                 bool      `json:"healthy"`
	CheckedAt               time.Time `json:"checked_at"`
}

func DecodeReport(raw []byte) (Report, error) {
	if len(raw) == 0 || len(raw) > MaxReportBytes {
		return Report{}, errors.New("SSH trust receipt exceeds its bound")
	}
	var r Report
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return r, errors.New("SSH trust receipt has trailing data")
	}
	return r, nil
}

func (r Report) Validate(c Command, evidenceDigest string) error {
	if r.RolloutID != c.RolloutID || r.AgentID != c.AgentID || r.PlanDigest != c.PlanDigest || r.ReadinessDigest != c.ReadinessDigest || r.CAFingerprint != c.CAFingerprint || r.CheckedAt.IsZero() {
		return errors.New("SSH trust receipt differs from its exact reviewed job")
	}
	if !digest(evidenceDigest) {
		return errors.New("SSH trust receipt needs its exact evidence digest")
	}
	switch r.Rollback {
	case "not_needed", "not_available", "verified", "failed":
	default:
		return errors.New("SSH trust receipt has an unknown rollback state")
	}
	switch r.Phase {
	case "preflight", "backup", "write_trust", "write_config", "validate", "reload", "health", "readback", "complete":
	default:
		return errors.New("SSH trust receipt has an unknown phase")
	}
	switch r.State {
	case "verified":
		if r.ReasonCode != "" || r.Phase != "complete" || r.Rollback != "not_needed" || !r.CAReadBack || !r.EffectiveConfigReadBack || !r.Validated || !r.Reloaded || !r.Healthy || !digest(r.TrustFileSHA256) || !digest(r.ConfigFileSHA256) {
			return errors.New("SSH trust completion needs independent file/config readback and runtime checks")
		}
	case "failed", "refused":
		if !ReasonCode(r.ReasonCode) {
			return errors.New("SSH trust failure needs a closed reason code")
		}
		if r.Phase == "complete" {
			return errors.New("a failed SSH trust attempt cannot claim completion")
		}
		if r.State == "refused" && (r.Changed || r.Rollback != "not_needed" || r.Phase != "preflight") {
			return errors.New("a local refusal cannot claim a host mutation")
		}
	default:
		return errors.New("SSH trust receipt has an unknown state")
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if "sha256:"+crypto.SHA256Hex(raw) != evidenceDigest {
		return errors.New("SSH trust evidence digest differs from its report")
	}
	return nil
}

func (r Report) Encode() ([]byte, string, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, "", err
	}
	return raw, "sha256:" + crypto.SHA256Hex(raw), nil
}
