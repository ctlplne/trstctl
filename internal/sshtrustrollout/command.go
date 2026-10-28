// SPDX-License-Identifier: BUSL-1.1

// Package sshtrustrollout defines the public-only additive fleet trust contract.
// Paths, reload/health argv, confirmation and rollback policy remain host-local.
package sshtrustrollout

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/crypto/sshkeys"
)

const Destination = "ssh.trust.apply"
const MaxCommandBytes = 64 << 10

// Command is one approved public CA addition bound to one opted-in host agent.
// It deliberately carries no executable command, target path or removal mode.
type Command struct {
	ExpiresAt       time.Time `json:"expires_at"`
	RolloutID       string    `json:"rollout_id"`
	AgentID         string    `json:"agent_id"`
	PublicCAKey     []byte    `json:"public_ca_key"`
	CAFingerprint   string    `json:"ca_fingerprint"`
	PlanDigest      string    `json:"plan_digest"`
	ReadinessDigest string    `json:"readiness_digest"`
}

func DecodeCommand(reader io.Reader) (Command, error) {
	body, err := io.ReadAll(io.LimitReader(reader, MaxCommandBytes+1))
	if err != nil || len(body) > MaxCommandBytes {
		return Command{}, errors.New("SSH trust command exceeds its read bound")
	}
	var command Command
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil {
		return Command{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Command{}, errors.New("SSH trust command has trailing data")
	}
	return command, command.Validate()
}

func (c Command) Validate() error {
	if c.ExpiresAt.IsZero() {
		return errors.New("SSH trust command needs an execution deadline")
	}
	for _, raw := range []string{c.RolloutID, c.AgentID} {
		id, err := uuid.Parse(raw)
		if err != nil || id == uuid.Nil || id.String() != raw {
			return errors.New("SSH trust command needs canonical rollout and agent IDs")
		}
	}
	_, fingerprint, err := CanonicalPublicCAKey(c.PublicCAKey)
	if err != nil {
		return err
	}
	if fingerprint != c.CAFingerprint {
		return errors.New("SSH trust public key differs from its reviewed CA fingerprint")
	}

	if !digest(c.PlanDigest) || !digest(c.ReadinessDigest) {
		return errors.New("SSH trust command needs the reviewed plan and host readiness digests")
	}
	return nil
}

func digest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, c := range value[7:] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// LocalAuthority comes only from the host's own configuration and enrollment.
// A remote payload cannot opt the host in or replace its pinned commands.
type LocalAuthority struct {
	AllowedCAFingerprint string
	Enabled              bool
	Confirmed            bool
	AgentID              string
	ReadinessDigest      string
}

func (c Command) PermitLocal(authority LocalAuthority, now time.Time) error {
	if !authority.Enabled {
		return &Refusal{Code: "local_not_enabled"}
	}
	if !authority.Confirmed {
		return &Refusal{Code: "local_unconfirmed"}
	}
	if c.AgentID != authority.AgentID {
		return &Refusal{Code: "other_agent"}
	}
	if c.ReadinessDigest != authority.ReadinessDigest {
		return &Refusal{Code: "policy_changed"}
	}
	if c.CAFingerprint != authority.AllowedCAFingerprint {
		return &Refusal{Code: "ca_pin_changed"}
	}
	if c.ExpiresAt.IsZero() || !now.Before(c.ExpiresAt) {
		return &Refusal{Code: "execution_window_ended"}
	}
	return c.Validate()
}

// EnrolledAgentID preserves the existing agents.id UUIDv5 derivation. Both the
// authenticated receiver and the host derive it from enrollment, never from a
// command-supplied identity. Changing this namespace would split existing hosts.
func EnrolledAgentID(tenantID, commonName string) string {
	return uuid.NewSHA1(uuid.MustParse("b3d4e5f6-0a1b-5c2d-8e3f-4a5b6c7d8e9f"), []byte(tenantID+"\x00"+commonName)).String()
}

// CanonicalPublicCAKey validates one public CA and drops its free-form comment.
// A review retains the actual public key, without persisting a user's email or
// workstation name from an authorized_keys comment.
func CanonicalPublicCAKey(raw []byte) ([]byte, string, error) {
	key := bytes.TrimSpace(raw)
	if len(key) == 0 || len(key) > 32<<10 || bytes.ContainsAny(key, "\r\n") {
		return nil, "", errors.New("SSH trust addition needs one public CA line")
	}
	keys := sshkeys.ParseAuthorizedKeys(key)
	if len(keys) != 1 || len(keys[0].Options) != 0 || strings.Contains(keys[0].Type, "-cert-") {
		return nil, "", errors.New("SSH trust addition needs a public CA key without options")
	}
	fields := bytes.Fields(key)
	if len(fields) < 2 {
		return nil, "", errors.New("SSH public CA line is incomplete")
	}
	canonical := append(append(append([]byte(nil), fields[0]...), ' '), fields[1]...)
	canonical = append(canonical, '\n')
	return canonical, keys[0].FingerprintSHA256, nil
}

// Refusal carries a closed preflight reason; raw host errors stay local.
type Refusal struct{ Code string }

func (e *Refusal) Error() string {
	switch e.Code {
	case "local_not_enabled":
		return "SSH trust fleet work is not enabled on this host"
	case "local_unconfirmed":
		return "SSH trust fleet work needs this host operator's confirmation"
	case "other_agent":
		return "SSH trust command names another enrolled host"
	case "policy_changed":
		return "SSH trust host settings changed since review"
	case "ca_pin_changed":
		return "SSH trust CA differs from this host's staged public key"
	case "execution_window_ended":
		return "SSH trust execution window ended; preview again"
	default:
		return "SSH trust preflight refused"
	}
}
func ReasonCode(code string) bool {
	switch code {
	case "local_not_enabled", "local_unconfirmed", "other_agent", "policy_changed", "ca_pin_changed", "execution_window_ended", "canceled", "local_configuration_invalid", "host_busy", "apply_failed", "readback_failed":
		return true
	default:
		return false
	}
}
