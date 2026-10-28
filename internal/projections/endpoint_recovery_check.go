// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// A210: a recovery check of a contained host target. A person queues it; the
// enrolled host agent answers in a signed job receipt.
const (
	EventEndpointRecoveryCheckRequested = "endpoint.recovery_check.requested"
	EventEndpointRecoveryChecked        = "endpoint.recovery_check.checked"
	EventEndpointRecoveryCheckFailed    = "endpoint.recovery_check.failed"
)

// EndpointRecoveryCheckRequested queues one check on the target's enrolled host.
type EndpointRecoveryCheckRequested struct {
	CheckID             string   `json:"check_id"`
	TargetID            string   `json:"target_id"`
	TargetRevision      string   `json:"target_revision"`
	AgentID             string   `json:"agent_id"`
	RevokedFingerprints []string `json:"revoked_fingerprints,omitempty"`
	RequestedBy         string   `json:"requested_by,omitempty"`
	IdempotencyKey      string   `json:"idempotency_key"`
}

// EndpointRecoveryChecked is the host's signed answer: digests of the pinned
// recovery action, never its path, and the listener's state.
type EndpointRecoveryChecked struct {
	CheckID            string `json:"check_id"`
	TargetID           string `json:"target_id"`
	JobID              int64  `json:"job_id"`
	Attempt            int    `json:"attempt"`
	Recovery           string `json:"recovery"`
	RecoveryAction     string `json:"recovery_action,omitempty"`
	ExecutableSHA256   string `json:"executable_sha256,omitempty"`
	ArgvSHA256         string `json:"argv_sha256,omitempty"`
	Listener           string `json:"listener"`
	ServingFingerprint string `json:"serving_fingerprint,omitempty"`
	EvidenceDigest     string `json:"evidence_digest"`
	ReceiptStatement   string `json:"receipt_statement"`
	ReceiptSignature   string `json:"receipt_signature_base64"`
	SignerFingerprint  string `json:"signer_fingerprint"`
	Agent              string `json:"agent"`
}

// EndpointRecoveryCheckFailed is a host's signed refusal, with a closed reason.
type EndpointRecoveryCheckFailed struct {
	CheckID           string `json:"check_id"`
	TargetID          string `json:"target_id"`
	JobID             int64  `json:"job_id"`
	Attempt           int    `json:"attempt"`
	Reason            string `json:"reason"`
	ReceiptSignature  string `json:"receipt_signature_base64"`
	SignerFingerprint string `json:"signer_fingerprint"`
	Agent             string `json:"agent"`
}

var (
	recoveryCheckRecovery = map[string]bool{"pinned": true, "no_recovery_action": true, "no_binding": true}
	recoveryCheckListener = map[string]bool{"none": true, "stopped": true, "serving": true, "serving_revoked": true, "unverified": true}
)

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func optionalSHA256Hex(value string) bool {
	if value == "" {
		return true
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && strings.ToLower(value) == value
}

// ValidateEndpointRecoveryCheckRequested checks a request's identifiers.
func ValidateEndpointRecoveryCheckRequested(pl EndpointRecoveryCheckRequested) error {
	if !canonicalUUID(pl.CheckID) || !canonicalUUID(pl.TargetID) || !canonicalUUID(pl.AgentID) ||
		strings.TrimSpace(pl.TargetRevision) == "" || strings.TrimSpace(pl.IdempotencyKey) == "" {
		return errors.New("a recovery check names a check, a target revision, an agent and a request key")
	}
	if len(pl.RevokedFingerprints) > 16 {
		return errors.New("a recovery check names at most 16 revoked leaves")
	}
	for _, fp := range pl.RevokedFingerprints {
		if fp == "" || !optionalSHA256Hex(fp) {
			return errors.New("a revoked leaf is a lowercase SHA-256 fingerprint")
		}
	}
	return nil
}

// ValidateEndpointRecoveryChecked checks an answer's closed vocabulary.
func ValidateEndpointRecoveryChecked(pl EndpointRecoveryChecked) error {
	if !canonicalUUID(pl.CheckID) || !canonicalUUID(pl.TargetID) || pl.JobID <= 0 || pl.Attempt <= 0 {
		return errors.New("a recovery check answer names its check, target, job and attempt")
	}
	if !recoveryCheckRecovery[pl.Recovery] || !recoveryCheckListener[pl.Listener] {
		return errors.New("a recovery check answer has an unknown state")
	}
	if !optionalSHA256Hex(pl.ExecutableSHA256) || !optionalSHA256Hex(pl.ArgvSHA256) ||
		!optionalSHA256Hex(pl.ServingFingerprint) || pl.EvidenceDigest == "" {
		return errors.New("a recovery check answer carries malformed digests")
	}
	if (pl.Recovery == "pinned") != (pl.RecoveryAction != "" && pl.ExecutableSHA256 != "" && pl.ArgvSHA256 != "") {
		return errors.New("only a pinned recovery action carries a name and digests")
	}
	return nil
}

func (p *Projector) applyEndpointRecoveryCheckTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventEndpointRecoveryCheckRequested:
		var pl EndpointRecoveryCheckRequested
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if err := ValidateEndpointRecoveryCheckRequested(pl); err != nil {
			return true, fmt.Errorf("projections: %s: %w", e.Type, err)
		}
		return true, p.store.ApplyEndpointRecoveryCheckRequestedTx(ctx, tx, store.EndpointRecoveryCheck{
			TenantID: e.TenantID, TargetID: pl.TargetID, CheckID: pl.CheckID, TargetRevision: pl.TargetRevision,
			AgentID: pl.AgentID, RequestedBy: pl.RequestedBy, RequestedAt: e.Time, EventSequence: e.Sequence,
		})
	case EventEndpointRecoveryChecked:
		var pl EndpointRecoveryChecked
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if err := ValidateEndpointRecoveryChecked(pl); err != nil {
			return true, fmt.Errorf("projections: %s: %w", e.Type, err)
		}
		jobID, checkedAt := pl.JobID, e.Time
		return true, p.store.ApplyEndpointRecoveryCheckAnsweredTx(ctx, tx, store.EndpointRecoveryCheck{
			TenantID: e.TenantID, TargetID: pl.TargetID, CheckID: pl.CheckID, Status: store.EndpointRecoveryCheckChecked,
			Recovery: pl.Recovery, RecoveryAction: pl.RecoveryAction, ExecutableSHA256: pl.ExecutableSHA256,
			ArgvSHA256: pl.ArgvSHA256, Listener: pl.Listener, ServingFingerprint: pl.ServingFingerprint,
			JobID: &jobID, EvidenceDigest: pl.EvidenceDigest, CheckedAt: timePointer(checkedAt), EventSequence: e.Sequence,
		})
	case EventEndpointRecoveryCheckFailed:
		var pl EndpointRecoveryCheckFailed
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if !canonicalUUID(pl.CheckID) || !canonicalUUID(pl.TargetID) || pl.JobID <= 0 || strings.TrimSpace(pl.Reason) == "" {
			return true, fmt.Errorf("projections: %s: a failed recovery check names its check, target, job and reason", e.Type)
		}
		jobID := pl.JobID
		return true, p.store.ApplyEndpointRecoveryCheckAnsweredTx(ctx, tx, store.EndpointRecoveryCheck{
			TenantID: e.TenantID, TargetID: pl.TargetID, CheckID: pl.CheckID, Status: store.EndpointRecoveryCheckFailed,
			Failure: pl.Reason, JobID: &jobID, CheckedAt: timePointer(e.Time), EventSequence: e.Sequence,
		})
	}
	return false, nil
}

func timePointer(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
