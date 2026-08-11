// SPDX-License-Identifier: MPL-2.0

package projections

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

const (
	EventManagedKeyCommandRequested = "managed_key.command.requested"
	EventManagedKeyCommandCompleted = "managed_key.command.completed"
	EventManagedKeyCommandFailed    = "managed_key.command.failed"

	// ManagedKeyApprovalEventSchemaVersion is the first managed-key command
	// payload that carries an exact, one-shot operation approval. Version-one
	// generate history remains replayable, but a destructive command without the
	// v2 authority fields always fails closed.
	ManagedKeyApprovalEventSchemaVersion = 2
)

type ManagedKeyCommand struct {
	OperationID          string                      `json:"operation_id"`
	Provider             string                      `json:"provider"`
	Action               string                      `json:"action"`
	KeyID                string                      `json:"key_id,omitempty"`
	Algorithm            string                      `json:"algorithm"`
	RequestBinding       string                      `json:"request_binding"`
	Requester            string                      `json:"requester,omitempty"`
	FromState            string                      `json:"from_state,omitempty"`
	ToState              string                      `json:"to_state,omitempty"`
	TargetVersion        uint64                      `json:"target_version,omitempty"`
	IdempotencyKeyDigest string                      `json:"idempotency_key_digest,omitempty"`
	ApprovalEvidenceRefs []string                    `json:"approval_evidence_refs,omitempty"`
	Approval             *store.OperationApprovalUse `json:"approval,omitempty"`
}

type ManagedKeyCommandCompleted struct {
	ManagedKeyCommand
	ResultKeyID string `json:"result_key_id"`
	PublicDER   []byte `json:"public_der"`
	State       string `json:"state"`
}

type ManagedKeyCommandFailed struct {
	OperationID    string `json:"operation_id"`
	RequestBinding string `json:"request_binding"`
	Error          string `json:"error"`
}

func init() {
	knownSchemaVersions[EventManagedKeyCommandRequested] = map[int]bool{1: true, ManagedKeyApprovalEventSchemaVersion: true}
	knownSchemaVersions[EventManagedKeyCommandCompleted] = map[int]bool{1: true, ManagedKeyApprovalEventSchemaVersion: true}
	knownSchemaVersions[EventManagedKeyCommandFailed] = map[int]bool{1: true}
}

// ManagedKeyApprovalEvidence derives non-secret receipts reviewers see: provider
// and algorithm labels, one digest for the entire immutable signer command, and
// one digest for the raw HTTP Idempotency-Key. The raw key is never persisted.
func ManagedKeyApprovalEvidence(command ManagedKeyCommand) ([]string, error) {
	if len(command.IdempotencyKeyDigest) != 64 {
		return nil, fmt.Errorf("projections: managed-key idempotency digest must be SHA-256 hex")
	}
	if _, err := hex.DecodeString(command.IdempotencyKeyDigest); err != nil {
		return nil, fmt.Errorf("projections: managed-key idempotency digest must be SHA-256 hex: %w", err)
	}
	basis := struct {
		OperationID          string `json:"operation_id"`
		Provider             string `json:"provider"`
		Action               string `json:"action"`
		KeyID                string `json:"key_id"`
		Algorithm            string `json:"algorithm"`
		RequestBinding       string `json:"request_binding"`
		Requester            string `json:"requester"`
		FromState            string `json:"from_state"`
		ToState              string `json:"to_state"`
		TargetVersion        uint64 `json:"target_version"`
		IdempotencyKeyDigest string `json:"idempotency_key_digest"`
	}{
		OperationID: command.OperationID, Provider: command.Provider, Action: command.Action,
		KeyID: command.KeyID, Algorithm: command.Algorithm, RequestBinding: command.RequestBinding,
		Requester: command.Requester, FromState: command.FromState, ToState: command.ToState,
		TargetVersion: command.TargetVersion, IdempotencyKeyDigest: command.IdempotencyKeyDigest,
	}
	raw, err := json.Marshal(basis)
	if err != nil {
		return nil, err
	}
	return []string{
		"managed-key-algorithm:" + command.Algorithm,
		"managed-key-command-sha256:" + trstcrypto.SHA256Hex(append([]byte("trstctl:managed-key-command:v1\x00"), raw...)),
		"managed-key-idempotency-sha256:" + command.IdempotencyKeyDigest,
		"managed-key-provider:" + command.Provider,
	}, nil
}

// ManagedKeyIdempotencyKeyDigest turns the raw mutation key into reviewer-safe,
// domain-separated evidence. A fresh key creates a fresh approval intent, while
// retrying the same key resolves to the same request.
func ManagedKeyIdempotencyKeyDigest(idempotencyKey string) string {
	return trstcrypto.SHA256Hex([]byte("trstctl:managed-key-idempotency-key:v1\x00" + idempotencyKey))
}

// ManagedKeyCommandTargetState maps a destructive command to the state of the
// approved target after execution. Rotate supersedes the reviewed generation;
// its successor is a different managed-key row in active state.
func ManagedKeyCommandTargetState(action string) (string, bool) {
	switch action {
	case "rotate":
		return "superseded", true
	case "revoke":
		return "revoked", true
	case "zeroize":
		return "zeroized", true
	default:
		return "", false
	}
}

func sameManagedKeyEvidence(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func (p *Projector) applyManagedKeyTx(ctx context.Context, tx pgx.Tx, event events.Event) (bool, error) {
	switch event.Type {
	case EventManagedKeyCommandRequested:
		var payload ManagedKeyCommand
		if err := decode(event, &payload); err != nil {
			return true, err
		}
		if payload.OperationID == "" || payload.Provider == "" || payload.Action == "" || payload.Algorithm == "" || payload.RequestBinding == "" {
			return true, fmt.Errorf("projections: %s payload is incomplete", event.Type)
		}
		switch payload.Action {
		case "generate":
			if schemaVersionOf(event) != events.DefaultSchemaVersion || payload.Approval != nil || len(payload.ApprovalEvidenceRefs) != 0 {
				return true, fmt.Errorf("projections: generate cannot consume destructive-operation approval")
			}
		case "rotate", "revoke", "zeroize":
			if schemaVersionOf(event) != ManagedKeyApprovalEventSchemaVersion {
				return true, fmt.Errorf("%w: destructive managed-key command has no approval schema", store.ErrApprovalNotReady)
			}
			if payload.KeyID == "" || payload.Requester == "" || payload.FromState == "" ||
				payload.ToState == "" || payload.TargetVersion == 0 || payload.Approval == nil {
				return true, fmt.Errorf("%w: destructive managed-key command has no exact authority", store.ErrApprovalNotReady)
			}
			toState, _ := ManagedKeyCommandTargetState(payload.Action)
			if payload.ToState != toState || payload.Approval.ResourceKind != "managed_key" ||
				payload.Approval.ResourceID != payload.KeyID ||
				payload.Approval.Action != "managedkey:"+payload.Action ||
				payload.Approval.Requester != payload.Requester ||
				payload.Approval.FromState != payload.FromState ||
				payload.Approval.ToState != payload.ToState ||
				payload.Approval.TargetVersion != payload.TargetVersion {
				return true, store.ErrApprovalDrifted
			}
			expectedEvidence, err := ManagedKeyApprovalEvidence(payload)
			if err != nil {
				return true, err
			}
			if !sameManagedKeyEvidence(payload.ApprovalEvidenceRefs, expectedEvidence) {
				return true, store.ErrApprovalDrifted
			}
			request, err := p.store.ValidateManagedKeyApprovalCommandTx(ctx, tx, event.TenantID,
				*payload.Approval, payload.KeyID, payload.ApprovalEvidenceRefs)
			if err != nil {
				return true, err
			}
			if request.Status == store.ApprovalStatusConsumed {
				// The generic consumer distinguishes the one safe replay (this exact
				// immutable event) from every second attempted use. Do that before
				// looking at mutable key state, which may have legitimately changed
				// after the original command completed.
				if err := p.store.ConsumeOperationApprovalTx(ctx, tx, event.TenantID,
					*payload.Approval, event.ID, event.Time); err != nil {
					return true, err
				}
			} else {
				key, err := p.store.ManagedKeyApprovalTargetTx(ctx, tx, event.TenantID,
					payload.Provider, payload.KeyID, true)
				if err != nil {
					return true, err
				}
				if key.Algorithm != payload.Algorithm || key.State != payload.FromState ||
					key.Version < 0 || uint64(key.Version) != payload.TargetVersion {
					return true, store.ErrApprovalDrifted
				}
				if err := p.store.ConsumeOperationApprovalTx(ctx, tx, event.TenantID,
					*payload.Approval, event.ID, event.Time); err != nil {
					return true, err
				}
			}
		default:
			return true, fmt.Errorf("projections: unsupported managed-key action %q", payload.Action)
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return true, err
		}
		return true, p.store.ApplyManagedKeyIntentTx(ctx, tx, store.ManagedKeyOperation{
			TenantID: event.TenantID, OperationID: payload.OperationID, Provider: payload.Provider,
			Action: payload.Action, KeyID: payload.KeyID, Algorithm: payload.Algorithm, RequestBinding: payload.RequestBinding,
			Status: "queued", CreatedAt: event.Time, UpdatedAt: event.Time,
		}, body)
	case EventManagedKeyCommandCompleted:
		var payload ManagedKeyCommandCompleted
		if err := decode(event, &payload); err != nil {
			return true, err
		}
		if payload.OperationID == "" || payload.ResultKeyID == "" || payload.Provider == "" || payload.Action == "" || payload.Algorithm == "" || payload.RequestBinding == "" || payload.State == "" || len(payload.PublicDER) == 0 {
			return true, fmt.Errorf("projections: %s payload is incomplete", event.Type)
		}
		if hasApproval := payload.Approval != nil; hasApproval != (schemaVersionOf(event) == ManagedKeyApprovalEventSchemaVersion) {
			return true, fmt.Errorf("projections: %s approval payload/schema mismatch", event.Type)
		}
		return true, p.store.ApplyManagedKeyCompletedTx(ctx, tx, store.ManagedKeyOperation{
			TenantID: event.TenantID, OperationID: payload.OperationID, Provider: payload.Provider,
			Action: payload.Action, KeyID: payload.KeyID, Algorithm: payload.Algorithm, RequestBinding: payload.RequestBinding,
			Status: "completed", ResultKeyID: payload.ResultKeyID, PublicDER: payload.PublicDER,
			ResultState: payload.State, UpdatedAt: event.Time,
		})
	case EventManagedKeyCommandFailed:
		var payload ManagedKeyCommandFailed
		if err := decode(event, &payload); err != nil {
			return true, err
		}
		if payload.OperationID == "" || payload.RequestBinding == "" || payload.Error == "" {
			return true, fmt.Errorf("projections: %s payload is incomplete", event.Type)
		}
		return true, p.store.ApplyManagedKeyFailedTx(ctx, tx, event.TenantID, payload.OperationID, payload.RequestBinding, payload.Error, event.Time)
	default:
		return false, nil
	}
}
