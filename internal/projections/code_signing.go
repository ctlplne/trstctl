// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/codesigningref"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

var codeSigningApprovalEventNamespace = uuid.MustParse("046f42f9-87a1-5f88-a8e1-f3804ea19091")

const (
	EventCodeSigningCommanded          = "codesign.commanded"
	EventCodeSigningCompleted          = "codesign.completed"
	EventCodeSigningFailed             = "codesign.failed"
	EventCodeSigningEphemeralDestroyed = "codesign.ephemeral.destroyed"

	// CodeSigningApprovalEventSchemaVersion adds the exact one-shot approval use
	// to codesign.commanded. Version 1 remains replayable for deployments where
	// dual control was not enabled.
	CodeSigningApprovalEventSchemaVersion = 2

	// CodeSigningPrivacySafeEventSchemaVersion replaces the raw mutation key with
	// its domain-separated one-way reference plus the full request binding. Both
	// approved and approval-disabled commands use this shape; v1/v2 stay replayable.
	CodeSigningPrivacySafeEventSchemaVersion = 3
)

type CodeSigningCommanded struct {
	OperationID       string                      `json:"operation_id"`
	IdempotencyKey    string                      `json:"idempotency_key,omitempty"` // v1/v2 only.
	IdempotencyKeyRef string                      `json:"idempotency_key_ref,omitempty"`
	RequestBinding    string                      `json:"request_binding,omitempty"`
	Mode              string                      `json:"mode"`
	RequestHash       string                      `json:"request_hash"`
	SealedCommand     []byte                      `json:"sealed_command"`
	Approval          *store.OperationApprovalUse `json:"approval,omitempty"`
}

type CodeSigningCommandReference struct {
	OperationID string `json:"operation_id"`
}

// CodeSigningOperationID is the privacy-safe operation identity for a raw API
// mutation key. Only the one-way reference enters the UUID derivation.
func CodeSigningOperationID(tenantID, idempotencyKey string) string {
	return store.CodeSigningOperationID(tenantID, idempotencyKey)
}

// LegacyCodeSigningOperationID retains the v1/v2 raw-key derivation.
func LegacyCodeSigningOperationID(tenantID, idempotencyKey string) string {
	return store.LegacyCodeSigningOperationID(tenantID, idempotencyKey)
}

// CodeSigningApprovalEventID is the sole target event allowed to consume the
// approval for a commanded operation.
func CodeSigningApprovalEventID(tenantID, operationID string) string {
	return uuid.NewSHA1(codeSigningApprovalEventNamespace,
		[]byte(tenantID+"\x00"+EventCodeSigningCommanded+"\x00"+operationID)).String()
}

// CodeSigningRequestBinding is the privacy-safe first-command key. It binds the
// complete plaintext command digest and the caller's raw idempotency key without
// persisting either plaintext personal data or a reusable raw key.
func CodeSigningRequestBinding(requestHash, idempotencyKey string) string {
	binding, _ := CodeSigningRequestBindingFromRef(
		requestHash, store.CodeSigningIdempotencyKeyRef(idempotencyKey),
	)
	return binding
}

// CodeSigningRequestBindingFromRef reproduces the existing first-command
// binding without recovering the raw mutation key.
func CodeSigningRequestBindingFromRef(requestHash, keyRef string) (string, error) {
	if !store.IsCodeSigningIdempotencyKeyRef(keyRef) {
		return "", errors.New("projections: code-signing idempotency key reference is invalid")
	}
	return crypto.SHA256Hex([]byte("trstctl:approved-code-signing-request:v1\x00" +
		requestHash + "\x00" + strings.TrimPrefix(keyRef, "sha256:"))), nil
}

// CodeSigningCommandSemanticDigest includes the randomized ciphertext and every
// operational command field. Approved v2 commands use a versioned privacy-stable
// basis shared with their SQL projection: raw and operation-bound key forms have
// the same digest, and time uses PostgreSQL's durable microsecond precision. The
// historical v2 digest remains available below solely for one-way compatibility
// with fences and rows committed by an older release. V3 normalizes only fields
// the authorized erasure transform may rewrite; exact allowed privacy shapes are
// still checked separately against the durable fence.
func CodeSigningCommandSemanticDigest(event events.Event, payload CodeSigningCommanded) (string, error) {
	if schemaVersionOf(event) == CodeSigningApprovalEventSchemaVersion && payload.Approval != nil {
		if event.Type != EventCodeSigningCommanded {
			return "", errors.New("projections: legacy approved code-signing event type is invalid")
		}
		keyDigest := ""
		switch {
		case LegacyCodeSigningOperationID(event.TenantID, payload.IdempotencyKey) == payload.OperationID:
			keyDigest = store.CodeSigningIdempotencyKeyDigest(payload.IdempotencyKey)
		default:
			var ok bool
			keyDigest, ok = store.LegacyCodeSigningStorageKeyDigest(payload.IdempotencyKey, payload.OperationID)
			if !ok {
				return "", errors.New("projections: legacy approved code-signing key identity is invalid")
			}
		}
		return codesigningref.LegacyApprovedCommandSemanticDigest(codesigningref.LegacyApprovedCommandSemanticBasis{
			EventID: event.ID, TenantID: event.TenantID, EventTime: event.Time,
			OperationID: payload.OperationID, KeyDigest: keyDigest, Mode: payload.Mode,
			RequestHash: payload.RequestHash, SealedCommand: payload.SealedCommand,
			ApprovalRequestID:    payload.Approval.RequestID,
			ApprovalIntentDigest: payload.Approval.IntentDigest,
		})
	}
	return codeSigningHistoricalSemanticDigest(event, payload)
}

// LegacyCodeSigningHistoricalSemanticDigest reproduces the pre-privacy v2
// semantic format byte-for-byte. Callers may use it only to prove that an older
// durable row or fence is the predecessor of the canonical digest above.
func LegacyCodeSigningHistoricalSemanticDigest(event events.Event, payload CodeSigningCommanded) (string, error) {
	if schemaVersionOf(event) != CodeSigningApprovalEventSchemaVersion || payload.Approval == nil {
		return "", errors.New("projections: historical code-signing semantic compatibility requires approved schema v2")
	}
	return codeSigningHistoricalSemanticDigest(event, payload)
}

func codeSigningHistoricalSemanticDigest(event events.Event, payload CodeSigningCommanded) (string, error) {
	normalized := payload
	if payload.Approval != nil {
		use := *payload.Approval
		use.Requester = ""
		use.Reason = ""
		use.EvidenceRefs = nil
		normalized.Approval = &use
	}
	var actor *events.Actor
	if event.Actor != nil {
		copyActor := *event.Actor
		copyActor.Subject = ""
		copyActor.Roles = append([]string(nil), event.Actor.Roles...)
		if schemaVersionOf(event) >= CodeSigningPrivacySafeEventSchemaVersion {
			for i := range copyActor.Roles {
				copyActor.Roles[i] = ""
			}
		}
		actor = &copyActor
	}
	domain := "trstctl:approved-code-signing-event:v1\x00"
	if schemaVersionOf(event) >= CodeSigningPrivacySafeEventSchemaVersion {
		if err := validatePrivacySafeCodeSigningCommand(payload); err != nil {
			return "", err
		}
		normalized.IdempotencyKey = ""
		domain = "trstctl:approved-code-signing-event:v2\x00"
	}
	basis := struct {
		ID            string               `json:"id"`
		Type          string               `json:"type"`
		TenantID      string               `json:"tenant_id"`
		Time          time.Time            `json:"time"`
		SchemaVersion int                  `json:"schema_version"`
		Actor         *events.Actor        `json:"actor,omitempty"`
		Payload       CodeSigningCommanded `json:"payload"`
	}{event.ID, event.Type, event.TenantID, event.Time.UTC(), schemaVersionOf(event), actor, normalized}
	raw, err := json.Marshal(basis)
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(append([]byte(domain), raw...)), nil
}

func validatePrivacySafeCodeSigningCommand(payload CodeSigningCommanded) error {
	if payload.IdempotencyKey != "" || !store.IsCodeSigningIdempotencyKeyRef(payload.IdempotencyKeyRef) {
		return errors.New("projections: privacy-safe code-signing command carries an invalid key reference")
	}
	expectedBinding, err := CodeSigningRequestBindingFromRef(payload.RequestHash, payload.IdempotencyKeyRef)
	if err != nil || payload.RequestBinding != expectedBinding {
		return errors.New("projections: privacy-safe code-signing command request binding differs")
	}
	return nil
}

type CodeSigningCompleted struct {
	OperationID      string          `json:"operation_id"`
	RequestHash      string          `json:"request_hash"`
	Response         json.RawMessage `json:"response"`
	RekorDestination string          `json:"rekor_destination"`
	RekorPayload     json.RawMessage `json:"rekor_payload"`
	EphemeralHandle  string          `json:"ephemeral_handle,omitempty"`
}

type CodeSigningFailed struct {
	OperationID     string `json:"operation_id"`
	Error           string `json:"error"`
	EphemeralHandle string `json:"ephemeral_handle,omitempty"`
}

func init() {
	for _, eventType := range []string{
		EventCodeSigningCommanded,
		EventCodeSigningCompleted,
		EventCodeSigningFailed,
		EventCodeSigningEphemeralDestroyed,
	} {
		knownSchemaVersions[eventType] = map[int]bool{1: true}
	}
	knownSchemaVersions[EventCodeSigningCommanded][CodeSigningApprovalEventSchemaVersion] = true
	knownSchemaVersions[EventCodeSigningCommanded][CodeSigningPrivacySafeEventSchemaVersion] = true
}

func (p *Projector) resolveApprovedCodeSigningFenceUseTx(
	ctx context.Context,
	tx pgx.Tx,
	event events.Event,
	payload *CodeSigningCommanded,
) (string, error) {
	fence, currentUse, privacyRewritten, err := p.store.LockApprovedTargetFenceTx(ctx, tx,
		event.TenantID, store.ApprovedTargetCodeSigningCommand, payload.OperationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	semantic, err := CodeSigningCommandSemanticDigest(event, *payload)
	if err != nil {
		return "", err
	}
	if semantic != fence.SemanticDigest {
		compatible := false
		if schemaVersionOf(event) == CodeSigningApprovalEventSchemaVersion {
			historical, historicalErr := LegacyCodeSigningHistoricalSemanticDigest(event, *payload)
			if historicalErr != nil {
				return "", historicalErr
			}
			compatible = historical == fence.SemanticDigest
		}
		if !compatible {
			return "", fmt.Errorf("%w: retained approved code-signing command differs from durable fence", store.ErrIdempotencyConflict)
		}
	}
	if !privacyRewritten {
		if !reflect.DeepEqual(event.Actor, fence.Actor) {
			return "", fmt.Errorf("%w: retained approved code-signing actor differs from durable fence", store.ErrIdempotencyConflict)
		}
		return fence.SemanticDigest, nil
	}
	var original CodeSigningCommanded
	if err := json.Unmarshal(fence.Payload, &original); err != nil {
		return "", fmt.Errorf("projections: decode approved code-signing fence: %w", err)
	}
	if original.Approval == nil || payload.Approval == nil {
		return "", fmt.Errorf("%w: approved code-signing privacy recovery lacks authority", store.ErrApprovalDrifted)
	}
	if err := store.ValidateApprovedTargetActorPrivacyRewrite(event.TenantID,
		fence.Actor, currentUse.Requester, event.Actor, original.Approval.Requester); err != nil {
		return "", fmt.Errorf("%w: approved code-signing actor privacy recovery differs", err)
	}
	if err := store.ValidateApprovedTargetPrivacyRewrite(event.TenantID,
		*original.Approval, currentUse, *payload.Approval); err != nil {
		return "", fmt.Errorf("%w: approved code-signing privacy recovery differs", err)
	}
	payload.Approval = &currentUse
	return fence.SemanticDigest, nil
}

func (p *Projector) applyCodeSigningTx(ctx context.Context, tx pgx.Tx, event events.Event) (bool, error) {
	switch event.Type {
	case EventCodeSigningCommanded:
		var payload CodeSigningCommanded
		if err := decode(event, &payload); err != nil {
			return true, err
		}
		version := schemaVersionOf(event)
		if payload.OperationID == "" || payload.RequestHash == "" || len(payload.SealedCommand) == 0 || (payload.Mode != "key" && payload.Mode != "keyless") {
			return true, fmt.Errorf("projections: %s payload is incomplete", event.Type)
		}
		privacySafe := version == CodeSigningPrivacySafeEventSchemaVersion
		if privacySafe {
			if err := validatePrivacySafeCodeSigningCommand(payload); err != nil {
				return true, err
			}
			if !event.Time.Equal(event.Time.UTC().Truncate(time.Microsecond)) {
				return true, fmt.Errorf("%w: privacy-safe code-signing event time is not PostgreSQL-exact", store.ErrIdempotencyConflict)
			}
		} else if payload.IdempotencyKey == "" || payload.IdempotencyKeyRef != "" || payload.RequestBinding != "" {
			return true, fmt.Errorf("projections: %s legacy payload key shape is invalid", event.Type)
		}
		if hasApproval := payload.Approval != nil; (version == 1 && hasApproval) ||
			(version == CodeSigningApprovalEventSchemaVersion && !hasApproval) {
			return true, fmt.Errorf("projections: %s approval payload/schema mismatch", event.Type)
		}
		approvedCommand := payload.Approval != nil
		var storedIdempotencyKey string
		expectedOperationID := payload.OperationID
		expectedResourceID := ""
		legacyRawKey := false
		if privacySafe {
			storedIdempotencyKey = payload.IdempotencyKeyRef
			expectedOperationID = store.CodeSigningOperationIDFromRef(event.TenantID, payload.IdempotencyKeyRef)
			var err error
			expectedResourceID, err = store.CodeSigningApprovalResourceIDFromRef(payload.RequestHash, payload.IdempotencyKeyRef)
			if err != nil {
				return true, err
			}
		} else if LegacyCodeSigningOperationID(event.TenantID, payload.IdempotencyKey) == payload.OperationID {
			legacyRawKey = true
			expectedResourceID = store.CodeSigningApprovalResourceID(payload.RequestHash, payload.IdempotencyKey)
			storedIdempotencyKey = store.LegacyCodeSigningStorageKey(payload.OperationID, payload.IdempotencyKey)
		} else if store.IsLegacyCodeSigningStorageKey(payload.IdempotencyKey, payload.OperationID) {
			// Privacy erasure may replace a subject-bearing v1/v2 API key only
			// with the exact historical operation-bound storage identity. The
			// operation UUID remains byte-identical, while rebuilt SQL never
			// needs to retain or serve the raw key.
			storedIdempotencyKey = payload.IdempotencyKey
			if payload.Approval != nil {
				var err error
				expectedResourceID, err = store.CodeSigningApprovalResourceIDForOperation(
					event.TenantID, payload.OperationID, payload.RequestHash,
					payload.IdempotencyKey, payload.Approval.ResourceID,
				)
				if err != nil {
					return true, err
				}
			}
		} else {
			return true, fmt.Errorf("%w: legacy code-signing command operation/key identity changed", store.ErrIdempotencyConflict)
		}
		if payload.OperationID != expectedOperationID {
			return true, fmt.Errorf("%w: code-signing command operation identity changed", store.ErrIdempotencyConflict)
		}
		fenceSemanticDigest := ""
		if approvedCommand {
			var fenceErr error
			fenceSemanticDigest, fenceErr = p.resolveApprovedCodeSigningFenceUseTx(ctx, tx, event, &payload)
			if fenceErr != nil {
				return true, fenceErr
			}
			if event.ID != CodeSigningApprovalEventID(event.TenantID, expectedOperationID) ||
				payload.Approval.ResourceKind != "code_signing" || payload.Approval.ResourceID != expectedResourceID ||
				payload.Approval.Action != "sign" || payload.Approval.FromState != "" ||
				payload.Approval.ToState != "" || payload.Approval.TargetVersion != 0 || payload.Approval.Issuance != nil {
				return true, fmt.Errorf("%w: code-signing approved command identity changed", store.ErrApprovalDrifted)
			}
		}
		command, err := json.Marshal(CodeSigningCommandReference{OperationID: payload.OperationID})
		if err != nil {
			return true, err
		}
		semanticDigest := ""
		historicalSemanticDigest := ""
		sourceEventID := ""
		if approvedCommand {
			semanticDigest, err = CodeSigningCommandSemanticDigest(event, payload)
			if err != nil {
				return true, err
			}
			if version == CodeSigningApprovalEventSchemaVersion && legacyRawKey {
				historicalSemanticDigest, err = LegacyCodeSigningHistoricalSemanticDigest(event, payload)
				if err != nil {
					return true, err
				}
			}
			sourceEventID = event.ID
		}
		if err := p.store.ApplyCodeSigningIntentTx(ctx, tx, store.CodeSigningOperation{
			TenantID: event.TenantID, OperationID: payload.OperationID,
			IdempotencyKey: storedIdempotencyKey, Mode: payload.Mode,
			RequestHash: payload.RequestHash, SealedCommand: payload.SealedCommand,
			Status: "queued", CreatedAt: event.Time, UpdatedAt: event.Time,
			Approval: payload.Approval, SourceEventID: sourceEventID,
			SemanticDigest: semanticDigest, HistoricalSemanticDigest: historicalSemanticDigest,
		}, command); err != nil {
			return true, err
		}
		if approvedCommand {
			if fenceSemanticDigest == "" {
				fenceSemanticDigest = semanticDigest
			}
			return true, p.store.CompleteApprovedTargetFenceTx(ctx, tx, event.TenantID,
				store.ApprovedTargetCodeSigningCommand, payload.OperationID,
				event.ID, event.Type, schemaVersionOf(event), event.Time, []byte(fenceSemanticDigest))
		}
		return true, nil
	case EventCodeSigningCompleted:
		var payload CodeSigningCompleted
		if err := decode(event, &payload); err != nil {
			return true, err
		}
		if payload.OperationID == "" || payload.RequestHash == "" || len(payload.Response) == 0 || payload.RekorDestination == "" || len(payload.RekorPayload) == 0 {
			return true, fmt.Errorf("projections: %s payload is incomplete", event.Type)
		}
		return true, p.store.ApplyCodeSigningCompletedTx(ctx, tx, event.TenantID,
			payload.OperationID, payload.RequestHash, payload.Response,
			payload.RekorDestination, payload.RekorPayload, payload.EphemeralHandle,
			event.Time)
	case EventCodeSigningFailed:
		var payload CodeSigningFailed
		if err := decode(event, &payload); err != nil {
			return true, err
		}
		if payload.OperationID == "" || payload.Error == "" {
			return true, fmt.Errorf("projections: %s payload is incomplete", event.Type)
		}
		return true, p.store.ApplyCodeSigningFailedTx(ctx, tx, event.TenantID,
			payload.OperationID, payload.Error, payload.EphemeralHandle, event.Time)
	case EventCodeSigningEphemeralDestroyed:
		var payload CodeSigningCommandReference
		if err := decode(event, &payload); err != nil {
			return true, err
		}
		if payload.OperationID == "" {
			return true, fmt.Errorf("projections: %s payload is incomplete", event.Type)
		}
		return true, p.store.ApplyCodeSigningCleanupCompletedTx(ctx, tx, event.TenantID,
			payload.OperationID, event.Time)
	default:
		return false, nil
	}
}
