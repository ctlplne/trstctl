// SPDX-License-Identifier: MPL-2.0

package projections

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

const (
	EventCodeSigningCommanded          = "codesign.commanded"
	EventCodeSigningCompleted          = "codesign.completed"
	EventCodeSigningFailed             = "codesign.failed"
	EventCodeSigningEphemeralDestroyed = "codesign.ephemeral.destroyed"
)

type CodeSigningCommanded struct {
	OperationID    string `json:"operation_id"`
	IdempotencyKey string `json:"idempotency_key"`
	Mode           string `json:"mode"`
	RequestHash    string `json:"request_hash"`
	SealedCommand  []byte `json:"sealed_command"`
}

type CodeSigningCommandReference struct {
	OperationID string `json:"operation_id"`
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
}

func (p *Projector) applyCodeSigningTx(ctx context.Context, tx pgx.Tx, event events.Event) (bool, error) {
	switch event.Type {
	case EventCodeSigningCommanded:
		var payload CodeSigningCommanded
		if err := decode(event, &payload); err != nil {
			return true, err
		}
		if payload.OperationID == "" || payload.IdempotencyKey == "" || payload.RequestHash == "" || len(payload.SealedCommand) == 0 || (payload.Mode != "key" && payload.Mode != "keyless") {
			return true, fmt.Errorf("projections: %s payload is incomplete", event.Type)
		}
		command, err := json.Marshal(CodeSigningCommandReference{OperationID: payload.OperationID})
		if err != nil {
			return true, err
		}
		return true, p.store.ApplyCodeSigningIntentTx(ctx, tx, store.CodeSigningOperation{
			TenantID: event.TenantID, OperationID: payload.OperationID,
			IdempotencyKey: payload.IdempotencyKey, Mode: payload.Mode,
			RequestHash: payload.RequestHash, SealedCommand: payload.SealedCommand,
			Status: "queued", CreatedAt: event.Time, UpdatedAt: event.Time,
		}, command)
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
