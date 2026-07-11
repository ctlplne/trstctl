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
	EventManagedKeyCommandRequested = "managed_key.command.requested"
	EventManagedKeyCommandCompleted = "managed_key.command.completed"
	EventManagedKeyCommandFailed    = "managed_key.command.failed"
)

type ManagedKeyCommand struct {
	OperationID    string `json:"operation_id"`
	Provider       string `json:"provider"`
	Action         string `json:"action"`
	KeyID          string `json:"key_id,omitempty"`
	Algorithm      string `json:"algorithm"`
	RequestBinding string `json:"request_binding"`
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
	for _, eventType := range []string{EventManagedKeyCommandRequested, EventManagedKeyCommandCompleted, EventManagedKeyCommandFailed} {
		knownSchemaVersions[eventType] = map[int]bool{1: true}
	}
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
