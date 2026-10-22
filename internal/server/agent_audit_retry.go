// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
)

// agentAuditRetryPayload is the outbox row for an agent audit event whose first
// append reached the bus and was not acknowledged (A65). It carries the event
// exactly as first attempted — identity, time, actor and payload — so the retry
// is the same JetStream message: the stream's duplicate window, not a second
// record, answers a publish whose acknowledgement was lost.
type agentAuditRetryPayload struct {
	ID            string          `json:"id"`
	Type          string          `json:"type"`
	TenantID      string          `json:"tenant_id"`
	Time          time.Time       `json:"time"`
	SchemaVersion int             `json:"schema_version,omitempty"`
	Data          json.RawMessage `json:"data,omitempty"`
	Actor         *events.Actor   `json:"actor,omitempty"`
}

const (
	agentAuditRetryKeyPrefix = "agent-audit-retry:"
	// agentAuditRetryRole keeps the row off the agent channel: only the control
	// plane holds the event log.
	agentAuditRetryRole = "control_plane"
)

// queueAgentAuditRetry decides what a failed audit append becomes. A publish the
// bus did not acknowledge is queued for the dispatcher under the event's fixed
// ID; anything else (a payload the privacy schema refuses, a missing tenant) is
// deterministic and would fail the same way again, so it is logged and not
// retried. Neither log line carries the payload.
func (a *agentService) queueAgentAuditRetry(ctx context.Context, event events.Event, cause error) {
	attrs := []any{
		slog.String("tenant_id", event.TenantID), slog.String("event_type", event.Type), slog.String("event_id", event.ID),
	}
	logError := func(reason string) {
		if a.logger != nil {
			a.logger.Error("agent job audit event could not be stored", append(attrs, slog.String("reason", reason))...)
		}
	}
	if !errors.Is(cause, events.ErrPublish) {
		logError("append refused")
		return
	}
	if a.outbox == nil || a.store == nil {
		logError("publish not acknowledged and no outbox to retry through")
		return
	}
	payload, err := json.Marshal(agentAuditRetryPayload{
		ID: event.ID, Type: event.Type, TenantID: event.TenantID, Time: event.Time,
		SchemaVersion: event.SchemaVersion, Data: event.Data, Actor: event.Actor,
	})
	if err != nil {
		logError("retry payload")
		return
	}
	if err := a.store.WithTenant(ctx, event.TenantID, func(tx pgx.Tx) error {
		_, err := a.outbox.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID: event.TenantID, Destination: orchestrator.DestinationAgentAuditRetry,
			IdempotencyKey: agentAuditRetryKeyPrefix + event.ID, Payload: payload,
			RequiredAgentRole: agentAuditRetryRole,
		})
		return err
	}); err != nil {
		logError("retry not queued")
		return
	}
	if a.logger != nil {
		a.logger.Warn("agent job audit event queued for retry", attrs...)
	}
}

// handleAgentAuditRetry re-appends a queued agent audit event under its original
// identity. A failure here is the outbox's to retry with backoff; the row's
// idempotency key is the event ID and the stream deduplicates the message ID,
// so neither a redelivery nor a late first acknowledgement records it twice.
func (d *issuanceDispatcher) handleAgentAuditRetry(ctx context.Context, m orchestrator.Message) error {
	if d.log == nil {
		return errors.New("server: agent audit retry: no event log")
	}
	var row agentAuditRetryPayload
	if err := json.Unmarshal(m.Payload, &row); err != nil {
		return fmt.Errorf("server: agent audit retry: %w", err)
	}
	if row.ID == "" || row.Type == "" || row.TenantID == "" || row.TenantID != m.TenantID {
		return errors.New("server: agent audit retry: row does not name a tenant-bound event")
	}
	_, err := d.log.Append(ctx, events.Event{
		ID: row.ID, Type: row.Type, TenantID: row.TenantID, Time: row.Time,
		SchemaVersion: row.SchemaVersion, Data: row.Data, Actor: row.Actor,
	})
	return err
}
