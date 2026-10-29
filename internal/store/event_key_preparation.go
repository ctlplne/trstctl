// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/eventprotect"
)

const (
	EventKeyPreparationDestination = "eventprivacy.prepare"
	EventKeyPreparationEffectLane  = "eventprivacy.prepare"
)

// EventKeyPreparationCommand contains only public source coordinates. It is an
// intent, not permission to create a key: the receiver must independently match
// these fields to the retained request and its first registration lifetime.
type EventKeyPreparationCommand struct {
	Ref                  eventprotect.KeyRef `json:"ref"`
	RegistrationIdentity string              `json:"registration_identity"`
	RequestedEventID     string              `json:"requested_event_id"`
	RequestedSequence    uint64              `json:"requested_sequence"`
	RequestedAt          time.Time           `json:"requested_at"`
	RetentionNanos       int64               `json:"retention_ns"`
}

func EventKeyPreparationOutboxKey(keyID string) string {
	return EventKeyPreparationDestination + ":" + keyID
}

func (command EventKeyPreparationCommand) Validate() error {
	tenant, tenantErr := uuid.Parse(command.Ref.TenantID)
	key, keyErr := uuid.Parse(command.Ref.ID)
	registration := command.RegistrationIdentity
	if tenantErr != nil || tenant == uuid.Nil || tenant.String() != command.Ref.TenantID ||
		keyErr != nil || key == uuid.Nil || key.String() != command.Ref.ID ||
		registration == "" || len(registration) > 512 || !utf8.ValidString(registration) ||
		strings.TrimSpace(registration) != registration || strings.ContainsFunc(registration, unicode.IsControl) ||
		command.RequestedEventID != command.Ref.ID+":requested" || command.RequestedSequence == 0 ||
		command.RequestedAt.IsZero() || command.RetentionNanos <= 0 {
		return fmt.Errorf("store: invalid event key preparation source coordinates")
	}
	return nil
}

// EnsureEventKeyPreparationTx queues the exact first request in the same RLS
// transaction as its projection. Replays repair an absent derived intent but
// never replace changed coordinates or make the command claimable by an agent.
func (s *Store) EnsureEventKeyPreparationTx(ctx context.Context, tx pgx.Tx, command EventKeyPreparationCommand) error {
	if s == nil || tx == nil {
		return fmt.Errorf("store: event key preparation requires a store and transaction")
	}
	if err := command.Validate(); err != nil {
		return err
	}
	command.RequestedAt = command.RequestedAt.UTC()
	payload, err := json.Marshal(command)
	if err != nil {
		return fmt.Errorf("store: encode event key preparation: %w", err)
	}
	tenantID, keyID := command.Ref.TenantID, command.Ref.ID
	outboxKey := EventKeyPreparationOutboxKey(keyID)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"event-key-preparation-outbox\x1f"+tenantID+"\x1f"+keyID); err != nil {
		return fmt.Errorf("store: lock event key preparation: %w", err)
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO outbox (tenant_id, destination, effect_lane, payload, idempotency_key, required_agent_role)
		 SELECT $1, $2, $3, $4, $5, 'control_plane'
		 WHERE NOT EXISTS (SELECT 1 FROM outbox WHERE tenant_id = $1 AND idempotency_key = $5)`,
		tenantID, EventKeyPreparationDestination, EventKeyPreparationEffectLane, payload, outboxKey)
	if err != nil {
		return fmt.Errorf("store: enqueue event key preparation: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var destination, lane, role, agent string
	var existing []byte
	if err := tx.QueryRow(ctx,
		`SELECT destination, COALESCE(NULLIF(effect_lane, ''), destination), payload, required_agent_role, COALESCE(required_agent_id::text, '')
		 FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2 ORDER BY id LIMIT 1`,
		tenantID, outboxKey).Scan(&destination, &lane, &existing, &role, &agent); err != nil {
		return fmt.Errorf("store: load event key preparation replay: %w", err)
	}
	if destination != EventKeyPreparationDestination || lane != EventKeyPreparationEffectLane ||
		role != "control_plane" || agent != "" || !bytes.Equal(existing, payload) {
		return fmt.Errorf("%w: event key preparation command differs", ErrIdempotencyConflict)
	}
	return nil
}
