// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

// ProviderSuspendCommand is independent denial authority. A pending command
// retains the exact source event for crash recovery; projection scrubs its
// personal data, while the opaque restriction remains until a resume event.
type ProviderSuspendCommand struct {
	Event  events.Event
	Status string
}

const providerSuspendColumns = `tenant_id::text, event_id, event_time, event_actor,
	event_payload, payload_sha256, status, projected_sequence`

func scanProviderSuspendCommand(row pgx.Row) (ProviderSuspendCommand, error) {
	var command ProviderSuspendCommand
	var actor, payload []byte
	var digest *string
	var sequence *int64
	if err := row.Scan(&command.Event.TenantID, &command.Event.ID,
		&command.Event.Time, &actor, &payload, &digest, &command.Status, &sequence); err != nil {
		return command, err
	}
	command.Event.Type = "provider.tenant_suspend"
	command.Event.SchemaVersion = events.DefaultSchemaVersion
	command.Event.Data = payload
	if len(actor) != 0 {
		var a events.Actor
		if err := json.Unmarshal(actor, &a); err != nil {
			return command, fmt.Errorf("store: decode Provider suspension actor: %w", err)
		}
		command.Event.Actor = &a
	}
	switch command.Status {
	case "pending":
		if digest == nil || sequence != nil || len(payload) == 0 || crypto.SHA256Hex(payload) != *digest {
			return command, errors.New("store: Provider suspension command payload drifted")
		}
	case "completed", "released":
		if len(payload) != 0 || len(actor) != 0 || digest != nil || sequence == nil || *sequence <= 0 {
			return command, errors.New("store: completed Provider suspension retained personal data")
		}
		command.Event.Sequence = uint64(*sequence)
	default:
		return command, errors.New("store: invalid Provider suspension command status")
	}
	return command, nil
}

// ClaimProviderSuspendCommand commits the denial while the caller holds the
// customer's exclusive service barrier. No event may be published first.
func (s *Store) ClaimProviderSuspendCommand(ctx context.Context, candidate events.Event) (ProviderSuspendCommand, error) {
	var canonical ProviderSuspendCommand
	if candidate.ID == "" || candidate.TenantID == "" ||
		candidate.Type != "provider.tenant_suspend" ||
		candidate.SchemaVersion != events.DefaultSchemaVersion ||
		candidate.Time.IsZero() || !candidate.Time.Equal(candidate.Time.UTC().Truncate(time.Microsecond)) ||
		len(candidate.Data) == 0 {
		return canonical, errors.New("store: incomplete Provider suspension command")
	}
	if parsed, err := uuid.Parse(candidate.ID); err != nil || parsed.String() != candidate.ID {
		return canonical, errors.New("store: Provider suspension event ID must be a canonical UUID")
	}
	var actor []byte
	if candidate.Actor != nil {
		var err error
		actor, err = json.Marshal(candidate.Actor)
		if err != nil {
			return canonical, err
		}
	}
	err := s.WithPrivacyRecoveryBarrier(ctx, candidate.TenantID,
		"Provider suspension privacy barrier", func(barrierCtx context.Context) error {
			return s.WithTenant(barrierCtx, candidate.TenantID, func(tx pgx.Tx) error {
				if err := lockUpsertArbiterTx(barrierCtx, tx,
					"provider_suspend_commands", candidate.TenantID, candidate.TenantID); err != nil {
					return err
				}
				// A retry first resolves its original row, including a released one.
				var err error
				canonical, err = scanProviderSuspendCommand(tx.QueryRow(barrierCtx,
					`SELECT `+providerSuspendColumns+` FROM provider_suspend_commands
					 WHERE tenant_id=$1 AND event_id=$2 FOR UPDATE`, candidate.TenantID, candidate.ID))
				if err == nil {
					return nil
				}
				if !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
				var active bool
				if err := tx.QueryRow(barrierCtx, `SELECT EXISTS (SELECT 1 FROM provider_suspend_commands
					WHERE tenant_id=$1 AND status IN ('pending','completed'))`, candidate.TenantID).Scan(&active); err != nil {
					return err
				}
				if active {
					return ErrIdempotencyConflict
				}
				_, err = tx.Exec(barrierCtx, `INSERT INTO provider_suspend_commands
					(tenant_id,event_id,event_time,event_actor,event_payload,payload_sha256)
					VALUES ($1,$2,$3,$4,$5,$6)`, candidate.TenantID, candidate.ID,
					candidate.Time, actor, candidate.Data, crypto.SHA256Hex(candidate.Data))
				if err != nil {
					return err
				}
				canonical = ProviderSuspendCommand{Event: candidate, Status: "pending"}
				return nil
			})
		})
	return canonical, err
}

// CompleteProviderSuspendCommandTx binds a projected suspension to its exact
// pre-append command and drops the transient actor and payload atomically.
func (s *Store) CompleteProviderSuspendCommandTx(ctx context.Context, tx pgx.Tx, event events.Event) error {
	if event.Sequence == 0 || event.Sequence > math.MaxInt64 {
		return errors.New("store: Provider suspension needs a bounded source sequence")
	}
	command, err := scanProviderSuspendCommand(tx.QueryRow(ctx,
		`SELECT `+providerSuspendColumns+` FROM provider_suspend_commands
		 WHERE tenant_id=$1 AND event_id=$2 FOR UPDATE`, event.TenantID, event.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // Historical Provider event predates this command receiver.
	}
	if err != nil {
		return err
	}
	if command.Status != "pending" {
		return nil
	}
	if command.Event.Type != event.Type || command.Event.SchemaVersion != event.SchemaVersion ||
		!command.Event.Time.Equal(event.Time) || !bytes.Equal(command.Event.Data, event.Data) ||
		!reflect.DeepEqual(command.Event.Actor, event.Actor) {
		return errors.New("store: Provider suspension event differs from first command")
	}
	_, err = tx.Exec(ctx, `UPDATE provider_suspend_commands SET status='completed',
		event_actor=NULL,event_payload=NULL,payload_sha256=NULL,
		projected_sequence=$3,updated_at=now()
		WHERE tenant_id=$1 AND event_id=$2 AND status='pending'`, event.TenantID, event.ID, int64(event.Sequence))
	return err
}

// ReleaseProviderSuspendCommandTx removes the denial only in the same SQL
// transaction that projects a later, authorized Provider resume event.
func (s *Store) ReleaseProviderSuspendCommandTx(ctx context.Context, tx pgx.Tx, tenantID, resumeEventID string, resumeSequence uint64) error {
	if resumeSequence == 0 || resumeSequence > math.MaxInt64 {
		return errors.New("store: Provider resume needs a bounded source sequence")
	}
	var eventID, status string
	var projectedSequence *int64
	err := tx.QueryRow(ctx, `SELECT event_id,status,projected_sequence FROM provider_suspend_commands
		WHERE tenant_id=$1 AND status IN ('pending','completed') FOR UPDATE`, tenantID).Scan(&eventID, &status, &projectedSequence)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if status != "completed" || projectedSequence == nil || *projectedSequence >= int64(resumeSequence) {
		// Ordered recovery may replay an older Resume while a newer suspension
		// command is pending or already completed. Source order, not wall time,
		// decides which suspension an authorized Resume can release.
		return nil
	}
	_, err = tx.Exec(ctx, `UPDATE provider_suspend_commands SET status='released',
		released_by_event_id=$3,updated_at=now()
		WHERE tenant_id=$1 AND event_id=$2 AND status='completed'`, tenantID, eventID, resumeEventID)
	return err
}

func ProviderSuspendCommandActiveTx(ctx context.Context, tx pgx.Tx, tenantID string) (bool, error) {
	var active bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM provider_suspend_commands
		WHERE tenant_id=$1 AND status IN ('pending','completed'))`, tenantID).Scan(&active)
	return active, err
}

// ProviderSuspendPending refuses a later destructive status command until the
// earlier suspension has a durable projected result in source order.
func (s *Store) ProviderSuspendPending(ctx context.Context, tenantID string) (bool, error) {
	var pending bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM provider_suspend_commands
			WHERE tenant_id=$1 AND status='pending')`, tenantID).Scan(&pending)
	})
	return pending, err
}

// PendingProviderSuspendKeysSystem returns only opaque tenant/event references;
// callers re-enter tenant RLS to load any personal recovery material.
func (s *Store) PendingProviderSuspendKeysSystem(ctx context.Context, afterTenant, afterEvent string, limit int) ([][2]string, error) {
	if afterTenant == "" {
		afterTenant = "00000000-0000-0000-0000-000000000000"
	}
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	//trstctl:system-query — startup inventory returns only tenant and event IDs, not command payloads.
	rows, err := s.SystemPool().Query(ctx, `SELECT tenant_id::text,event_id FROM provider_suspend_commands
		WHERE status='pending' AND (tenant_id,event_id) > ($1::uuid,$2)
		ORDER BY tenant_id,event_id LIMIT $3`, afterTenant, afterEvent, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys [][2]string
	for rows.Next() {
		var key [2]string
		if err := rows.Scan(&key[0], &key[1]); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *Store) ProviderSuspendCommand(ctx context.Context, tenantID, eventID string) (ProviderSuspendCommand, error) {
	var command ProviderSuspendCommand
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		command, err = scanProviderSuspendCommand(tx.QueryRow(ctx,
			`SELECT `+providerSuspendColumns+` FROM provider_suspend_commands
			 WHERE tenant_id=$1 AND event_id=$2`, tenantID, eventID))
		return err
	})
	return command, err
}
