// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

// IdentityTerminalCommand is the independent admission fence for one identity.
// The pending record retains the exact event until the read model commits it.
type IdentityTerminalCommand struct {
	IdentityID, RequestBinding, TargetState, Status string
	Event                                           events.Event
}

const identityTerminalColumns = `tenant_id::text,identity_id::text,event_id::text,
	event_type,event_time,event_schema_version,event_payload,payload_sha256,
	request_binding,target_state,status,projected_sequence`

func scanIdentityTerminalCommand(row pgx.Row) (IdentityTerminalCommand, error) {
	var command IdentityTerminalCommand
	var payload []byte
	var digest *string
	var sequence *int64
	if err := row.Scan(&command.Event.TenantID, &command.IdentityID, &command.Event.ID,
		&command.Event.Type, &command.Event.Time, &command.Event.SchemaVersion,
		&payload, &digest, &command.RequestBinding, &command.TargetState,
		&command.Status, &sequence); err != nil {
		return command, err
	}
	command.Event.Data = payload
	switch command.Status {
	case "pending":
		if digest == nil || len(payload) == 0 || sequence != nil || crypto.SHA256Hex(payload) != *digest {
			return command, errors.New("store: pending identity terminal command drifted")
		}
	case "completed":
		if digest != nil || len(payload) != 0 || sequence == nil || *sequence <= 0 {
			return command, errors.New("store: completed identity terminal command retained payload")
		}
		command.Event.Sequence = uint64(*sequence)
	default:
		return command, errors.New("store: invalid identity terminal command status")
	}
	return command, nil
}

func validateIdentityTerminalCommand(command IdentityTerminalCommand) error {
	if command.Event.TenantID == "" || command.IdentityID == "" || command.Event.ID == "" ||
		len(command.RequestBinding) != 64 || len(command.Event.Data) == 0 ||
		command.Event.Time.IsZero() || !command.Event.Time.Equal(command.Event.Time.UTC().Truncate(time.Microsecond)) ||
		command.Event.SchemaVersion <= 0 || command.Event.Actor != nil {
		return errors.New("store: incomplete identity terminal command")
	}
	for _, id := range []string{command.Event.TenantID, command.IdentityID, command.Event.ID} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed.String() != id {
			return errors.New("store: identity terminal command needs canonical UUIDs")
		}
	}
	if (command.TargetState == "revoked" && command.Event.Type != "identity.revoked") ||
		(command.TargetState == "retired" && command.Event.Type != "identity.retired") {
		return errors.New("store: identity terminal event and target differ")
	}
	var coordinates struct {
		IdentityID string `json:"identity_id"`
		To         string `json:"to"`
	}
	if err := json.Unmarshal(command.Event.Data, &coordinates); err != nil ||
		coordinates.IdentityID != command.IdentityID || coordinates.To != command.TargetState {
		return errors.New("store: identity terminal payload target differs")
	}
	return nil
}

// ClaimIdentityTerminalCommand commits before broker append. A retry can use
// the first pending event; a different request cannot displace it.
func (s *Store) ClaimIdentityTerminalCommand(ctx context.Context, candidate IdentityTerminalCommand) (IdentityTerminalCommand, error) {
	var canonical IdentityTerminalCommand
	if err := validateIdentityTerminalCommand(candidate); err != nil {
		return canonical, err
	}
	err := s.WithTenant(ctx, candidate.Event.TenantID, func(tx pgx.Tx) error {
		if err := lockUpsertArbiterTx(ctx, tx, "identity_terminal_commands",
			candidate.Event.TenantID, candidate.IdentityID); err != nil {
			return err
		}
		var err error
		canonical, err = scanIdentityTerminalCommand(tx.QueryRow(ctx,
			`SELECT `+identityTerminalColumns+` FROM identity_terminal_commands
			 WHERE tenant_id=$1 AND identity_id=$2 FOR UPDATE`,
			candidate.Event.TenantID, candidate.IdentityID))
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil {
			if canonical.Status == "pending" {
				if canonical.RequestBinding != candidate.RequestBinding ||
					canonical.TargetState != candidate.TargetState {
					return ErrIdempotencyConflict
				}
				return nil
			}
			// Revoked -> retired is the only legal second terminal edge. The
			// earlier event remains bound in identity_terminal_receipts.
			if canonical.TargetState != "revoked" || candidate.TargetState != "retired" {
				return ErrIdempotencyConflict
			}
			_, err = tx.Exec(ctx, `UPDATE identity_terminal_commands SET
				event_id=$3,event_type=$4,event_time=$5,event_schema_version=$6,
				event_payload=$7,payload_sha256=$8,request_binding=$9,
				target_state=$10,status='pending',projected_sequence=NULL,updated_at=now()
				WHERE tenant_id=$1 AND identity_id=$2`, candidate.Event.TenantID,
				candidate.IdentityID, candidate.Event.ID, candidate.Event.Type,
				candidate.Event.Time, candidate.Event.SchemaVersion, candidate.Event.Data,
				crypto.SHA256Hex(candidate.Event.Data), candidate.RequestBinding, candidate.TargetState)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO identity_terminal_commands
				(tenant_id,identity_id,event_id,event_type,event_time,event_schema_version,
				 event_payload,payload_sha256,request_binding,target_state)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, candidate.Event.TenantID,
				candidate.IdentityID, candidate.Event.ID, candidate.Event.Type,
				candidate.Event.Time, candidate.Event.SchemaVersion, candidate.Event.Data,
				crypto.SHA256Hex(candidate.Event.Data), candidate.RequestBinding, candidate.TargetState)
		}
		if err != nil {
			return err
		}
		canonical = candidate
		canonical.Status = "pending"
		return nil
	})
	return canonical, err
}

// IdentityTerminalState is a bounded, tenant-scoped admission read. A pending
// command is already authoritative even if the projected identity is stale.
func (s *Store) IdentityTerminalState(ctx context.Context, tenantID, identityID string) (state string, pending bool, found bool, err error) {
	err = s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var status string
		readErr := tx.QueryRow(ctx, `SELECT target_state,status FROM identity_terminal_commands
			WHERE tenant_id=$1 AND identity_id=$2`, tenantID, identityID).Scan(&state, &status)
		if errors.Is(readErr, pgx.ErrNoRows) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
		found, pending = true, status == "pending"
		return nil
	})
	return
}

// PendingIdentityTerminalTargets gives list/detail readers one indexed page
// read, so a retained terminal event cannot be shown as simply active.
func (s *Store) PendingIdentityTerminalTargets(ctx context.Context, tenantID string, identityIDs []string) (map[string]string, error) {
	result := make(map[string]string)
	if len(identityIDs) == 0 {
		return result, nil
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT identity_id::text,target_state FROM identity_terminal_commands
			WHERE tenant_id=$1 AND identity_id=ANY($2::uuid[]) AND status='pending'`, tenantID, identityIDs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, target string
			if err := rows.Scan(&id, &target); err != nil {
				return err
			}
			result[id] = target
		}
		return rows.Err()
	})
	return result, err
}

// IdentityTerminalCommandByIdentity reads the exact current command. Mutation
// retries use its retained event identity and reserved containment outbox ID.
func (s *Store) IdentityTerminalCommandByIdentity(ctx context.Context, tenantID, identityID string) (IdentityTerminalCommand, error) {
	var command IdentityTerminalCommand
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var readErr error
		command, readErr = scanIdentityTerminalCommand(tx.QueryRow(ctx,
			`SELECT `+identityTerminalColumns+` FROM identity_terminal_commands
			 WHERE tenant_id=$1 AND identity_id=$2`, tenantID, identityID))
		return readErr
	})
	return command, err
}

// CompleteIdentityTerminalCommandTx keeps the command and its immutable
// receipt in the same transaction as the lifecycle read-model update.
func (s *Store) CompleteIdentityTerminalCommandTx(ctx context.Context, tx pgx.Tx, identityID string, event events.Event) error {
	if event.Sequence == 0 || event.Sequence > math.MaxInt64 {
		return errors.New("store: terminal lifecycle event needs bounded source sequence")
	}
	command, err := scanIdentityTerminalCommand(tx.QueryRow(ctx,
		`SELECT `+identityTerminalColumns+` FROM identity_terminal_commands
		 WHERE tenant_id=$1 AND identity_id=$2 FOR UPDATE`, event.TenantID, identityID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // Historical lifecycle event predates this receiver.
	}
	if err != nil {
		return err
	}
	if command.Event.ID != event.ID {
		return nil // An older event cannot release a newer terminal command.
	}
	if command.Status == "completed" {
		if command.Event.Sequence != event.Sequence {
			return errors.New("store: terminal receipt sequence drifted")
		}
		return nil
	}
	if command.Event.Type != event.Type || command.Event.SchemaVersion != event.SchemaVersion ||
		!command.Event.Time.Equal(event.Time) || !bytes.Equal(command.Event.Data, event.Data) {
		return fmt.Errorf("%w: terminal lifecycle event differs from first command", ErrIdempotencyConflict)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO identity_terminal_receipts
		(tenant_id,event_id,identity_id,event_type,request_binding,payload_sha256,target_state,projected_sequence)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (tenant_id,event_id) DO NOTHING`, event.TenantID, event.ID, identityID,
		event.Type, command.RequestBinding, crypto.SHA256Hex(event.Data), command.TargetState,
		int64(event.Sequence)); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE identity_terminal_commands SET status='completed',
		event_payload=NULL,payload_sha256=NULL,projected_sequence=$3,updated_at=now()
		WHERE tenant_id=$1 AND identity_id=$2 AND event_id=$4 AND status='pending'`,
		event.TenantID, identityID, int64(event.Sequence), event.ID)
	return err
}

// PendingIdentityTerminalCommands is indexed and ordered for crash recovery.
func (s *Store) PendingIdentityTerminalCommands(ctx context.Context, tenantID, afterIdentity string, limit int) ([]IdentityTerminalCommand, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	var result []IdentityTerminalCommand
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+identityTerminalColumns+` FROM identity_terminal_commands
			WHERE tenant_id=$1 AND status='pending' AND identity_id > $2::uuid
			ORDER BY identity_id LIMIT $3`, tenantID, afterIdentity, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			command, scanErr := scanIdentityTerminalCommand(rows)
			if scanErr != nil {
				return scanErr
			}
			result = append(result, command)
		}
		return rows.Err()
	})
	return result, err
}

// PendingIdentityTerminalKeysSystem inventories opaque keys only. Recovery
// enters the customer's RLS scope before reading command bytes.
func (s *Store) PendingIdentityTerminalKeysSystem(ctx context.Context, afterTenant, afterIdentity string, limit int) ([][2]string, error) {
	if afterTenant == "" {
		afterTenant = "00000000-0000-0000-0000-000000000000"
	}
	if afterIdentity == "" {
		afterIdentity = "00000000-0000-0000-0000-000000000000"
	}
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	//trstctl:system-query — cross-tenant startup recovery needs pending tenant/identity keys before any tenant is known; this bounded system read returns no event payload, and each command is loaded in its tenant's RLS context.
	rows, err := s.SystemPool().Query(ctx, `SELECT tenant_id::text,identity_id::text FROM identity_terminal_commands
		WHERE status='pending' AND (tenant_id,identity_id) > ($1::uuid,$2::uuid)
		ORDER BY tenant_id,identity_id LIMIT $3`, afterTenant, afterIdentity, limit)
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
