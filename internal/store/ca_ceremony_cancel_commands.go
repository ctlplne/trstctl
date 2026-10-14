// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

// CACeremonyCancelCommand is independent authority, retained across a read-model
// rebuild. The pending row holds the exact source event; the completed row is an
// opaque terminal fence with no actor or reason.
type CACeremonyCancelCommand struct {
	TenantID, CeremonyID string
	Event                events.Event
	Status               string
}

const caCeremonyCancelColumns = `tenant_id::text, ceremony_id::text, event_id,
    event_time, event_actor, event_payload, payload_sha256, status`

func scanCACeremonyCancelCommand(row pgx.Row) (CACeremonyCancelCommand, error) {
	var c CACeremonyCancelCommand
	var actor, payload []byte
	var digest *string
	if err := row.Scan(&c.TenantID, &c.CeremonyID, &c.Event.ID, &c.Event.Time,
		&actor, &payload, &digest, &c.Status); err != nil {
		return c, err
	}
	c.Event.TenantID = c.TenantID
	c.Event.Type = "ca.ceremony.cancelled"
	c.Event.SchemaVersion = events.DefaultSchemaVersion
	c.Event.Data = payload
	if len(actor) != 0 {
		var a events.Actor
		if err := json.Unmarshal(actor, &a); err != nil {
			return c, fmt.Errorf("store: decode CA ceremony cancel actor: %w", err)
		}
		c.Event.Actor = &a
	}
	switch c.Status {
	case "pending":
		if digest == nil || len(payload) == 0 || crypto.SHA256Hex(payload) != *digest {
			return c, errors.New("store: CA ceremony cancel command payload drifted")
		}
	case "completed":
		if len(payload) != 0 || len(actor) != 0 || digest != nil {
			return c, errors.New("store: completed CA ceremony cancel retained payload")
		}
	default:
		return c, errors.New("store: unsupported CA ceremony cancel command state")
	}
	return c, nil
}

// ClaimCACeremonyCancelCommand is the pre-append fence. Locking the ceremony
// row serializes the claim with an approval or signing transaction already in
// flight; subsequent admissions must consult the independent command row.
func (s *Store) ClaimCACeremonyCancelCommand(ctx context.Context, candidate CACeremonyCancelCommand) (CACeremonyCancelCommand, bool, error) {
	var canonical CACeremonyCancelCommand
	var created bool
	if candidate.TenantID == "" || candidate.CeremonyID == "" ||
		candidate.Event.ID == "" || candidate.Event.TenantID != candidate.TenantID ||
		candidate.Event.Type != "ca.ceremony.cancelled" ||
		candidate.Event.SchemaVersion != events.DefaultSchemaVersion ||
		candidate.Event.Time.IsZero() || len(candidate.Event.Data) == 0 ||
		!candidate.Event.Time.Equal(candidate.Event.Time.UTC().Truncate(time.Microsecond)) {
		return canonical, false, errors.New("store: incomplete CA ceremony cancel command")
	}
	var actor []byte
	if candidate.Event.Actor != nil {
		var err error
		actor, err = json.Marshal(candidate.Event.Actor)
		if err != nil {
			return canonical, false, err
		}
	}
	err := s.WithPrivacyRecoveryBarrier(ctx, candidate.TenantID,
		"CA ceremony cancellation privacy barrier", func(barrierCtx context.Context) error {
			return s.WithTenant(barrierCtx, candidate.TenantID, func(tx pgx.Tx) error {
				if err := lockUpsertArbiterTx(barrierCtx, tx,
					"ca_ceremony_cancel_commands", candidate.TenantID, candidate.CeremonyID); err != nil {
					return err
				}
				if err := lockUpsertArbiterTx(barrierCtx, tx,
					"ca_ceremony_cancel_commands:event", candidate.TenantID, candidate.Event.ID); err != nil {
					return err
				}
				var existing string
				err := tx.QueryRow(barrierCtx, `SELECT event_id FROM ca_ceremony_cancel_commands
					WHERE tenant_id=$1 AND ceremony_id=$2 FOR UPDATE`, candidate.TenantID, candidate.CeremonyID).Scan(&existing)
				if err != nil && !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
				var ceremonyStatus string
				if err := tx.QueryRow(barrierCtx, `SELECT status FROM ca_key_ceremonies
					WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, candidate.TenantID, candidate.CeremonyID).Scan(&ceremonyStatus); err != nil {
					return err
				}
				if ceremonyStatus != "pending" {
					return ErrKeyCeremonyNotPending
				}
				if existing != "" {
					canonical, err = scanCACeremonyCancelCommand(tx.QueryRow(barrierCtx,
						`SELECT `+caCeremonyCancelColumns+` FROM ca_ceremony_cancel_commands
						 WHERE tenant_id=$1 AND ceremony_id=$2 FOR UPDATE`, candidate.TenantID, candidate.CeremonyID))
					if err != nil {
						return err
					}
					if canonical.Status != "pending" || !bytes.Equal(canonical.Event.Data, candidate.Event.Data) ||
						!reflect.DeepEqual(canonical.Event.Actor, candidate.Event.Actor) {
						return ErrIdempotencyConflict
					}
					return nil
				}
				var eventClaimed bool
				if err := tx.QueryRow(barrierCtx, `SELECT EXISTS (SELECT 1 FROM ca_ceremony_cancel_commands
					WHERE tenant_id=$1 AND event_id=$2)`, candidate.TenantID, candidate.Event.ID).Scan(&eventClaimed); err != nil {
					return err
				}
				if eventClaimed {
					return ErrIdempotencyConflict
				}
				_, err = tx.Exec(barrierCtx, `INSERT INTO ca_ceremony_cancel_commands
					(tenant_id, ceremony_id, event_id, event_time, event_actor, event_payload, payload_sha256)
					VALUES ($1,$2,$3,$4,$5,$6,$7)`, candidate.TenantID, candidate.CeremonyID,
					candidate.Event.ID, candidate.Event.Time, actor, candidate.Event.Data,
					crypto.SHA256Hex(candidate.Event.Data))
				if err != nil {
					return err
				}
				canonical = candidate
				canonical.Status = "pending"
				created = true
				return nil
			})
		})
	return canonical, created, err
}

func (s *Store) LockCACeremonyCancelCommandTx(ctx context.Context, tx pgx.Tx, tenantID, ceremonyID string) (CACeremonyCancelCommand, error) {
	return scanCACeremonyCancelCommand(tx.QueryRow(ctx,
		`SELECT `+caCeremonyCancelColumns+` FROM ca_ceremony_cancel_commands
		 WHERE tenant_id=$1 AND ceremony_id=$2 FOR UPDATE`, tenantID, ceremonyID))
}

func (s *Store) CACeremonyCancelCommandExistsTx(ctx context.Context, tx pgx.Tx, tenantID, ceremonyID string) (bool, error) {
	var found bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ca_ceremony_cancel_commands
		WHERE tenant_id=$1 AND ceremony_id=$2)`, tenantID, ceremonyID).Scan(&found)
	return found, err
}

func (s *Store) CACeremonyCancelCommandStatus(ctx context.Context, tenantID, ceremonyID string) (string, error) {
	var status string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status FROM ca_ceremony_cancel_commands
			WHERE tenant_id=$1 AND ceremony_id=$2`, tenantID, ceremonyID).Scan(&status)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return status, err
}

// CompleteCACeremonyCancelCommandTx binds projection to the first event and
// scrubs transient personal data in the same SQL transaction as terminal state.
func (s *Store) CompleteCACeremonyCancelCommandTx(ctx context.Context, tx pgx.Tx, tenantID, ceremonyID string, event events.Event) error {
	c, err := s.LockCACeremonyCancelCommandTx(ctx, tx, tenantID, ceremonyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	} // legacy event
	if err != nil {
		return err
	}
	if c.Event.ID != event.ID {
		return errors.New("store: CA ceremony cancel event conflicts with first command")
	}
	if c.Status == "completed" {
		return nil
	}
	if !c.Event.Time.Equal(event.Time) || !bytes.Equal(c.Event.Data, event.Data) ||
		!reflect.DeepEqual(c.Event.Actor, event.Actor) || c.Event.Type != event.Type ||
		c.Event.SchemaVersion != event.SchemaVersion {
		return errors.New("store: CA ceremony cancel event differs from first command")
	}
	_, err = tx.Exec(ctx, `UPDATE ca_ceremony_cancel_commands
		SET status='completed', event_actor=NULL, event_payload=NULL, payload_sha256=NULL, updated_at=now()
		WHERE tenant_id=$1 AND ceremony_id=$2 AND event_id=$3`, tenantID, ceremonyID, event.ID)
	return err
}

func (s *Store) ListPendingCACeremonyCancels(ctx context.Context, tenantID string, limit int) ([]CACeremonyCancelCommand, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	var out []CACeremonyCancelCommand
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+caCeremonyCancelColumns+` FROM ca_ceremony_cancel_commands
			WHERE tenant_id=$1 AND status='pending' ORDER BY created_at, ceremony_id LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanCACeremonyCancelCommand(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}
