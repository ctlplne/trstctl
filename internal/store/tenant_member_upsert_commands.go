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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
)

// TenantMemberUpsertCommand is a disposable admission fence, not the state
// source. A pending command removes cookie grants while its exact event waits
// for projection. A later offboard may supersede an unappended command.
type TenantMemberUpsertCommand struct {
	TenantID          string
	SubjectRef        string
	OffboardEventID   *string
	Event             events.Event
	LastEventSequence int64
	Status            string
}

const tenantMemberUpsertCommandColumns = `tenant_id::text, subject_ref, event_id::text,
    event_time, event_schema_version, offboard_event_id::text, event_actor,
    event_payload, payload_sha256, last_event_sequence, status`

func scanTenantMemberUpsertCommand(row pgx.Row) (TenantMemberUpsertCommand, error) {
	var c TenantMemberUpsertCommand
	var actor, payload []byte
	var digest *string
	if err := row.Scan(&c.TenantID, &c.SubjectRef, &c.Event.ID, &c.Event.Time,
		&c.Event.SchemaVersion, &c.OffboardEventID, &actor, &payload, &digest,
		&c.LastEventSequence, &c.Status); err != nil {
		return c, err
	}
	c.Event.TenantID = c.TenantID
	c.Event.Type = "tenant.member.upserted"
	c.Event.Data = payload
	if len(actor) > 0 {
		var a events.Actor
		if err := json.Unmarshal(actor, &a); err != nil {
			return c, fmt.Errorf("store: decode member upsert actor: %w", err)
		}
		c.Event.Actor = &a
	}
	switch c.Status {
	case "pending":
		if digest == nil || len(payload) == 0 || crypto.SHA256Hex(payload) != *digest || c.LastEventSequence != 0 {
			return c, errors.New("store: member upsert command payload drifted")
		}
	case "completed":
		if len(payload) != 0 || len(actor) != 0 || digest != nil || c.LastEventSequence <= 0 {
			return c, errors.New("store: completed member upsert command retained payload")
		}
	case "superseded":
		if len(payload) != 0 || len(actor) != 0 || digest != nil || c.LastEventSequence != 0 {
			return c, errors.New("store: superseded member upsert command retained payload")
		}
	default:
		return c, errors.New("store: unsupported member upsert command state")
	}
	return c, nil
}

// ClaimTenantMemberUpsertCommand commits a tenant+subject first writer before
// publishing the source event. Retries reuse its exact event and cannot lift
// the pending restriction with a different set of roles.
func (s *Store) ClaimTenantMemberUpsertCommand(ctx context.Context, tenantID, subject string, ev events.Event, requireActive bool) (TenantMemberUpsertCommand, bool, error) {
	var canonical TenantMemberUpsertCommand
	var created bool
	if tenantID == "" || subject == "" || ev.ID == "" || ev.TenantID != tenantID ||
		ev.Type != "tenant.member.upserted" || ev.SchemaVersion < 1 || len(ev.Data) == 0 ||
		ev.Time.IsZero() || !ev.Time.Equal(ev.Time.UTC().Truncate(time.Microsecond)) {
		return canonical, false, errors.New("store: incomplete member upsert command")
	}
	var payload struct {
		Subject string `json:"subject"`
	}
	if err := json.Unmarshal(ev.Data, &payload); err != nil || payload.Subject != subject {
		return canonical, false, errors.New("store: member upsert event subject differs from command")
	}
	err := s.WithPrivacyRecoveryBarrier(ctx, tenantID, "member upsert command privacy barrier", func(barrierCtx context.Context) error {
		return s.WithTenant(barrierCtx, tenantID, func(tx pgx.Tx) error {
			if err := s.LockTenantMemberSubjectTx(barrierCtx, tx, tenantID, subject); err != nil {
				return err
			}
			if err := s.CheckTenantMemberUpsertAdmissionTx(barrierCtx, tx, tenantID, subject); err != nil {
				return err
			}
			if requireActive {
				if err := s.CheckTenantMemberCurrentlyActiveTx(barrierCtx, tx, tenantID, subject); err != nil {
					return err
				}
			}
			ref := privacy.SubjectRef(tenantID, subject)
			var err error
			canonical, err = scanTenantMemberUpsertCommand(tx.QueryRow(barrierCtx,
				`SELECT `+tenantMemberUpsertCommandColumns+` FROM tenant_member_upsert_commands
				 WHERE tenant_id = $1 AND subject_ref = $2 FOR UPDATE`, tenantID, ref))
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if err == nil && canonical.Status == "pending" {
				if canonical.Event.SchemaVersion != ev.SchemaVersion ||
					!bytes.Equal(canonical.Event.Data, ev.Data) ||
					!reflect.DeepEqual(canonical.Event.Actor, ev.Actor) {
					return ErrIdempotencyConflict
				}
				return nil
			}
			var offboardEventID *string
			if err := tx.QueryRow(barrierCtx, `SELECT event_id::text FROM tenant_member_offboard_commands
				WHERE tenant_id = $1 AND subject_ref = $2`, tenantID, ref).Scan(&offboardEventID); err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			var actor []byte
			if ev.Actor != nil {
				actor, err = json.Marshal(ev.Actor)
				if err != nil {
					return err
				}
			}
			if canonical.Status != "" {
				_, err = tx.Exec(barrierCtx, `UPDATE tenant_member_upsert_commands
				 SET event_id = $3, event_time = $4, event_schema_version = $5,
				     offboard_event_id = $6, event_actor = $7, event_payload = $8,
				     payload_sha256 = $9, last_event_sequence = 0, status = 'pending', updated_at = now()
				 WHERE tenant_id = $1 AND subject_ref = $2`, tenantID, ref, ev.ID, ev.Time,
					ev.SchemaVersion, offboardEventID, actor, ev.Data, crypto.SHA256Hex(ev.Data))
			} else {
				_, err = tx.Exec(barrierCtx, `INSERT INTO tenant_member_upsert_commands
				 (tenant_id, subject_ref, event_id, event_time, event_schema_version,
				  offboard_event_id, event_actor, event_payload, payload_sha256)
				 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, tenantID, ref, ev.ID, ev.Time,
					ev.SchemaVersion, offboardEventID, actor, ev.Data, crypto.SHA256Hex(ev.Data))
			}
			if err != nil {
				return err
			}
			created = true
			canonical, err = scanTenantMemberUpsertCommand(tx.QueryRow(barrierCtx,
				`SELECT `+tenantMemberUpsertCommandColumns+` FROM tenant_member_upsert_commands
				 WHERE tenant_id = $1 AND subject_ref = $2 FOR UPDATE`, tenantID, ref))
			return err
		})
	})
	return canonical, created, err
}

func (s *Store) LockTenantMemberUpsertCommandTx(ctx context.Context, tx pgx.Tx, tenantID, subjectRef string) (TenantMemberUpsertCommand, error) {
	return scanTenantMemberUpsertCommand(tx.QueryRow(ctx,
		`SELECT `+tenantMemberUpsertCommandColumns+` FROM tenant_member_upsert_commands
		 WHERE tenant_id = $1 AND subject_ref = $2 FOR UPDATE`, tenantID, subjectRef))
}

// MemberUpsertOffboardChangedTx compares the offboard generation observed at
// claim with the current one. An unappended role event may not rehire after a
// newer offboard claim, even if that offboard event is still unprojected.
func (s *Store) MemberUpsertOffboardChangedTx(ctx context.Context, tx pgx.Tx, c TenantMemberUpsertCommand) (bool, error) {
	var current *string
	err := tx.QueryRow(ctx, `SELECT event_id::text FROM tenant_member_offboard_commands
		WHERE tenant_id = $1 AND subject_ref = $2`, c.TenantID, c.SubjectRef).Scan(&current)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	if err != nil {
		current = nil
	}
	if current == nil || c.OffboardEventID == nil {
		return current != nil || c.OffboardEventID != nil, nil
	}
	return *current != *c.OffboardEventID, nil
}

func (s *Store) SupersedeTenantMemberUpsertCommandTx(ctx context.Context, tx pgx.Tx, c TenantMemberUpsertCommand) error {
	tag, err := tx.Exec(ctx, `UPDATE tenant_member_upsert_commands
	 SET status = 'superseded', event_actor = NULL, event_payload = NULL,
	     payload_sha256 = NULL, updated_at = now()
	 WHERE tenant_id = $1 AND subject_ref = $2 AND event_id = $3 AND status = 'pending'`,
		c.TenantID, c.SubjectRef, c.Event.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("store: member upsert supersession lost its first writer")
	}
	return nil
}

// CompleteTenantMemberUpsertCommandTx scrubs pending personal data in the
// projection transaction. Legacy source events have no command and still replay.
func (s *Store) CompleteTenantMemberUpsertCommandTx(ctx context.Context, tx pgx.Tx, tenantID, subject string, event events.Event) error {
	// Legacy source events can carry non-UUID IDs. The command table only
	// accepts UUID event IDs, so those events have no command to complete.
	if _, err := uuid.Parse(event.ID); err != nil {
		return nil
	}
	var commandRef string
	err := tx.QueryRow(ctx, `SELECT subject_ref FROM tenant_member_upsert_commands
		WHERE tenant_id = $1 AND event_id = $2`, tenantID, event.ID).Scan(&commandRef)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	ref := commandRef
	if err := s.LockTenantMemberSubjectRefTx(ctx, tx, tenantID, ref); err != nil {
		return err
	}
	c, err := s.LockTenantMemberUpsertCommandTx(ctx, tx, tenantID, ref)
	if err != nil {
		return err
	}
	if c.Event.ID != event.ID || c.Status == "completed" {
		return nil
	}
	if c.Status != "pending" || !c.Event.Time.Equal(event.Time) ||
		!bytes.Equal(c.Event.Data, event.Data) || !reflect.DeepEqual(c.Event.Actor, event.Actor) ||
		c.Event.Type != event.Type || c.Event.SchemaVersion != event.SchemaVersion ||
		event.Sequence == 0 || event.Sequence > 1<<63-1 {
		return errors.New("store: member upsert event differs from durable command")
	}
	_, err = tx.Exec(ctx, `UPDATE tenant_member_upsert_commands
	 SET status = 'completed', event_actor = NULL, event_payload = NULL,
	     payload_sha256 = NULL, last_event_sequence = $3, updated_at = now()
	 WHERE tenant_id = $1 AND subject_ref = $2 AND event_id = $4`, tenantID, ref, int64(event.Sequence), event.ID)
	return err
}

func (s *Store) ListPendingTenantMemberUpsertCommands(ctx context.Context, tenantID string, limit int) ([]TenantMemberUpsertCommand, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	var out []TenantMemberUpsertCommand
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+tenantMemberUpsertCommandColumns+` FROM tenant_member_upsert_commands
		 WHERE tenant_id = $1 AND status = 'pending' ORDER BY updated_at, subject_ref LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanTenantMemberUpsertCommand(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// MemberSessionAuthority is a single RLS snapshot of projected roles and the
// pending command fence. A failed read is never interpreted as sign-in roles.
func (s *Store) MemberSessionAuthority(ctx context.Context, tenantID, subject string) ([]string, string, bool, bool, error) {
	var roles []string
	var status *string
	var pending bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT m.roles, m.status,
		 EXISTS (SELECT 1 FROM tenant_member_upsert_commands AS c
		         WHERE c.tenant_id = $1 AND c.subject_ref = $3 AND c.status = 'pending')
		 FROM (SELECT 1) AS seed
		 LEFT JOIN LATERAL (SELECT roles, status FROM tenant_members
		                    WHERE tenant_id = $1 AND subject = $2) AS m ON true`,
			tenantID, subject, privacy.SubjectRef(tenantID, subject)).Scan(&roles, &status, &pending)
	})
	if err != nil {
		return nil, "", false, false, err
	}
	if status == nil {
		return nil, "", false, pending, nil
	}
	return roles, *status, true, pending, nil
}
