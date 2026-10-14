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

// TenantMemberOffboardCommand is independent admission authority. Pending rows
// preserve one exact source event; completed rows retain only an opaque subject
// reference and sequence so late replay cannot revive a pre-offboard bearer.
type TenantMemberOffboardCommand struct {
	TenantID          string
	SubjectRef        string
	Event             events.Event
	LastEventSequence int64
	Status            string
}

var ErrTenantMemberOffboarded = errors.New("store: tenant member is offboarded")

const tenantMemberOffboardCommandColumns = `tenant_id::text, subject_ref, event_id::text,
    event_time, event_schema_version, event_actor, event_payload, payload_sha256,
    last_event_sequence, status`

func scanTenantMemberOffboardCommand(row pgx.Row) (TenantMemberOffboardCommand, error) {
	var c TenantMemberOffboardCommand
	var actor, payload []byte
	var digest *string
	var sequence int64
	if err := row.Scan(&c.TenantID, &c.SubjectRef, &c.Event.ID, &c.Event.Time,
		&c.Event.SchemaVersion, &actor, &payload, &digest, &sequence, &c.Status); err != nil {
		return c, err
	}
	c.Event.TenantID = c.TenantID
	c.Event.Type = "tenant.member.offboarded"
	c.Event.Data = payload
	c.LastEventSequence = sequence
	if len(actor) > 0 {
		var a events.Actor
		if err := json.Unmarshal(actor, &a); err != nil {
			return c, fmt.Errorf("store: decode member offboard actor: %w", err)
		}
		c.Event.Actor = &a
	}
	switch c.Status {
	case "pending":
		if digest == nil || len(payload) == 0 || crypto.SHA256Hex(payload) != *digest {
			return c, errors.New("store: member offboard command payload drifted")
		}
	case "completed":
		if len(payload) != 0 || len(actor) != 0 || digest != nil || sequence <= 0 {
			return c, errors.New("store: completed member offboard command retained payload")
		}
	default:
		return c, errors.New("store: unsupported member offboard command state")
	}
	return c, nil
}

// LockTenantMemberSubjectTx is shared by claims and authority-creating event
// appends. Holding this transaction lock through source append gives an exact
// source order across replicas without a second lock-pool connection.
func (s *Store) LockTenantMemberSubjectTx(ctx context.Context, tx pgx.Tx, tenantID, subject string) error {
	if tenantID == "" || subject == "" {
		return errors.New("store: tenant member subject is required")
	}
	return s.LockTenantMemberSubjectRefTx(ctx, tx, tenantID, privacy.SubjectRef(tenantID, subject))
}

func (s *Store) LockTenantMemberSubjectRefTx(ctx context.Context, tx pgx.Tx, tenantID, subjectRef string) error {
	if tenantID == "" || subjectRef == "" {
		return errors.New("store: tenant member subject ref is required")
	}
	return lockUpsertArbiterTx(ctx, tx, "tenant_member_offboard_commands", tenantID, subjectRef)
}

// CheckTenantMemberBearerAdmissionTx denies a pending offboard and a completed
// offboard whose member has not been explicitly reactivated. Unmanaged machine
// principals remain eligible when no member or command exists.
func (s *Store) CheckTenantMemberBearerAdmissionTx(ctx context.Context, tx pgx.Tx, tenantID, subject string) error {
	var pendingOrOffboarded bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM tenant_member_offboard_commands AS c
		LEFT JOIN tenant_members AS m ON m.tenant_id = c.tenant_id AND m.subject_ref = c.subject_ref
		WHERE c.tenant_id = $1 AND c.subject_ref = $2
		  AND (c.status = 'pending' OR m.status IS DISTINCT FROM 'active')
	) OR EXISTS (
		SELECT 1 FROM tenant_members AS m
		WHERE m.tenant_id = $1 AND m.subject_ref = $2 AND m.status = 'offboarded'
	)`, tenantID, privacy.SubjectRef(tenantID, subject)).Scan(&pendingOrOffboarded)
	if err != nil {
		return err
	}
	if pendingOrOffboarded {
		return ErrTenantMemberOffboarded
	}
	return nil
}

// A new, explicit member upsert can rehire after completion, but may not pass
// a pending offboard whose event has not yet reached the read model.
func (s *Store) CheckTenantMemberUpsertAdmissionTx(ctx context.Context, tx pgx.Tx, tenantID, subject string) error {
	var pending bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM tenant_member_offboard_commands
		 WHERE tenant_id = $1 AND subject_ref = $2 AND status = 'pending')`,
		tenantID, privacy.SubjectRef(tenantID, subject)).Scan(&pending); err != nil {
		return err
	}
	if pending {
		return ErrTenantMemberOffboarded
	}
	return nil
}

func (s *Store) CheckTenantMemberCurrentlyActiveTx(ctx context.Context, tx pgx.Tx, tenantID, subject string) error {
	var active bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenant_members
		WHERE tenant_id = $1 AND subject_ref = $2 AND status = 'active')`,
		tenantID, privacy.SubjectRef(tenantID, subject)).Scan(&active); err != nil {
		return err
	}
	if !active {
		return ErrTenantMemberOffboarded
	}
	return nil
}

// ClaimTenantMemberOffboardCommand commits denial before attempting a source
// append. makeEvent receives the token count observed under the same subject
// lock; retries reuse the first event and cannot manufacture a second command.
func (s *Store) ClaimTenantMemberOffboardCommand(ctx context.Context, tenantID, subject string, makeEvent func(int) (events.Event, error)) (TenantMemberOffboardCommand, int, bool, error) {
	var canonical TenantMemberOffboardCommand
	var count int
	var created bool
	if tenantID == "" || subject == "" || makeEvent == nil {
		return canonical, 0, false, errors.New("store: incomplete member offboard command")
	}
	err := s.WithPrivacyRecoveryBarrier(ctx, tenantID, "member offboard command privacy barrier", func(barrierCtx context.Context) error {
		return s.WithTenant(barrierCtx, tenantID, func(tx pgx.Tx) error {
			if err := s.LockTenantMemberSubjectTx(barrierCtx, tx, tenantID, subject); err != nil {
				return err
			}
			ref := privacy.SubjectRef(tenantID, subject)
			var err error
			canonical, err = scanTenantMemberOffboardCommand(tx.QueryRow(barrierCtx,
				`SELECT `+tenantMemberOffboardCommandColumns+` FROM tenant_member_offboard_commands
				 WHERE tenant_id = $1 AND subject_ref = $2 FOR UPDATE`, tenantID, ref))
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if err == nil {
				if canonical.Status == "pending" {
					return nil
				}
				var active, pendingRehire bool
				if err := tx.QueryRow(barrierCtx,
					`SELECT EXISTS (SELECT 1 FROM tenant_members WHERE tenant_id = $1 AND subject_ref = $2 AND status = 'active')`,
					tenantID, ref).Scan(&active); err != nil {
					return err
				}
				if err := tx.QueryRow(barrierCtx,
					`SELECT EXISTS (SELECT 1 FROM tenant_member_upsert_commands
					 WHERE tenant_id = $1 AND subject_ref = $2 AND status = 'pending')`,
					tenantID, ref).Scan(&pendingRehire); err != nil {
					return err
				}
				if !active && !pendingRehire {
					return nil
				}
			}
			if err := tx.QueryRow(barrierCtx,
				`SELECT count(*) FROM api_tokens WHERE tenant_id = $1 AND subject_ref = $2 AND revoked_at IS NULL`,
				tenantID, ref).Scan(&count); err != nil {
				return err
			}
			ev, err := makeEvent(count)
			if err != nil {
				return err
			}
			if ev.ID == "" || ev.TenantID != tenantID || ev.Type != "tenant.member.offboarded" ||
				ev.Time.IsZero() || len(ev.Data) == 0 || ev.SchemaVersion < 1 ||
				!ev.Time.Equal(ev.Time.UTC().Truncate(time.Microsecond)) {
				return errors.New("store: incomplete member offboard event")
			}
			var actor []byte
			if ev.Actor != nil {
				actor, err = json.Marshal(ev.Actor)
				if err != nil {
					return err
				}
			}
			if canonical.Status == "completed" {
				_, err = tx.Exec(barrierCtx, `UPDATE tenant_member_offboard_commands
				 SET event_id = $3, event_time = $4, event_schema_version = $5, event_actor = $6,
				     event_payload = $7, payload_sha256 = $8, status = 'pending', updated_at = now()
				 WHERE tenant_id = $1 AND subject_ref = $2`, tenantID, ref, ev.ID, ev.Time,
					ev.SchemaVersion, actor, ev.Data, crypto.SHA256Hex(ev.Data))
			} else {
				_, err = tx.Exec(barrierCtx, `INSERT INTO tenant_member_offboard_commands
				 (tenant_id, subject_ref, event_id, event_time, event_schema_version, event_actor, event_payload, payload_sha256)
				 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, tenantID, ref, ev.ID, ev.Time,
					ev.SchemaVersion, actor, ev.Data, crypto.SHA256Hex(ev.Data))
			}
			if err != nil {
				return err
			}
			created = true
			canonical, err = scanTenantMemberOffboardCommand(tx.QueryRow(barrierCtx,
				`SELECT `+tenantMemberOffboardCommandColumns+` FROM tenant_member_offboard_commands
				 WHERE tenant_id = $1 AND subject_ref = $2 FOR UPDATE`, tenantID, ref))
			return err
		})
	})
	return canonical, count, created, err
}

// CompleteTenantMemberOffboardCommandTx verifies the canonical event and
// removes pending PII in the same transaction as member/token projections.
func (s *Store) CompleteTenantMemberOffboardCommandTx(ctx context.Context, tx pgx.Tx, tenantID, subject string, event events.Event) error {
	ref := privacy.SubjectRef(tenantID, subject)
	// Privacy erasure may have pseudonymized a pending event's subject. Its
	// independently durable command keeps the original opaque admission key.
	// Historical source events may have non-UUID IDs. Skip the command lookup
	// for those events; UUID commands still use the indexed exact-ID lookup.
	var commandRef string
	var err error
	if eventID, parseErr := uuid.Parse(event.ID); parseErr == nil {
		err = tx.QueryRow(ctx, `SELECT subject_ref FROM tenant_member_offboard_commands
			WHERE tenant_id = $1 AND event_id = $2`, tenantID, eventID).Scan(&commandRef)
	} else {
		err = pgx.ErrNoRows
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil {
		ref = commandRef
	}
	if err := s.LockTenantMemberSubjectRefTx(ctx, tx, tenantID, ref); err != nil {
		return err
	}
	c, err := scanTenantMemberOffboardCommand(tx.QueryRow(ctx,
		`SELECT `+tenantMemberOffboardCommandColumns+` FROM tenant_member_offboard_commands
		 WHERE tenant_id = $1 AND subject_ref = $2 FOR UPDATE`, tenantID, ref))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	} // Legacy source event.
	if err != nil {
		return err
	}
	if c.Event.ID != event.ID {
		return nil
	} // Historical replay; latest claim wins.
	if c.Status == "completed" {
		return nil
	}
	if !c.Event.Time.Equal(event.Time) || !bytes.Equal(c.Event.Data, event.Data) ||
		!reflect.DeepEqual(c.Event.Actor, event.Actor) || c.Event.Type != event.Type ||
		c.Event.SchemaVersion != event.SchemaVersion || event.Sequence == 0 || event.Sequence > 1<<63-1 {
		return errors.New("store: member offboard event differs from durable command")
	}
	_, err = tx.Exec(ctx, `UPDATE tenant_member_offboard_commands
	 SET status = 'completed', event_actor = NULL, event_payload = NULL,
	     payload_sha256 = NULL, last_event_sequence = $3, updated_at = now()
	 WHERE tenant_id = $1 AND subject_ref = $2 AND event_id = $4`,
		tenantID, ref, int64(event.Sequence), event.ID)
	return err
}

func (s *Store) LockTenantMemberOffboardCommandTx(ctx context.Context, tx pgx.Tx, tenantID, subjectRef string) (TenantMemberOffboardCommand, error) {
	return scanTenantMemberOffboardCommand(tx.QueryRow(ctx,
		`SELECT `+tenantMemberOffboardCommandColumns+` FROM tenant_member_offboard_commands
		 WHERE tenant_id = $1 AND subject_ref = $2 FOR UPDATE`, tenantID, subjectRef))
}

func (s *Store) ListPendingTenantMemberOffboardCommands(ctx context.Context, tenantID string, limit int) ([]TenantMemberOffboardCommand, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	var out []TenantMemberOffboardCommand
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+tenantMemberOffboardCommandColumns+` FROM tenant_member_offboard_commands
		 WHERE tenant_id = $1 AND status = 'pending' ORDER BY updated_at, subject_ref LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanTenantMemberOffboardCommand(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// MemberOffboardStatus is a fail-closed admission lookup for cookies and
// already-projected bearers. It is RLS-scoped and distinguishes read failure.
func (s *Store) MemberOffboardStatus(ctx context.Context, tenantID, subject string) (bool, error) {
	var denied bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (
		 SELECT 1 FROM tenant_member_offboard_commands AS c
		 LEFT JOIN tenant_members AS m ON m.tenant_id = c.tenant_id AND m.subject_ref = c.subject_ref
		 WHERE c.tenant_id = $1 AND c.subject_ref = $2
		   AND (c.status = 'pending' OR m.status IS DISTINCT FROM 'active'))
		 OR EXISTS (SELECT 1 FROM tenant_members AS m
		            WHERE m.tenant_id = $1 AND m.subject_ref = $2 AND m.status = 'offboarded')`,
			tenantID, privacy.SubjectRef(tenantID, subject)).Scan(&denied)
	})
	return denied, err
}
