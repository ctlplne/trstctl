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

	"trstctl.com/trstctl/internal/accessrules"
)

var ErrPAMCommandActionNotFound = errors.New("store: session command action not found")

// PAMCommandAction is a projection of a value-free gateway decision. Its source
// event ID comes from the envelope, not from an agent or the event's payload.
type PAMCommandAction struct {
	accessrules.Decision
	SourceEventID        string `json:"source_event_id"`
	ApprovalRequestID    string `json:"approval_request_id,omitempty"`
	ApprovalIntentDigest string `json:"approval_intent_digest,omitempty"`
}

// ApplyPAMCommandBlockedTx projects pam.command.blocked. An occurrence is
// immutable; its canonical source event owns retries beyond broker deduplication.
func (s *Store) ApplyPAMCommandBlockedTx(ctx context.Context, tx pgx.Tx, tenantID string, a PAMCommandAction) error {
	if err := accessrules.ValidateDecision(a.Decision); err != nil {
		return err
	}
	ids, err := json.Marshal(a.RuleIDs)
	if err != nil {
		return err
	}
	ops, err := json.Marshal(a.Operations)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO pam_command_actions (tenant_id,id,session_id,job_id,attempt,connection_id,ordinal,phase,protocol,rule_ids,operations,policy_digest,message_digest,status,reason,decided_at,observed_at,review_expires_at,source_event_id)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14,$15,$16,$17,$18,$19)
 ON CONFLICT(tenant_id,id) DO UPDATE SET status=EXCLUDED.status,reason=EXCLUDED.reason,decided_at=EXCLUDED.decided_at,source_event_id=EXCLUDED.source_event_id
 WHERE pam_command_actions.status='pending' AND EXCLUDED.status<>'pending'
 AND pam_command_actions.session_id=EXCLUDED.session_id AND pam_command_actions.job_id=EXCLUDED.job_id AND pam_command_actions.attempt=EXCLUDED.attempt
 AND pam_command_actions.connection_id=EXCLUDED.connection_id AND pam_command_actions.ordinal=EXCLUDED.ordinal
 AND pam_command_actions.phase=EXCLUDED.phase AND pam_command_actions.protocol=EXCLUDED.protocol AND pam_command_actions.rule_ids=EXCLUDED.rule_ids
 AND pam_command_actions.operations=EXCLUDED.operations AND pam_command_actions.policy_digest=EXCLUDED.policy_digest AND pam_command_actions.message_digest=EXCLUDED.message_digest
 AND pam_command_actions.observed_at=EXCLUDED.observed_at AND pam_command_actions.review_expires_at=EXCLUDED.review_expires_at`, tenantID, a.ID, a.SessionID, a.JobID, a.Attempt, a.ConnectionID, a.Ordinal, a.Phase, a.Protocol, ids, ops, a.PolicyDigest, a.MessageDigest, a.Status, a.Reason, a.DecidedAt.UTC(), a.ObservedAt.UTC(), a.ReviewExpiresAt, a.SourceEventID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		existing, err := s.GetPAMCommandActionForUpdateTx(ctx, tx, tenantID, a.ID)
		if err != nil {
			return err
		}
		if reflect.DeepEqual(existing.Decision, a.Decision) && existing.SourceEventID == a.SourceEventID {
			return nil
		}
		// Replaying the original hold must never regress a terminal occurrence.
		original := existing.Decision
		original.Status = a.Status
		original.Reason = a.Reason
		original.DecidedAt = a.DecidedAt
		if a.Status == accessrules.StatusPending && existing.Status != accessrules.StatusPending && reflect.DeepEqual(original, a.Decision) {
			return nil
		}
		return ErrIdempotencyConflict
	}
	return nil
}

const pamCommandActionColumns = `a.id::text,a.session_id::text,a.job_id,a.attempt,a.connection_id::text,a.ordinal,a.phase,a.protocol,a.rule_ids,a.operations,a.policy_digest,a.message_digest,a.status,a.reason,a.decided_at,a.observed_at,a.review_expires_at,a.source_event_id::text,COALESCE(review.approval_id,''),COALESCE(review.intent_digest,'')`
const pamCommandActionRead = ` FROM pam_command_actions a LEFT JOIN LATERAL (
 SELECT r.id::text AS approval_id,r.intent_digest FROM operation_approval_requests r
 WHERE r.tenant_id=$1 AND r.resource_kind='pam_command' AND r.resource_id='pam-command:'||a.id::text AND r.action='execute'
 ORDER BY r.created_at DESC,r.id DESC LIMIT 1) review ON true `

func scanPAMCommandAction(row pgx.Row) (PAMCommandAction, error) {
	var a PAMCommandAction
	err := row.Scan(&a.ID, &a.SessionID, &a.JobID, &a.Attempt, &a.ConnectionID, &a.Ordinal, &a.Phase, &a.Protocol, &a.RuleIDs, &a.Operations, &a.PolicyDigest, &a.MessageDigest, &a.Status, &a.Reason, &a.DecidedAt, &a.ObservedAt, &a.ReviewExpiresAt, &a.SourceEventID, &a.ApprovalRequestID, &a.ApprovalIntentDigest)
	// The source payload uses UTC. PostgreSQL codecs can attach Local to the
	// same instant; normalize before comparing a canonical occurrence on retry.
	a.DecidedAt = a.DecidedAt.UTC()
	a.ObservedAt = a.ObservedAt.UTC()
	if a.ReviewExpiresAt != nil {
		deadline := a.ReviewExpiresAt.UTC()
		a.ReviewExpiresAt = &deadline
	}
	return a, err
}

func (s *Store) GetPAMCommandAction(ctx context.Context, tenantID, id string) (PAMCommandAction, error) {
	var a PAMCommandAction
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		a, err = scanPAMCommandAction(tx.QueryRow(ctx, `SELECT `+pamCommandActionColumns+pamCommandActionRead+` WHERE a.tenant_id=$1 AND a.id=$2`, tenantID, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PAMCommandAction{}, ErrPAMCommandActionNotFound
	}
	return a, err
}

// ListPAMCommandActions is a bounded, stable page of one tenant/session's
// immutable decisions, newest first. The cursor contains public time/id only.
func (s *Store) ListPAMCommandActions(ctx context.Context, tenantID, sessionID string, limit int, before *time.Time, beforeID string) ([]PAMCommandAction, error) {
	if limit < 1 || limit > 101 {
		limit = 101
	}
	out := []PAMCommandAction{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pamCommandActionColumns+pamCommandActionRead+` WHERE a.tenant_id=$1 AND a.session_id=$2 AND ($3::timestamptz IS NULL OR (a.observed_at,a.id)<($3,NULLIF($4,'')::uuid))
 ORDER BY a.observed_at DESC,a.id DESC LIMIT $5`, tenantID, sessionID, before, beforeID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanPAMCommandAction(rows)
			if err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// GetPAMCommandActionForUpdateTx is the target-before-approval lock order shared
// by reviewer decisions and authorization projection. It never waits for a human.
func (s *Store) GetPAMCommandActionForUpdateTx(ctx context.Context, tx pgx.Tx, tenant, id string) (PAMCommandAction, error) {
	return scanPAMCommandAction(tx.QueryRow(ctx, `SELECT `+pamCommandActionColumns+pamCommandActionRead+` WHERE a.tenant_id=$1 AND a.id=$2 FOR UPDATE OF a`, tenant, id))
}

// ApplyPAMCommandAlertedTx projects an alerted command (A275): its action
// row, and in the same transaction the risk alert its outbox entry delivers.
// A replay finds the alert already queued with the same payload.
func (s *Store) ApplyPAMCommandAlertedTx(ctx context.Context, tx pgx.Tx, tenantID string, a PAMCommandAction, destination string, alert []byte, key string) error {
	if err := s.ApplyPAMCommandBlockedTx(ctx, tx, tenantID, a); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "pam-command-alert\x1f"+tenantID+"\x1f"+key); err != nil {
		return fmt.Errorf("store: lock session risk alert: %w", err)
	}
	var existingDestination string
	var existingPayload []byte
	err := tx.QueryRow(ctx, `SELECT destination, payload FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2 ORDER BY id LIMIT 1`,
		tenantID, key).Scan(&existingDestination, &existingPayload)
	if err == nil {
		if existingDestination != destination || !bytes.Equal(existingPayload, alert) {
			return fmt.Errorf("%w: session risk alert key is already bound", ErrIdempotencyConflict)
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO outbox (tenant_id, destination, effect_lane, payload, idempotency_key) VALUES ($1, $2, $2, $3, $4)`,
		tenantID, destination, alert, key); err != nil {
		return fmt.Errorf("store: enqueue session risk alert: %w", err)
	}
	return nil
}
