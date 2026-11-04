// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

// Decisions on pending AD CS requests (N1): the projections of
// adcs.request.decision_queued and adcs.request.decided.

// ErrADCSDecisionNotFound is a decision this tenant does not have.
var ErrADCSDecisionNotFound = errors.New("store: AD CS decision not found")

// ADCSDecision is one approved decision on one pending AD CS request.
type ADCSDecision struct {
	ID                string
	IssuerID          string
	CAConfig          string
	RequestID         int
	Decision          string
	RelayAgentID      string
	Reason            string
	ApprovalRequestID string
	RequestedBy       string
	Decided           bool
	Disposition       string
	Serial            string
	QueuedAt          time.Time
	DecidedAt         *time.Time
	// JobStatus and JobError are the relay job's state while undecided.
	JobStatus string
	JobError  string
}

func adcsDecisionSequence(sequence uint64) (int64, error) {
	if sequence == 0 || sequence > math.MaxInt64 {
		return 0, fmt.Errorf("store: AD CS decision event sequence %d is out of range", sequence)
	}
	return int64(sequence), nil // #nosec G115 -- bounded above (CWE-190)
}

// ApplyADCSDecisionQueuedTx projects a queued decision. A replay adds nothing.
func (s *Store) ApplyADCSDecisionQueuedTx(ctx context.Context, tx pgx.Tx, tenantID string, d ADCSDecision, sequence uint64) error {
	seq, err := adcsDecisionSequence(sequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO adcs_request_decisions (tenant_id, id, issuer_id, ca_config, request_id, decision, relay_agent_id, reason,
		                                    approval_request_id, requested_by, queued_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (tenant_id, id) DO NOTHING`,
		tenantID, d.ID, d.IssuerID, d.CAConfig, d.RequestID, d.Decision, d.RelayAgentID, d.Reason, d.ApprovalRequestID,
		d.RequestedBy, d.QueuedAt.UTC(), seq)
	return err
}

// ApplyADCSDecidedTx records what the CA holds after a decision.
func (s *Store) ApplyADCSDecidedTx(ctx context.Context, tx pgx.Tx, tenantID, id, disposition, serial string, at time.Time, sequence uint64) error {
	seq, err := adcsDecisionSequence(sequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE adcs_request_decisions SET decided = true, disposition = $3, serial = $4, decided_at = $5,
		event_sequence = $6 WHERE tenant_id = $1 AND id = $2 AND NOT decided`, tenantID, id, disposition, serial, at.UTC(), seq)
	return err
}

// adcsDecisionColumns read a decision with its relay job's state: the job is
// the outbox row the decision queued.
const adcsDecisionColumns = `d.id::text, d.issuer_id, d.ca_config, d.request_id, d.decision, d.relay_agent_id, d.reason,
	d.approval_request_id::text, d.requested_by, d.decided, d.disposition, d.serial, d.queued_at, d.decided_at,
	coalesce(o.status, ''), coalesce(o.last_error, '')`

const adcsDecisionFrom = ` FROM adcs_request_decisions d
	LEFT JOIN outbox o ON o.tenant_id = d.tenant_id AND o.destination = 'adcs.request.decide' AND o.idempotency_key = 'adcs-decide:' || d.id::text`

func scanADCSDecision(row pgx.Row) (ADCSDecision, error) {
	var d ADCSDecision
	err := row.Scan(&d.ID, &d.IssuerID, &d.CAConfig, &d.RequestID, &d.Decision, &d.RelayAgentID, &d.Reason, &d.ApprovalRequestID,
		&d.RequestedBy, &d.Decided, &d.Disposition, &d.Serial, &d.QueuedAt, &d.DecidedAt, &d.JobStatus, &d.JobError)
	return d, err
}

// GetADCSDecision reads one decision.
func (s *Store) GetADCSDecision(ctx context.Context, tenantID, id string) (ADCSDecision, error) {
	var d ADCSDecision
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		d, err = scanADCSDecision(tx.QueryRow(ctx, `SELECT `+adcsDecisionColumns+adcsDecisionFrom+`
			WHERE d.tenant_id = $1 AND d.id = $2`, tenantID, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ADCSDecision{}, ErrADCSDecisionNotFound
	}
	return d, err
}

// ListADCSDecisions lists an issuer's decisions, newest first.
func (s *Store) ListADCSDecisions(ctx context.Context, tenantID, issuerID string, limit int) ([]ADCSDecision, error) {
	out := []ADCSDecision{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+adcsDecisionColumns+adcsDecisionFrom+`
			WHERE d.tenant_id = $1 AND d.issuer_id = $2 ORDER BY d.queued_at DESC, d.id LIMIT $3`, tenantID, issuerID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			d, err := scanADCSDecision(rows)
			if err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}
