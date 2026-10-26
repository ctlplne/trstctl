// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// MaxAgentJobApplianceReference bounds an appliance's reference for a job.
const MaxAgentJobApplianceReference = 256

// RecordAgentJobApplianceReference keeps an appliance's own reference for the
// key request a job made (A122): Cisco ISE's ID for the CSR it generated. Only
// the agent holding the job at that attempt may record it, and a later attempt
// replaces it only when it had to make a new request. recorded is false when
// the agent no longer holds the job.
func (s *Store) RecordAgentJobApplianceReference(ctx context.Context, tenantID, agentID string, jobID int64, attempt int,
	reference string, now time.Time) (bool, error) {
	reference = strings.TrimSpace(reference)
	if reference == "" || len(reference) > MaxAgentJobApplianceReference || jobID <= 0 || attempt <= 0 {
		return false, errors.New("store: an appliance reference needs a job, an attempt and a reference of at most 256 bytes")
	}
	recorded := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var held bool
		err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM outbox
		 WHERE tenant_id=$1 AND id=$2 AND claimed_by_agent_id=$3::uuid
		 AND claim_attempts=$4 AND claim_completed_at IS NULL
		 AND agent_recalled_at IS NULL AND status='pending' AND claim_expires_at>$5)`,
			tenantID, jobID, agentID, attempt, now.UTC()).Scan(&held)
		if err != nil || !held {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO agent_job_appliance_references (tenant_id, job_id, reference, recorded_attempt, recorded_at)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (tenant_id, job_id) DO UPDATE SET reference = EXCLUDED.reference,
			  recorded_attempt = EXCLUDED.recorded_attempt, recorded_at = EXCLUDED.recorded_at`,
			tenantID, jobID, reference, attempt, now.UTC())
		if err != nil {
			return err
		}
		recorded = true
		return nil
	})
	return recorded, err
}

// AgentJobApplianceReference returns the appliance reference a job recorded,
// or "" when it has none.
func (s *Store) AgentJobApplianceReference(ctx context.Context, tenantID string, jobID int64) (string, error) {
	var reference string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT reference FROM agent_job_appliance_references WHERE tenant_id=$1 AND job_id=$2`,
			tenantID, jobID).Scan(&reference)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	return reference, err
}
