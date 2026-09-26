// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// AgentJobAttemptBinding returns the server-recorded destination only when this
// exact agent received this exact attempt. It grants no lease, credential access
// or permission to apply an observation to current target state.
func (s *Store) AgentJobAttemptBinding(ctx context.Context, tenantID, agentID string, jobID int64, attempt int) (string, bool, error) {
	var destination string
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT destination FROM agent_job_attempt_bindings
		 WHERE tenant_id=$1 AND job_id=$2 AND attempt=$3 AND agent_id=$4::uuid`,
			tenantID, jobID, attempt, agentID).Scan(&destination)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return nil
	})
	return destination, found, err
}
