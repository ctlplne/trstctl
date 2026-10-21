// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Cancelling queued or running connector work (A48).
//
// Every deploy, rollback, host renewal and containment for one deployment
// target shares that target's effect lane, so "everything in flight for this
// target" is one lane query. A row is in one of three states and the honest
// answer differs for each:
//
//   - withdrawn: nobody holds it. It stops being claimable and never executes.
//   - recalled: an enrolled agent holds its lease. The row is recalled the way
//     a paused migration recalls work: the agent's next lease extension,
//     credential redemption and rollback authorization are refused, and a late
//     signed result is retained as a receipt rather than applied. The agent
//     may already have changed the target; cancellation cannot undo that and
//     the receipt says so.
//   - executing: the control-plane outbox worker holds its lease and is inside
//     the connector call right now. That call cannot be interrupted from a
//     tenant request without leaving the appliance half-written, so the row is
//     reported and left alone; the operator cancels again once it lands, or
//     rolls back.

// Outbox status for a command an operator withdrew or recalled. It is terminal
// like failed, but it is not a delivery failure: dead-letter depth and retry
// surfaces count failed rows, and a cancellation is neither.
const OutboxStatusCancelled = "cancelled"

// OutboxLastErrorOperatorCancelled is the closed last_error class recorded on
// a cancelled row.
const OutboxLastErrorOperatorCancelled = "operator_cancelled"

const (
	ConnectorWorkWithdrawn = "withdrawn"
	ConnectorWorkRecalled  = "recalled"
	ConnectorWorkExecuting = "executing"
)

// ConnectorWorkCancellation is one unfinished command on a target lane and
// what cancellation did to it.
type ConnectorWorkCancellation struct {
	OutboxID         int64
	Destination      string
	IdempotencyKey   string
	Disposition      string
	ClaimedByAgentID string
	IdentityID       string
	Fingerprint      string
}

// connectorWorkIdentity reads the public routing fields a lane command carries.
type connectorWorkIdentity struct {
	IdentityID  string `json:"identity_id"`
	Fingerprint string `json:"fingerprint"`
}

// CancelConnectorTargetWorkTx withdraws or recalls every unfinished command on
// the target's lane, optionally narrowed to one identity, and reports the rows
// the control-plane worker is executing right now and therefore left alone.
// Idempotent: a second call finds nothing unfinished and returns no rows.
func (s *Store) CancelConnectorTargetWorkTx(ctx context.Context, tx pgx.Tx, tenantID, targetID, identityID string, at time.Time) ([]ConnectorWorkCancellation, error) {
	targetID = strings.TrimSpace(targetID)
	identityID = strings.TrimSpace(identityID)
	if targetID == "" {
		return nil, errors.New("store: cancelling connector work needs a target id")
	}
	at = at.UTC()
	rows, err := tx.Query(ctx,
		`SELECT id, destination, idempotency_key,
		        COALESCE(claimed_by_agent_id::text, ''),
		        claimed_by_agent_id IS NOT NULL AND claim_expires_at > $3 AS agent_leased,
		        status = 'processing' AND worker_id IS NOT NULL AND lease_until > $3 AS worker_leased,
		        convert_from(payload, 'UTF8')
		   FROM outbox
		  WHERE tenant_id = $1
		    AND effect_lane = $2
		    AND status IN ('pending', 'processing')
		    AND delivered_at IS NULL
		    AND claim_completed_at IS NULL
		  ORDER BY id
		    FOR UPDATE`,
		tenantID, ConnectorTargetLanePrefix+targetID, at)
	if err != nil {
		return nil, err
	}
	var out []ConnectorWorkCancellation
	var recall, withdraw []int64
	for rows.Next() {
		var c ConnectorWorkCancellation
		var agentLeased, workerLeased bool
		var payload string
		if err := rows.Scan(&c.OutboxID, &c.Destination, &c.IdempotencyKey, &c.ClaimedByAgentID,
			&agentLeased, &workerLeased, &payload); err != nil {
			rows.Close()
			return nil, err
		}
		var who connectorWorkIdentity
		_ = json.Unmarshal([]byte(payload), &who)
		c.IdentityID, c.Fingerprint = who.IdentityID, strings.ToLower(who.Fingerprint)
		if identityID != "" && c.IdentityID != identityID {
			continue
		}
		switch {
		case workerLeased:
			c.Disposition = ConnectorWorkExecuting
		case agentLeased:
			c.Disposition = ConnectorWorkRecalled
			recall = append(recall, c.OutboxID)
		default:
			c.Disposition = ConnectorWorkWithdrawn
			withdraw = append(withdraw, c.OutboxID)
		}
		out = append(out, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, ids := range [][]int64{recall, withdraw} {
		if len(ids) == 0 {
			continue
		}
		if _, err := tx.Exec(ctx,
			`UPDATE outbox
			    SET status = $3,
			        agent_recalled_at = COALESCE(agent_recalled_at, $4),
			        last_error = $5,
			        worker_id = NULL,
			        lease_until = NULL
			  WHERE tenant_id = $1 AND id = ANY($2::bigint[])
			    AND status IN ('pending', 'processing')
			    AND delivered_at IS NULL AND claim_completed_at IS NULL`,
			tenantID, ids, OutboxStatusCancelled, at, OutboxLastErrorOperatorCancelled); err != nil {
			return nil, err
		}
	}
	return out, nil
}
