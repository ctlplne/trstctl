// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// N9-L2: a check-in wave and its progress, read from the check-ins it queued
// (each carries the wave's approval).

// ErrMDMCheckInWaveNotFound means no such wave for this tenant.
var ErrMDMCheckInWaveNotFound = errors.New("store: MDM check-in wave not found")

// MDMCheckInWave is one wave; CheckedIn, Failed and Queued count its devices'
// check-ins by state.
type MDMCheckInWave struct {
	ID                string
	MDM               string
	RelayAgentID      string
	Reason            string
	ApprovalRequestID string
	RequestedBy       string
	DeviceCount       int
	QueuedAt          time.Time
	CheckedIn         int
	Failed            int
	Queued            int
}

// ApplyMDMCheckInWaveQueuedTx records a queued wave. Recording it again changes
// nothing.
func (s *Store) ApplyMDMCheckInWaveQueuedTx(ctx context.Context, tx pgx.Tx, tenantID string, w MDMCheckInWave, sequence uint64) error {
	seq, err := mdmCheckInSequence(sequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO mdm_check_in_waves (tenant_id, id, mdm, relay_agent_id, reason, approval_request_id, requested_by,
		                                device_count, queued_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (tenant_id, id) DO NOTHING`,
		tenantID, w.ID, w.MDM, w.RelayAgentID, w.Reason, w.ApprovalRequestID, w.RequestedBy, w.DeviceCount, w.QueuedAt.UTC(), seq)
	return err
}

// mdmCheckInWaveSelect reads waves with their devices' check-ins counted: a
// check-in the MDM acknowledged, one whose relay job failed, and the rest.
const mdmCheckInWaveSelect = `SELECT w.id::text, w.mdm, w.relay_agent_id, w.reason, w.approval_request_id::text, w.requested_by,
	w.device_count, w.queued_at,
	count(*) FILTER (WHERE c.checked_in),
	count(*) FILTER (WHERE NOT c.checked_in AND o.status = 'failed'),
	count(*) FILTER (WHERE NOT c.checked_in AND coalesce(o.status, '') <> 'failed')
	FROM mdm_check_in_waves w
	JOIN mdm_device_check_ins c ON c.tenant_id = w.tenant_id AND c.approval_request_id = w.approval_request_id
	LEFT JOIN outbox o ON o.tenant_id = c.tenant_id AND o.destination = 'mdm.device.check_in' AND o.idempotency_key = 'mdm-check-in:' || c.id::text`

const mdmCheckInWaveGroup = ` GROUP BY w.id, w.mdm, w.relay_agent_id, w.reason, w.approval_request_id, w.requested_by, w.device_count, w.queued_at`

func scanMDMCheckInWave(row pgx.Row) (MDMCheckInWave, error) {
	var w MDMCheckInWave
	err := row.Scan(&w.ID, &w.MDM, &w.RelayAgentID, &w.Reason, &w.ApprovalRequestID, &w.RequestedBy, &w.DeviceCount, &w.QueuedAt,
		&w.CheckedIn, &w.Failed, &w.Queued)
	return w, err
}

// GetMDMCheckInWave reads one wave with its progress.
func (s *Store) GetMDMCheckInWave(ctx context.Context, tenantID, id string) (MDMCheckInWave, error) {
	var w MDMCheckInWave
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		w, err = scanMDMCheckInWave(tx.QueryRow(ctx, mdmCheckInWaveSelect+` WHERE w.tenant_id = $1 AND w.id = $2`+mdmCheckInWaveGroup, tenantID, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return MDMCheckInWave{}, ErrMDMCheckInWaveNotFound
	}
	return w, err
}

// ListMDMCheckInWaves lists an MDM's waves with their progress, newest first.
func (s *Store) ListMDMCheckInWaves(ctx context.Context, tenantID, mdm string, limit int) ([]MDMCheckInWave, error) {
	out := []MDMCheckInWave{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, mdmCheckInWaveSelect+` WHERE w.tenant_id = $1 AND w.mdm = $2`+mdmCheckInWaveGroup+`
			ORDER BY w.queued_at DESC, w.id LIMIT $3`, tenantID, mdm, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			w, err := scanMDMCheckInWave(rows)
			if err != nil {
				return err
			}
			out = append(out, w)
		}
		return rows.Err()
	})
	return out, err
}
