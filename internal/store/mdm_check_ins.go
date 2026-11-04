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

// MDM device check-ins (N9): the projections of mdm.device.check_in_queued
// and mdm.device.checked_in.

// ErrMDMCheckInNotFound is a check-in this tenant does not have.
var ErrMDMCheckInNotFound = errors.New("store: MDM check-in not found")

// MDMCheckIn is one approved check-in of one MDM device.
type MDMCheckIn struct {
	ID                string
	MDM               string
	DeviceID          string
	DeviceName        string
	RelayAgentID      string
	Reason            string
	ApprovalRequestID string
	RequestedBy       string
	CheckedIn         bool
	ProviderStatus    int
	QueuedAt          time.Time
	CheckedInAt       *time.Time
	// JobStatus and JobError are the relay job's state until the MDM
	// acknowledges the check-in.
	JobStatus string
	JobError  string
}

func mdmCheckInSequence(sequence uint64) (int64, error) {
	if sequence == 0 || sequence > math.MaxInt64 {
		return 0, fmt.Errorf("store: MDM check-in event sequence %d is out of range", sequence)
	}
	return int64(sequence), nil // #nosec G115 -- bounded above (CWE-190)
}

// ApplyMDMCheckInQueuedTx projects a queued check-in. A replay adds nothing.
func (s *Store) ApplyMDMCheckInQueuedTx(ctx context.Context, tx pgx.Tx, tenantID string, c MDMCheckIn, sequence uint64) error {
	seq, err := mdmCheckInSequence(sequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO mdm_device_check_ins (tenant_id, id, mdm, device_id, device_name, relay_agent_id, reason,
		                                  approval_request_id, requested_by, queued_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (tenant_id, id) DO NOTHING`,
		tenantID, c.ID, c.MDM, c.DeviceID, c.DeviceName, c.RelayAgentID, c.Reason, c.ApprovalRequestID, c.RequestedBy,
		c.QueuedAt.UTC(), seq)
	return err
}

// ApplyMDMCheckedInTx records the MDM's acknowledgement of a check-in.
func (s *Store) ApplyMDMCheckedInTx(ctx context.Context, tx pgx.Tx, tenantID, id string, providerStatus int, at time.Time, sequence uint64) error {
	seq, err := mdmCheckInSequence(sequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE mdm_device_check_ins SET checked_in = true, provider_status = $3, checked_in_at = $4,
		event_sequence = $5 WHERE tenant_id = $1 AND id = $2 AND NOT checked_in`, tenantID, id, providerStatus, at.UTC(), seq)
	return err
}

// mdmCheckInColumns read a check-in with its relay job's state: the job is the
// outbox row the check-in queued.
const mdmCheckInColumns = `c.id::text, c.mdm, c.device_id, c.device_name, c.relay_agent_id, c.reason,
	c.approval_request_id::text, c.requested_by, c.checked_in, c.provider_status, c.queued_at, c.checked_in_at,
	coalesce(o.status, ''), coalesce(o.last_error, '')`

const mdmCheckInFrom = ` FROM mdm_device_check_ins c
	LEFT JOIN outbox o ON o.tenant_id = c.tenant_id AND o.destination = 'mdm.device.check_in' AND o.idempotency_key = 'mdm-check-in:' || c.id::text`

func scanMDMCheckIn(row pgx.Row) (MDMCheckIn, error) {
	var c MDMCheckIn
	err := row.Scan(&c.ID, &c.MDM, &c.DeviceID, &c.DeviceName, &c.RelayAgentID, &c.Reason, &c.ApprovalRequestID,
		&c.RequestedBy, &c.CheckedIn, &c.ProviderStatus, &c.QueuedAt, &c.CheckedInAt, &c.JobStatus, &c.JobError)
	return c, err
}

// GetMDMCheckIn reads one check-in.
func (s *Store) GetMDMCheckIn(ctx context.Context, tenantID, id string) (MDMCheckIn, error) {
	var c MDMCheckIn
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		c, err = scanMDMCheckIn(tx.QueryRow(ctx, `SELECT `+mdmCheckInColumns+mdmCheckInFrom+`
			WHERE c.tenant_id = $1 AND c.id = $2`, tenantID, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return MDMCheckIn{}, ErrMDMCheckInNotFound
	}
	return c, err
}

// ListMDMCheckIns lists one MDM's check-ins, newest first.
func (s *Store) ListMDMCheckIns(ctx context.Context, tenantID, mdm string, limit int) ([]MDMCheckIn, error) {
	out := []MDMCheckIn{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+mdmCheckInColumns+mdmCheckInFrom+`
			WHERE c.tenant_id = $1 AND c.mdm = $2 ORDER BY c.queued_at DESC, c.id LIMIT $3`, tenantID, mdm, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanMDMCheckIn(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}
