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

// Incident closure (P13): the projection of incident.execution.closed.

// IncidentClosure is one incident closed in trstctl, with the state of the
// ServiceNow resolution it queued, if any.
type IncidentClosure struct {
	IncidentID string
	Resolution string
	ClosedBy   string
	ServiceNow bool
	ClosedAt   time.Time
	// JobStatus and JobError are the ServiceNow resolution's outbox state.
	JobStatus string
	JobError  string
}

// ApplyIncidentClosedTx projects a closure. A replay adds nothing.
func (s *Store) ApplyIncidentClosedTx(ctx context.Context, tx pgx.Tx, tenantID string, c IncidentClosure, sequence uint64) error {
	if sequence == 0 || sequence > math.MaxInt64 {
		return fmt.Errorf("store: incident closure event sequence %d is out of range", sequence)
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO incident_closures (tenant_id, incident_id, resolution, closed_by, servicenow, closed_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, incident_id) DO NOTHING`,
		tenantID, c.IncidentID, c.Resolution, c.ClosedBy, c.ServiceNow, c.ClosedAt.UTC(), int64(sequence)) // #nosec G115 -- bounded above (CWE-190)
	return err
}

// GetIncidentClosure reads an incident's closure with its ServiceNow
// resolution's outbox state.
func (s *Store) GetIncidentClosure(ctx context.Context, tenantID, incidentID string) (IncidentClosure, bool, error) {
	var c IncidentClosure
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT c.incident_id, c.resolution, c.closed_by, c.servicenow, c.closed_at,
			       coalesce(o.status, ''), coalesce(o.last_error, '')
			  FROM incident_closures c
			  LEFT JOIN outbox o ON o.tenant_id = c.tenant_id AND o.destination = 'itsm.servicenow.close'
			                    AND o.idempotency_key = 'servicenow-close:' || c.incident_id
			 WHERE c.tenant_id = $1 AND c.incident_id = $2`, tenantID, incidentID).Scan(
			&c.IncidentID, &c.Resolution, &c.ClosedBy, &c.ServiceNow, &c.ClosedAt, &c.JobStatus, &c.JobError)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	return c, found, err
}
