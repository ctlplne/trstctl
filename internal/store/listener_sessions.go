// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

// ListenerSessionObservation is a host's count of a listener's established
// connections right after a verified deploy (A245-L2): HeldByOlder are held by
// a process started before Since (the deploy's start), Unattributed by a
// process the agent could not read.
type ListenerSessionObservation struct {
	ID           string
	IdentityID   *string
	TargetID     string
	Target       string
	Fingerprint  string
	Port         int
	Established  int
	HeldByOlder  int
	Unattributed int
	Since        time.Time
	CheckedAt    time.Time
}

// ApplyListenerSessionsObservedTx projects connector.listener_sessions.observed;
// a replayed event changes nothing.
func (s *Store) ApplyListenerSessionsObservedTx(ctx context.Context, tx pgx.Tx, tenantID string, o ListenerSessionObservation, eventSequence uint64) error {
	var identity any
	if o.IdentityID != nil && isUUIDText(*o.IdentityID) {
		identity = *o.IdentityID
	}
	if eventSequence > math.MaxInt64 {
		eventSequence = 0
	}
	_, err := tx.Exec(ctx, `INSERT INTO listener_session_observations (tenant_id, id, identity_id, target_id, target, fingerprint,
		    port, established, held_by_older, unattributed, since, checked_at, event_sequence)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) ON CONFLICT (tenant_id, id) DO NOTHING`,
		tenantID, o.ID, identity, o.TargetID, o.Target, o.Fingerprint, o.Port, o.Established, o.HeldByOlder, o.Unattributed,
		o.Since, o.CheckedAt, int64(eventSequence)) // #nosec G115 -- bounded by MaxInt64 above.
	return err
}
