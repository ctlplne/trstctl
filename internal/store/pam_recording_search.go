// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// PAMRecordingSearchCandidate is a session recording a search may read
// (A275): the session's target and holder, and how much was recorded.
type PAMRecordingSearchCandidate struct {
	SessionID, TargetType, TargetID, Subject, Status string
	StartedAt                                        time.Time
	Bytes                                            int64
}

// ListPAMRecordingsForSearch lists a tenant's recordings that still hold
// their objects, begun in [from, until), newest first, at most limit: one
// target type's, or one target's, when named.
func (s *Store) ListPAMRecordingsForSearch(ctx context.Context, tenantID string, from, until time.Time, targetType, targetID string, limit int) ([]PAMRecordingSearchCandidate, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	var out []PAMRecordingSearchCandidate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT r.session_id::text, s.target_type, s.target_id, s.subject, r.status, r.started_at, r.bytes
		   FROM pam_session_recordings r
		   JOIN pam_sessions s ON s.tenant_id = r.tenant_id AND s.id = r.session_id
		  WHERE r.tenant_id = $1::uuid AND r.deleted_at IS NULL AND r.status <> 'deleted'
		    AND r.started_at >= $2 AND r.started_at < $3
		    AND ($4 = '' OR s.target_type = $4) AND ($5 = '' OR s.target_id = $5)
		  ORDER BY r.started_at DESC, r.session_id LIMIT $6`, tenantID, from.UTC(), until.UTC(), targetType, targetID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c PAMRecordingSearchCandidate
			if err := rows.Scan(&c.SessionID, &c.TargetType, &c.TargetID, &c.Subject, &c.Status, &c.StartedAt, &c.Bytes); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}
