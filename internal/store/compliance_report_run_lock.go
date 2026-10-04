// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
)

// WithComplianceReportRunLock elects one producer for an exact tenant/schedule/
// due edge across control-plane replicas. The lock is a PostgreSQL session
// advisory lock, so it spans archive I/O and the event append without holding
// a read-model transaction open. A competing worker skips this due edge.
func (s *Store) WithComplianceReportRunLock(ctx context.Context, tenantID, scheduleID string, due time.Time, fn func() error) (acquired bool, err error) {
	if _, parseErr := uuid.Parse(tenantID); parseErr != nil {
		return false, errors.New("store: report lock tenant must be a UUID")
	}
	if _, parseErr := uuid.Parse(scheduleID); parseErr != nil || due.IsZero() {
		return false, errors.New("store: report lock schedule and due edge are required")
	}
	if fn == nil {
		return false, errors.New("store: report lock callback is required")
	}
	identity := fmt.Sprintf("trstctl:compliance-report-run:v1:%s:%s:%s", tenantID, scheduleID, due.UTC().Format(time.RFC3339Nano))
	hash := crypto.SHA256Sum([]byte(identity))
	key := int64(binary.BigEndian.Uint64(hash[:8])) // #nosec G115 -- advisory-lock keys intentionally use all 64 hash bits, including the sign bit.
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Release()
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&acquired); err != nil {
		return false, err
	}
	if !acquired {
		return false, nil
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var unlocked bool
		unlockErr := conn.QueryRow(unlockCtx, `SELECT pg_advisory_unlock($1)`, key).Scan(&unlocked)
		if unlockErr != nil || !unlocked {
			_ = conn.Conn().Close(context.Background())
			if unlockErr == nil {
				unlockErr = errors.New("store: report advisory lock was not held on release")
			}
			err = errors.Join(err, unlockErr)
		}
	}()
	err = fn()
	return true, err
}
