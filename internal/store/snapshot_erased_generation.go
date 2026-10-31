// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// Only the complete-generation reader can attach the rejected cache identity.
// A bare erased flag or error supplied by a caller cannot select rows to delete.
type snapshotErasedGeneration struct{ captureID string }

func (*snapshotErasedGeneration) Error() string { return ErrSnapshotErased.Error() }
func (*snapshotErasedGeneration) Unwrap() error { return ErrSnapshotErased }

// DiscardErasedSnapshotGeneration removes only the disposable generation whose
// restore returned this private identity. Call AFTER successful current-source
// reconstruction; retained backup bytes and every other capture stay intact.
func (s *Store) DiscardErasedSnapshotGeneration(ctx context.Context, restoreErr error) error {
	var rejected *snapshotErasedGeneration
	if !errors.As(restoreErr, &rejected) || rejected == nil {
		return errors.New("store: erased snapshot generation identity is required")
	}
	id, err := uuid.Parse(rejected.captureID)
	if err != nil || id == uuid.Nil || id.Version() != 4 || id.String() != rejected.captureID {
		return errors.New("store: invalid erased snapshot generation identity")
	}
	return s.WithPrivacyReadModelReplacementBarrier(ctx, func(barrier context.Context) error {
		return s.WithProjectionLock(barrier, func(locked context.Context) error {
			_, err := s.pool.Exec(locked,
				//trstctl:system-query — system-only disposal of the exact rejected, reconstructible cross-tenant cache generation after successful source reconstruction; the owner-role bypass is bound to format and capture UUID, and no event, independent tenant state or retained artifact is deleted (AN-1 exemption).
				`DELETE FROM read_model_snapshots WHERE format_version=$1 AND payload -> $2 ->> 'id' = $3`,
				SnapshotFormatVersion, snapshotSetPayloadKey, rejected.captureID)
			return err
		})
	})
}
