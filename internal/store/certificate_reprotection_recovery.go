// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"math"
)

// CAReprotectionNameRecoveryCursor is independent of applied_seq: an older
// projector could have applied the cutover without updating the issuer name.
func (s *Store) CAReprotectionNameRecoveryCursor(ctx context.Context) (uint64, error) {
	var checked int64
	err := s.poolFor(ctx).QueryRow(ctx, `SELECT COALESCE(ca_reprotection_name_checked_through,0)
		FROM projection_checkpoint WHERE id=1`).Scan(&checked)
	if err != nil {
		return 0, err
	}
	if checked < 0 {
		return 0, errors.New("store: negative CA re-protection name recovery cursor")
	}
	return uint64(checked), nil
}

// MarkCAReprotectionNameCheckedThrough advances only after the indexed pass
// completes. A crash before this write repeats idempotent derived-field repair.
func (s *Store) MarkCAReprotectionNameCheckedThrough(ctx context.Context, seq uint64) error {
	if seq > math.MaxInt64 {
		return errors.New("store: CA re-protection name recovery head exceeds PostgreSQL bigint")
	}
	checked := int64(seq) // #nosec G115 -- MaxInt64 bound above rejects narrowing (CWE-190).
	_, err := s.poolFor(ctx).Exec(ctx, `UPDATE projection_checkpoint
		SET ca_reprotection_name_checked_through=GREATEST(COALESCE(ca_reprotection_name_checked_through,0),$1),updated_at=now()
		WHERE id=1`, checked)
	return err
}
