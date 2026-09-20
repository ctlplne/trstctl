// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/events"
)

// RebindCertificateMetadataPrivacyReceiptsTx must be called from the existing
// verified privacy preparation: that call site pins the old source after the
// actual staged target has passed the deterministic actor/data pair validator.
// It updates existing completion digests, never creates execution evidence.
// The preparation crash marker and these updates commit together before cutover.
// Randomized/generic history rewrites cannot use this deterministic transform.
// The snapshot-deferral flag below rejects ordinary contexts; it is not by
// itself a live verification lease or a tenant/subject authorization token.
func (s *Store) RebindCertificateMetadataPrivacyReceiptsTx(ctx context.Context, tx pgx.Tx, tenantID, subject string,
	replay func(context.Context, uint64, uint64, func(events.Event) error) error) error {
	if !events.TenantDataCutoverDefersSnapshotInvalidation(ctx) {
		return errors.New("store: certificate receipt rebinding requires the privacy cutover context")
	}
	if replay == nil {
		return errors.New("store: certificate privacy receipt source replay missing")
	}
	if err := s.LockCertificateMetadataOrderTx(ctx, tx, tenantID); err != nil {
		return err
	}
	tenant, err := uuid.Parse(tenantID)
	if err != nil {
		return err
	}
	var afterSequence int64
	for {
		type receipt struct {
			sequence   int64
			id, digest string
		}
		rows, err := tx.Query(ctx, `SELECT event_sequence,event_id,event_digest FROM certificate_metadata_receipts
			WHERE tenant_id=$1 AND event_sequence>$2 ORDER BY event_sequence LIMIT 128`, tenantID, afterSequence)
		if err != nil {
			return err
		}
		batch := make([]receipt, 0, 128)
		for rows.Next() {
			var r receipt
			if err := rows.Scan(&r.sequence, &r.id, &r.digest); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}
		// The pages cover disjoint physical sequence intervals. Walk each
		// source interval once, rather than scanning all history per receipt.
		firstSequence, lastSequence := batch[0].sequence, batch[len(batch)-1].sequence
		if firstSequence <= 0 || lastSequence <= 0 {
			return errors.New("store: invalid certificate receipt sequence")
		}
		matched := 0
		var lastSeen uint64
		err = replay(ctx, uint64(firstSequence), uint64(lastSequence), func(before events.Event) error {
			if before.Sequence <= lastSeen {
				return errors.New("store: frozen certificate receipt source is not strictly ordered")
			}
			lastSeen = before.Sequence
			if matched == len(batch) {
				return nil
			}
			r := batch[matched]
			if r.sequence <= 0 {
				return errors.New("store: invalid certificate receipt sequence")
			}
			expected := uint64(r.sequence)
			if before.Sequence < expected {
				return nil
			}
			sourceTenant, tenantErr := uuid.Parse(before.TenantID)
			if before.Sequence != expected || before.ID != r.id || tenantErr != nil || sourceTenant != tenant {
				return errors.New("store: certificate receipt has no matching frozen source occurrence")
			}
			oldDigest, err := certificateMetadataEventDigest(before)
			if err != nil {
				return err
			}
			if oldDigest != r.digest {
				return fmt.Errorf("%w: certificate privacy receipt differs from frozen source", ErrIdempotencyConflict)
			}
			after := before
			after.Actor, _ = events.PseudonymizeActorForSubject(before.Actor, tenantID, subject)
			if len(before.Data) > 0 {
				data, version, changed, err := events.PseudonymizeEventDataForSubjectVersioned(before.Data, tenantID, subject, before.Type, before.SchemaVersion)
				if err != nil {
					return err
				}
				if changed {
					after.Data, after.SchemaVersion = data, version
				}
			}
			newDigest, err := certificateMetadataEventDigest(after)
			if err != nil {
				return err
			}
			if newDigest != oldDigest {
				tag, err := tx.Exec(ctx, `UPDATE certificate_metadata_receipts SET event_digest=$4
                    WHERE tenant_id=$1 AND event_sequence=$2 AND event_id=$3 AND event_digest=$5`, tenantID, r.sequence, r.id, newDigest, oldDigest)
				if err != nil {
					return err
				}
				if tag.RowsAffected() != 1 {
					return errors.New("store: certificate privacy receipt changed during preparation")
				}
			}
			matched++
			return nil
		})
		if err != nil {
			return err
		}
		if matched != len(batch) {
			return errors.New("store: certificate receipts exceed retained frozen source")
		}
		afterSequence = lastSequence
	}
}
