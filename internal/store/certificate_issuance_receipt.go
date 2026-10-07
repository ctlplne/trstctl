// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/eventspec"
)

// CertificateIssuanceReceipt is a summary of the immutable source event. The
// projector classifies it only after that event's effects have succeeded. An
// incomplete legacy mint remains unverifiable rather than becoming a zero.
type CertificateIssuanceReceipt struct {
	Status      string
	Fingerprint *string
	Time        *time.Time
	// True only when a retained v2 managed-CA mint also projected its signed
	// public leaf into inventory. Old responder-only receipts default false.
	LegacyInventoryProjected bool
}

// CertificateIssuanceReceiptsNeedBackfill identifies pre-upgrade receipts and
// old snapshot rows. Only exact retained source envelopes can fill these fields.
func (s *Store) CertificateIssuanceReceiptsNeedBackfill(ctx context.Context) (bool, error) {
	tenants, err := s.ListTenants(ctx)
	if err != nil {
		return false, err
	}
	// Enumerate the existing registry, then inspect each live customer's
	// receipts under its application-role RLS context. Erased customers have
	// no history to backfill; no privileged receipt-table scan is needed.
	for _, tenant := range tenants {
		var unknown bool
		err := s.WithTenant(ctx, tenant.TenantID, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM certificate_metadata_receipts
				WHERE tenant_id=$1 AND issuance_status IS NULL)`, tenant.TenantID).Scan(&unknown)
		})
		if err != nil || unknown {
			return unknown, err
		}
	}
	return false, nil
}

// BackfillCertificateIssuanceReceipt updates only an existing, digest-verified
// completion receipt. It never replays inventory mutations or inserts a missing
// receipt. Erased or unavailable history therefore cannot become invented facts.
func (s *Store) BackfillCertificateIssuanceReceipt(ctx context.Context, e eventspec.Event, summarize func() (CertificateIssuanceReceipt, error)) error {
	return s.WithTenant(ctx, e.TenantID, func(tx pgx.Tx) error {
		if err := s.LockCertificateMetadataOrderTx(ctx, tx, e.TenantID); err != nil {
			return err
		}
		done, err := s.CertificateMetadataEventAppliedTx(ctx, tx, e)
		if err != nil || !done {
			return err
		}
		summary, err := summarize()
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE certificate_metadata_receipts
			SET issuance_status=$3,issuance_fingerprint=$4,issuance_time=$5
			WHERE tenant_id=$1 AND event_id=$2 AND issuance_status IS NULL`,
			e.TenantID, e.ID, summary.Status, summary.Fingerprint, summary.Time)
		return err
	})
}

// WithResponderIssuanceReceiptTx binds a responder-only issuance event to its
// successful serial projection. It does not advance the inventory metadata
// watermark: these events do not mutate certificate inventory or read its state.
// Sharing the immutable receipt format permits one fingerprint recount across
// responder-only and inventory-backed issuance without manufacturing inventory.
func (s *Store) WithResponderIssuanceReceiptTx(ctx context.Context, tx pgx.Tx, e eventspec.Event, apply func() error, summarize func() (CertificateIssuanceReceipt, error)) error {
	if e.Type != "ca.endentity.issued" && e.Type != "ca.certificate.issued" {
		return errors.New("store: expected responder issuance event")
	}
	if e.Sequence > math.MaxInt64 {
		return errors.New("store: issuance sequence exceeds PostgreSQL bigint")
	}
	if err := s.LockCertificateMetadataOrderTx(ctx, tx, e.TenantID); err != nil {
		return err
	}
	if e.Sequence == 0 {
		return apply()
	}
	// Exact receipts survive legacy renames within a lifetime. Offboard erases
	// them under this same fence, so an erased event still reaches the live-row
	// check below rather than inheriting authority in a replacement customer.
	done, err := s.CertificateMetadataEventAppliedTx(ctx, tx, e)
	if err != nil || done {
		return err
	}
	// Offboard holds the same metadata fence while erasing the registration
	// and receipts. Read under that fence without reversing its lifecycle lock
	// order. A retained event cannot enter a later registration of the UUID.
	var registration int64
	if err := tx.QueryRow(ctx, `SELECT event_seq FROM tenants WHERE tenant_id=$1`, e.TenantID).Scan(&registration); err != nil {
		return fmt.Errorf("%w: issuance receipt requires a live tenant: %v", ErrIdempotencyConflict, err)
	}
	if registration < 0 || (registration > 0 && e.Sequence <= uint64(registration)) {
		return fmt.Errorf("%w: issuance event predates the live tenant registration", ErrIdempotencyConflict)
	}
	if err := apply(); err != nil {
		return err
	}
	summary, err := summarize()
	if err != nil {
		return err
	}
	digest, err := certificateMetadataEventDigest(e)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO certificate_metadata_receipts
  (tenant_id,event_sequence,event_id,event_digest,issuance_status,issuance_fingerprint,issuance_time)
  VALUES($1,$2,$3,$4,$5,$6,$7)`, e.TenantID, int64(e.Sequence), e.ID, digest, summary.Status, summary.Fingerprint, summary.Time)
	return err
}
