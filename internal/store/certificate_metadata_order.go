// SPDX-License-Identifier: MPL-2.0
package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// WithCertificateProjectionOrderTx makes the actual envelope sequence visible
// only during one projector call. It does not authorize a tenant or replace RLS.
// The previous value is restored so unrelated writes in the same transaction
// cannot borrow this event's provenance. Rebuild uses the same event path.
// This scope does not acquire the certificate fence: unrelated event handlers
// may already hold their own domain locks. Certificate-dependent projectors
// admit before their first dependency read/row lock; direct SQL writers share
// the same fence through the BEFORE STATEMENT trigger.
func (s *Store) WithCertificateProjectionOrderTx(ctx context.Context, tx pgx.Tx, tenantID string, sequence uint64, apply func() error) (err error) {
	if sequence > math.MaxInt64 {
		return errors.New("store: certificate projection sequence exceeds PostgreSQL bigint")
	}
	var scoped bool
	var previous, previousTenant string
	if err := tx.QueryRow(ctx, `SELECT current_setting('trstctl.tenant_id',true)::uuid=$1::uuid,coalesce(current_setting('trstctl.certificate_projection_sequence',true),''),coalesce(current_setting('trstctl.certificate_projection_tenant',true),'')`, tenantID).Scan(&scoped, &previous, &previousTenant); err != nil {
		return err
	}
	if !scoped {
		return errors.New("store: certificate projection tenant differs from transaction scope (AN-1)")
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.certificate_projection_sequence',$1,true),set_config('trstctl.certificate_projection_tenant',$2,true)`, strconv.FormatUint(sequence, 10), tenantID); err != nil {
		return err
	}
	defer func() {
		_, restoreErr := tx.Exec(ctx, `SELECT set_config('trstctl.certificate_projection_sequence',$1,true),set_config('trstctl.certificate_projection_tenant',$2,true)`, previous, previousTenant)
		if err == nil && restoreErr != nil {
			err = fmt.Errorf("store: restore certificate projection scope: %w", restoreErr)
		}
	}()
	err = apply()
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) && pgerr.Code == "TC001" {
		return fmt.Errorf("%w: %s", ErrCertificateRecordingRebuildRequired, pgerr.Message)
	}
	return err
}

// GuardCertificateRecordingMetadataTx locks the leaf AND the predecessor that
// recording can supersede, before checking order. Ordinary metadata writers do
// not share the fingerprint advisory lock. The statement-level tenant fence
// covers even zero-row writers; row metadata retains per-leaf provenance too.
// Unknown legacy metadata and later effects require the existing full ordered
// rebuild. This method never restores a field or pretends the event was applied.
func (s *Store) GuardCertificateRecordingMetadataTx(ctx context.Context, tx pgx.Tx, tenantID, fingerprint string, replacesID *string, sequence uint64) error {
	if sequence > math.MaxInt64 {
		return errors.New("store: invalid certificate metadata sequence")
	}
	if err := s.LockCertificateMetadataOrderTx(ctx, tx, tenantID); err != nil {
		return err
	}
	var latest int64
	var unknown bool
	err := tx.QueryRow(ctx, `SELECT latest_sequence,unknown_write FROM certificate_metadata_watermarks WHERE tenant_id=$1`, tenantID).Scan(&latest, &unknown)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil && (unknown || latest < 0 || uint64(latest) > sequence) {
		return fmt.Errorf("%w: tenant certificate statement at %d (unknown=%t) is later than retained recording %d", ErrCertificateRecordingRebuildRequired, latest, unknown, sequence)
	}
	if sequence == 0 {
		return nil
	} // A zero head still checks the tenant statement fence above.
	rows, err := tx.Query(ctx, `SELECT id::text,metadata_sequence FROM certificates
        WHERE tenant_id=$1 AND (fingerprint=$2 OR id=$3::uuid)
        ORDER BY id FOR UPDATE`, tenantID, fingerprint, replacesID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var latest int64
		if err := rows.Scan(&id, &latest); err != nil {
			return err
		}
		if latest <= 0 || uint64(latest) > sequence {
			return fmt.Errorf("%w: retained event %d cannot overwrite certificate %s metadata at %d; stop incremental recovery and run the authorized ordered rebuild", ErrCertificateRecordingRebuildRequired, sequence, id, latest)
		}
	}
	return rows.Err()
}

// LockCertificateMetadataOrderTx shares the statement trigger's tenant lock.
// Projectors take it before their row/fingerprint locks; a recording command
// holds it before scanning the log and before any irreversible append.
func (s *Store) LockCertificateMetadataOrderTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	_, err := tx.Exec(ctx, `SELECT lock_certificate_metadata_order($1::uuid)`, tenantID)
	return err
}
