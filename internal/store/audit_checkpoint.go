package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/audit"
)

// SaveAuditCheckpoint persists a sealed retention boundary for a tenant (R4.4):
// every audit record up to BoundarySeq has been archived to cold storage and
// pruned from the hot log, anchored by BoundaryHash. Re-sealing the same boundary
// updates it in place, so a retried run is idempotent. It satisfies
// audit.CheckpointSink.
func (s *Store) SaveAuditCheckpoint(ctx context.Context, cp audit.Checkpoint) error {
	return s.WithTenant(ctx, cp.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO audit_checkpoints (tenant_id, boundary_seq, boundary_hash, record_count, archive_uri)
			 VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (tenant_id, boundary_seq)
			 DO UPDATE SET boundary_hash = EXCLUDED.boundary_hash,
			               record_count  = EXCLUDED.record_count,
			               archive_uri   = EXCLUDED.archive_uri,
			               created_at    = now()`,
			cp.TenantID, int64(cp.BoundarySeq), cp.BoundaryHash, int64(cp.RecordCount), cp.ArchiveURI)
		return err
	})
}

// LatestAuditCheckpoint returns the tenant's most recent sealed boundary (the
// highest boundary_seq), or ok=false if none has been sealed. It satisfies
// audit.CheckpointSource.
func (s *Store) LatestAuditCheckpoint(ctx context.Context, tenantID string) (audit.Checkpoint, bool, error) {
	cp := audit.Checkpoint{TenantID: tenantID}
	found := false
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var bseq, count int64
		row := tx.QueryRow(ctx,
			`SELECT boundary_seq, boundary_hash, record_count, archive_uri
			   FROM audit_checkpoints
			  WHERE tenant_id = $1
			  ORDER BY boundary_seq DESC
			  LIMIT 1`, tenantID)
		switch err := row.Scan(&bseq, &cp.BoundaryHash, &count, &cp.ArchiveURI); {
		case err == nil:
			cp.BoundarySeq = uint64(bseq)
			cp.RecordCount = int(count)
			found = true
			return nil
		case errors.Is(err, pgx.ErrNoRows):
			return nil
		default:
			return err
		}
	})
	if err != nil {
		return audit.Checkpoint{}, false, err
	}
	return cp, found, nil
}
