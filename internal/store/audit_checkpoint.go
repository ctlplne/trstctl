// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/events"
)

// AuditCheckpointRLSID maps only the known pre-UUID Provider audit scope to a
// stable, isolated RLS partition. The original scope remains in the event and
// scope_id. Unknown text must fail closed rather than minting arbitrary UUID
// partitions that could make malformed replay or restore look valid.
func AuditCheckpointRLSID(scope string) (string, error) {
	if parsed, err := uuid.Parse(scope); err == nil {
		return parsed.String(), nil
	}
	if scope != events.LegacyProviderGlobalAuditScope {
		return "", errors.New("store: unsupported non-UUID audit scope")
	}
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl.audit.checkpoint.scope.v1\x00"+scope)).String(), nil
}

// SaveAuditCheckpoint persists a sealed retention boundary for a tenant (R4.4):
// every audit record up to BoundarySeq has been archived to cold storage and
// retired from the served audit-query view, anchored by BoundaryHash. The AN-2
// source envelopes remain present for rebuild. Re-sealing the same boundary
// updates it in place, so a retried run is idempotent.
func (s *Store) SaveAuditCheckpoint(ctx context.Context, cp audit.Checkpoint) error {
	storageTenant, err := AuditCheckpointRLSID(cp.TenantID)
	if err != nil {
		return err
	}
	return s.WithTenant(ctx, storageTenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`INSERT INTO audit_checkpoints (tenant_id, scope_id, boundary_seq, boundary_hash, record_count, archive_uri)
			 VALUES ($1, $2, $3, $4, $5, $6)
			 ON CONFLICT (tenant_id, boundary_seq)
			 DO UPDATE SET scope_id      = EXCLUDED.scope_id,
			               boundary_hash = EXCLUDED.boundary_hash,
			               record_count  = EXCLUDED.record_count,
			               archive_uri   = EXCLUDED.archive_uri,
			               created_at    = now()
			 WHERE COALESCE(audit_checkpoints.scope_id, audit_checkpoints.tenant_id::text) = EXCLUDED.scope_id`,
			storageTenant, cp.TenantID, int64(cp.BoundarySeq), cp.BoundaryHash, int64(cp.RecordCount), cp.ArchiveURI) // #nosec G115 -- event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("store: audit checkpoint scope storage collision")
		}
		return nil
	})
}

// ApplyAuditCheckpointTx reconciles the durable logical-retention receiver from
// an immutable audit.archived event during live projection or rebuild. The event
// carries the exact global boundary, cumulative tenant count, hash, and archive
// locator, so an event-only restore does not re-expose archived history merely
// because PostgreSQL started empty.
func (s *Store) ApplyAuditCheckpointTx(ctx context.Context, tx pgx.Tx, cp audit.Checkpoint) error {
	if cp.TenantID == "" || cp.BoundarySeq == 0 || cp.RecordCount <= 0 ||
		cp.BoundaryHash == "" || cp.ArchiveURI == "" {
		return errors.New("store: audit checkpoint event is incomplete")
	}
	storageTenant, err := AuditCheckpointRLSID(cp.TenantID)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO audit_checkpoints (tenant_id, scope_id, boundary_seq, boundary_hash, record_count, archive_uri)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (tenant_id, boundary_seq)
		 DO UPDATE SET scope_id      = EXCLUDED.scope_id,
		               boundary_hash = EXCLUDED.boundary_hash,
		               record_count  = EXCLUDED.record_count,
		               archive_uri   = EXCLUDED.archive_uri
		 WHERE COALESCE(audit_checkpoints.scope_id, audit_checkpoints.tenant_id::text) = EXCLUDED.scope_id`,
		storageTenant, cp.TenantID, int64(cp.BoundarySeq), cp.BoundaryHash, int64(cp.RecordCount), cp.ArchiveURI) // #nosec G115 -- event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("store: audit checkpoint scope storage collision")
	}
	return nil
}

// LatestAuditCheckpoint returns the tenant's most recent sealed boundary (the
// highest boundary_seq), or ok=false if none has been sealed. It satisfies
// audit.CheckpointSource.
func (s *Store) LatestAuditCheckpoint(ctx context.Context, tenantID string) (audit.Checkpoint, bool, error) {
	cp := audit.Checkpoint{TenantID: tenantID}
	found := false
	storageTenant, err := AuditCheckpointRLSID(tenantID)
	if err != nil {
		return audit.Checkpoint{}, false, err
	}
	err = s.WithTenant(ctx, storageTenant, func(tx pgx.Tx) error {
		var bseq, count int64
		row := tx.QueryRow(ctx,
			`SELECT boundary_seq, boundary_hash, record_count, archive_uri
			   FROM audit_checkpoints
			  WHERE tenant_id = $1 AND COALESCE(scope_id, tenant_id::text) = $2
			  ORDER BY boundary_seq DESC
			  LIMIT 1`, storageTenant, tenantID)
		switch err := row.Scan(&bseq, &cp.BoundaryHash, &count, &cp.ArchiveURI); {
		case err == nil:
			cp.BoundarySeq = uint64(bseq) // #nosec G115 -- event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190)
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

// ListAuditCheckpointTenants returns every tenant that has a logical audit
// retention boundary. Backup uses this system inventory to prove that even a
// legacy checkpoint whose tenant has no surviving live event cannot disappear
// from retained-source validation.
func (s *Store) ListAuditCheckpointTenants(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		//trstctl:system-query — cross-tenant by design: backup/DR must inventory every audit checkpoint before selecting each scope under tenant_id-scoped RLS; this query returns ordered scope ids only and no checkpoint contents.
		`SELECT DISTINCT COALESCE(scope_id, tenant_id::text) AS scope FROM audit_checkpoints ORDER BY scope`)
	if err != nil {
		return nil, fmt.Errorf("store: list audit checkpoint tenants: %w", err)
	}
	defer rows.Close()
	var tenants []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		tenants = append(tenants, tenantID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return tenants, nil
}
