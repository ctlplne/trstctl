// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// OwnershipAssignment is the current projection of the most specific owner
// decision for one canonical NHI inventory record. The event log retains the
// attributed reason and every prior decision; this row answers only who owns
// the asset now.
type OwnershipAssignment struct {
	TenantID      string
	InventoryID   string
	Source        string
	OwnerID       string
	AssignedAt    time.Time
	SourceEventID string
	LastEventSeq  uint64
}

// ListOwnershipAssignments returns every current asset override for one tenant.
func (s *Store) ListOwnershipAssignments(ctx context.Context, tenantID string) ([]OwnershipAssignment, error) {
	out := []OwnershipAssignment{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT tenant_id::text, inventory_id, source, owner_id::text,
			       assigned_at, source_event_id::text, last_event_seq
			  FROM ownership_assignments
			 WHERE tenant_id = $1
			 ORDER BY inventory_id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item OwnershipAssignment
			var sequence int64
			if err := rows.Scan(&item.TenantID, &item.InventoryID, &item.Source, &item.OwnerID,
				&item.AssignedAt, &item.SourceEventID, &sequence); err != nil {
				return err
			}
			if sequence < 0 {
				return fmt.Errorf("store: ownership assignment %s has a negative event sequence", item.InventoryID)
			}
			item.LastEventSeq = uint64(sequence)
			out = append(out, item)
		}
		return rows.Err()
	})
	return out, err
}

// ApplyOwnershipAssignmentTx projects one ownership.assigned event item. For
// identity and certificate inventory, it also updates the native read model in
// this same tenant-scoped projection transaction so lifecycle admission and the
// browser cannot disagree about the effective owner.
func (s *Store) ApplyOwnershipAssignmentTx(ctx context.Context, tx pgx.Tx, item OwnershipAssignment) error {
	sequence := int64(item.LastEventSeq) // #nosec G115 -- event sequences fit PostgreSQL bigint
	tag, err := tx.Exec(ctx, `
		INSERT INTO ownership_assignments
		       (tenant_id, inventory_id, source, owner_id, assigned_at, source_event_id, last_event_seq)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, inventory_id) DO UPDATE
		   SET source = EXCLUDED.source,
		       owner_id = EXCLUDED.owner_id,
		       assigned_at = EXCLUDED.assigned_at,
		       source_event_id = EXCLUDED.source_event_id,
		       last_event_seq = EXCLUDED.last_event_seq
		 WHERE ownership_assignments.last_event_seq < EXCLUDED.last_event_seq`,
		item.TenantID, item.InventoryID, item.Source, item.OwnerID, item.AssignedAt, item.SourceEventID, sequence)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var currentOwner, currentEvent string
		var currentSequence int64
		err := tx.QueryRow(ctx, `
			SELECT owner_id::text, source_event_id::text, last_event_seq
			  FROM ownership_assignments
			 WHERE tenant_id = $1 AND inventory_id = $2`, item.TenantID, item.InventoryID).
			Scan(&currentOwner, &currentEvent, &currentSequence)
		if err != nil {
			return err
		}
		if currentSequence == sequence && (currentOwner != item.OwnerID || currentEvent != item.SourceEventID) {
			return fmt.Errorf("store: ownership assignment %s collides at event sequence %d", item.InventoryID, sequence)
		}
		return nil
	}

	ref, ok := strings.CutPrefix(item.InventoryID, "identity/")
	if ok {
		if ref == "" {
			return fmt.Errorf("store: ownership assignment has an empty identity reference")
		}
		native, err := tx.Exec(ctx, `UPDATE identities SET owner_id = $3 WHERE tenant_id = $1 AND id = $2`, item.TenantID, ref, item.OwnerID)
		if err != nil {
			return err
		}
		if native.RowsAffected() != 1 {
			return fmt.Errorf("store: ownership assignment identity %s disappeared before projection", ref)
		}
		return nil
	}
	ref, ok = strings.CutPrefix(item.InventoryID, "certificate/")
	if ok {
		if ref == "" {
			return fmt.Errorf("store: ownership assignment has an empty certificate reference")
		}
		native, err := tx.Exec(ctx, `UPDATE certificates SET owner_id = $3 WHERE tenant_id = $1 AND id = $2`, item.TenantID, ref, item.OwnerID)
		if err != nil {
			return err
		}
		if native.RowsAffected() != 1 {
			return fmt.Errorf("store: ownership assignment certificate %s disappeared before projection", ref)
		}
	}
	return nil
}
