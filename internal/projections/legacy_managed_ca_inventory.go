// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/events"
)

var errLegacyManagedCAInventoryRebuild = errors.New("legacy managed CA inventory needs rebuild")

// An older projector completed v2 managed leaf events in the responder ledger
// without recording their retained public certificates in inventory. Inspect
// only history already covered by the SQL projection checkpoint. The separate
// recovery cursor makes the first upgrade a full check and later boots a delta
// check, including events an older binary projected after a rollback.
func (p *Projector) legacyManagedCAInventoryNeedsRebuild(ctx context.Context, log *events.Log) (bool, error) {
	var needsRebuild bool
	err := log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		applied, checked, err := p.store.LegacyManagedCAInventoryRecoveryCursor(readCtx)
		if err != nil {
			return err
		}
		head, err := log.LastSequence(readCtx)
		if err != nil {
			return err
		}
		if applied > head {
			return fmt.Errorf("projections: managed CA recovery checkpoint %d beyond history head %d", applied, head)
		}
		from := checked + 1
		if checked > applied {
			from = 1 // restored older snapshot or rewritten history
		}
		if from > applied {
			return nil
		}
		tenants, err := p.store.ListTenants(readCtx)
		if err != nil {
			return err
		}
		registeredAt := make(map[string]uint64, len(tenants))
		for _, tenant := range tenants {
			registeredAt[tenant.TenantID] = tenant.EventSeq
		}
		err = log.ReplayThrough(readCtx, from, applied, func(e events.Event) error {
			registration, live := registeredAt[e.TenantID]
			if !live || e.Sequence < registration || e.Type != EventCAEndEntityIssued ||
				schemaVersionOf(e) != CAIssuedCertificateEvidenceSchemaVersion {
				return nil
			}
			managed, err := LegacyManagedCALeafEvidence(e)
			if err != nil || !managed {
				return err
			}
			projected, err := p.store.LegacyManagedCAInventoryEventProjected(readCtx, e)
			if err != nil {
				return err
			}
			if !projected {
				needsRebuild = true
				return errLegacyManagedCAInventoryRebuild
			}
			return nil
		})
		if errors.Is(err, errLegacyManagedCAInventoryRebuild) {
			return nil
		}
		if err != nil {
			return err
		}
		return p.store.MarkLegacyManagedCAInventoryCheckedThrough(readCtx, applied)
	})
	return needsRebuild, err
}
