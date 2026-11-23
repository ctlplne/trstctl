// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// RebuildFullRestorePartial prepares only the tenant/key and secret-sync graph
// needed to associate the paired PostgreSQL artifact. The full command and
// attached projection replay remains deferred until independent epochs and
// receiver authority have been imported. The checkpoint stays at zero, so a
// crash cannot make this partial view look like a finished read model.
func (p *Projector) RebuildFullRestorePartial(ctx context.Context, log *events.Log, marker store.RestoreMarker) error {
	return p.store.WithFullRestoreOwner(ctx, marker, func(ownerCtx context.Context) error {
		return p.store.WithGlobalKeyStateAdmission(ownerCtx, store.KeyStateShared, func(admitted context.Context) error {
			return p.store.WithPrivacyReadModelReplacementBarrier(admitted, func(barrierCtx context.Context) error {
				return p.withErasedHistory(barrierCtx, log, func(readCtx context.Context) error {
					return log.WithHistoryRead(readCtx, func(historyCtx context.Context) error {
						head, err := projectionHistoryHead(historyCtx, log)
						if err != nil {
							return err
						}
						return p.store.RebuildReadModelWithKeyStateContextTx(historyCtx, nil,
							func(rebuildCtx context.Context, tx pgx.Tx) error {
								if err := p.store.ResetProjectionCheckpointTx(rebuildCtx, tx); err != nil {
									return err
								}
								return replayProjectionThrough(rebuildCtx, log, 0, head, func(e events.Event) error {
									if e.Type == EventApplicationSecretRotated && schemaVersionOf(e) == ApplicationSecretMutationSchemaVersion {
										var payload ApplicationSecretMutation
										if err := decode(e, &payload); err != nil {
											return err
										}
										if payload.Sync != nil {
											if payload.Action != "rotate" || payload.Surface != "rotation" {
												return fmt.Errorf("projections: invalid embedded sync during partial restore")
											}
											if _, _, _, err := applicationSecretApprovalBinding(payload, false); err != nil {
												return err
											}
											eventHash, err := recoveryEventSHA256(e)
											if err != nil {
												return err
											}
											if err := p.store.SetTenantGUCTx(rebuildCtx, tx, e.TenantID); err != nil {
												return err
											}
											return p.applyEmbeddedApplicationSecretSyncTx(rebuildCtx, tx, e, payload, eventHash)
										}
									}
									if !fullRestorePartialEvent(e.Type) {
										return ValidateSchemaVersion(e)
									}
									if err := p.applyForRebuild(rebuildCtx, tx, e); err != nil {
										return fmt.Errorf("projections: partial full restore apply %s event %s at sequence %d: %w",
											e.Type, e.ID, e.Sequence, err)
									}
									return nil
								})
							})
					})
				})
			})
		})
	})
}

func fullRestorePartialEvent(eventType string) bool {
	switch eventType {
	case EventTenantRegistered, EventTenantOffboarded,
		EventSecretSyncQueued, EventSecretSyncDelivered,
		EventSecretSyncFailed, EventSecretSyncReceiverSettled:
		return true
	default:
		return isTenantKeyDomainHistoryEvent(eventType)
	}
}
