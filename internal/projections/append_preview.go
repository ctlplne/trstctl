// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

var errAppendPreviewRolledBack = errors.New("projections: append preview rolled back")

// ValidateAppendCandidate runs an ordinary tenant read-model projection in a
// transaction that always rolls back. The producer receives a projection
// refusal before its event can be published. Tenant lifecycle, custody, and
// audit checkpoint events retain their dedicated admission paths.
func ValidateAppendCandidate(ctx context.Context, st *store.Store, event events.Event) error {
	if err := ValidateSchemaVersion(event); err != nil {
		return err
	}
	if st == nil {
		return errors.New("projections: append preview requires a store")
	}
	if isTenantLifecycleEventType(event.Type) || isKeyStateMutationEventType(event.Type) ||
		event.Type == audit.EventTypeArchived || events.IsLegacyProviderGlobalAudit(event) ||
		uuid.Validate(event.TenantID) != nil {
		return nil
	}
	preview := event
	preview.Sequence = 1 << 61
	projector := New(st)
	apply := func(tx pgx.Tx) error {
		if err := projector.applyCoreEventTx(ctx, tx, preview); err != nil {
			return err
		}
		return errAppendPreviewRolledBack
	}
	var err error
	if event.Type == EventSecretSyncDelivered || event.Type == EventSecretSyncFailed ||
		event.Type == EventSecretSyncReceiverSettled || event.Type == EventSecretRotationScheduleRan {
		err = st.WithTenantProjection(ctx, event.TenantID, apply)
	} else {
		err = st.WithTenant(ctx, event.TenantID, apply)
	}
	if errors.Is(err, errAppendPreviewRolledBack) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("projections: append preview %s: %w", event.Type, err)
	}
	return errors.New("projections: append preview committed unexpectedly")
}
