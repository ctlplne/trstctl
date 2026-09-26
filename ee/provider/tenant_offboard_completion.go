// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/events"
)

const erasureCompletionPrefix = "provider-offboard-completed-"

// This witness is appended only after the core command (or metadata-only
// transaction) has returned verified completion. The earlier erase event can
// precede SQL commit and is not itself proof that deletion finished. Retrying
// after losing this witness first re-verifies the same registration-bound erase.
// Its projection records a receipt only; it never changes a newer customer.
func (o *TenantOffboarder) recordErasureCompletion(ctx context.Context, requested events.Event, request AuthorityEvent, now time.Time) error {
	id := erasureCompletionPrefix + requested.ID
	canonical, found, err := o.log.EventByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%w: inspect deletion completion: %v", ErrMutationPersistence, err)
	}
	if found {
		now = canonical.Time
	}
	completion := request
	tenant := *request.Tenant
	tenant.Status, tenant.UpdatedAt = TenantOffboarded, now
	completion.Tenant, completion.EffectiveAt = &tenant, now
	completion.Audit.Type, completion.Audit.At = AuditTenantErasureCompleted, now
	data, err := json.Marshal(completion)
	if err != nil {
		return fmt.Errorf("%w: encode deletion completion: %v", ErrMutationPersistence, err)
	}
	if !found {
		actor := request.Erasure.Actor
		canonical, err = o.log.Append(ctx, events.Event{ID: id, Type: AuditTenantErasureCompleted,
			TenantID: requested.TenantID, Time: now, SchemaVersion: events.DefaultSchemaVersion, Actor: &actor, Data: data})
		if err != nil {
			return fmt.Errorf("%w: retain deletion completion: %v", ErrMutationPersistence, err)
		}
	}
	if canonical.ID != id || canonical.Type != AuditTenantErasureCompleted || canonical.TenantID != requested.TenantID ||
		canonical.SchemaVersion != events.DefaultSchemaVersion || !bytes.Equal(canonical.Data, data) {
		return ErrMutationConflict
	}
	if err := o.mutations.projection.Apply(ctx, canonical); err != nil {
		return fmt.Errorf("%w: project deletion completion: %v", ErrMutationPersistence, err)
	}
	return nil
}
