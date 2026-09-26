// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/events"
)

// A changed registration cannot be erased using the old authorization. Keep
// service denied, but end the pending state so a newly reviewed, separately
// authorized command can bind the current registration. Transient persistence
// errors do not enter this path: their original command remains recoverable.
// The caller holds the Provider authority fence for the entire decision.
func (o *TenantOffboarder) recordErasureConflict(ctx context.Context, requested events.Event, request AuthorityEvent, now time.Time) error {
	id := "provider-offboard-failed-" + requested.ID
	canonical, found, err := o.log.EventByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%w: inspect offboard refusal: %v", ErrMutationPersistence, err)
	}
	if found {
		now = canonical.Time
	} else {
		current, err := NewPGStore(o.store).Tenant(ctx, requested.TenantID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: inspect pending offboard: %v", ErrMutationPersistence, err)
		}
		if current.Status != TenantOffboarding ||
			!current.CreatedAt.Equal(request.Tenant.CreatedAt.Truncate(time.Microsecond)) ||
			!current.UpdatedAt.Equal(request.Tenant.UpdatedAt.Truncate(time.Microsecond)) {
			// A newer command already owns this registry row. Do not roll it
			// back or change its status to explain an older command's refusal.
			return nil
		}
	}
	failure := request
	tenant := *request.Tenant
	tenant.Status, tenant.UpdatedAt = TenantOffboardFailed, now
	failure.Tenant, failure.EffectiveAt = &tenant, now
	failure.Audit.Type, failure.Audit.At = AuditTenantErasureFailed, now
	failure.Audit.Reason = "customer registration changed; review and submit a new offboarding request"
	data, err := json.Marshal(failure)
	if err != nil {
		return fmt.Errorf("%w: encode offboard refusal: %v", ErrMutationPersistence, err)
	}
	if !found {
		actor := request.Erasure.Actor
		canonical, err = o.log.Append(ctx, events.Event{ID: id, Type: AuditTenantErasureFailed,
			TenantID: requested.TenantID, Time: now, SchemaVersion: events.DefaultSchemaVersion, Actor: &actor, Data: data})
		if err != nil {
			return fmt.Errorf("%w: retain offboard refusal: %v", ErrMutationPersistence, err)
		}
	}
	if canonical.ID != id || canonical.Type != AuditTenantErasureFailed || canonical.TenantID != requested.TenantID ||
		canonical.SchemaVersion != events.DefaultSchemaVersion || !bytes.Equal(canonical.Data, data) {
		return ErrMutationConflict
	}
	if err := o.mutations.projection.Apply(ctx, canonical); err != nil {
		return fmt.Errorf("%w: project offboard refusal: %v", ErrMutationPersistence, err)
	}
	return nil
}
