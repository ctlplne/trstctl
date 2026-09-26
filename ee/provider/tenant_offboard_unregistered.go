// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	corestore "trstctl.com/trstctl/internal/store"
)

// Provider provisioning precedes enrollment. Removing that metadata does not
// invent a core tenant lifecycle. Check the complete core table inventory under
// the registration fence; unexpected workload data requires a real erasure, not
// a metadata-only success. Only the four views owned by this projection may be
// present. Recheck at completion because enrollment could win between phases.
func (o *TenantOffboarder) withUnregisteredCustomer(ctx context.Context, tenantID string, fn func(context.Context, pgx.Tx) error) error {
	err := o.log.WithHistoryRead(ctx, func(ctx context.Context) error {
		return o.store.WithTenantRegistrationFence(ctx, tenantID, func(tx pgx.Tx) error {
			for _, table := range corestore.TenantScopedTables {
				switch table {
				case "provider_tenants", "provider_breakglass_grants", "provider_tenant_quotas", "tenant_branding":
					continue
				}
				var exists bool
				if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM "+pgx.Identifier{table}.Sanitize()+" WHERE tenant_id=$1)", tenantID).Scan(&exists); err != nil {
					return err
				}
				if exists {
					return fmt.Errorf("%w: customer has core data; metadata-only offboarding is unavailable", ErrTenantStateConflict)
				}
			}
			if fn != nil {
				return fn(ctx, tx)
			}
			return nil
		})
	})
	if err == nil || errors.Is(err, ErrTenantStateConflict) || errors.Is(err, ErrMutationConflict) {
		return err
	}
	return fmt.Errorf("%w: complete unregistered customer offboarding: %v", ErrMutationPersistence, err)
}

func (o *TenantOffboarder) completeUnregistered(ctx context.Context, requested events.Event, request AuthorityEvent, now time.Time) error {
	// The completion ID is outside the UUID namespace of client-selected keys.
	// A prior result is recovered before inspecting current rows: it must never
	// erase a later provisioning or registration that reused the same UUID.
	id := "provider-unregistered-offboard-" + requested.ID
	canonical, found, err := o.log.EventByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%w: read metadata offboard result: %v", ErrMutationPersistence, err)
	}
	if found {
		now = canonical.Time
	}
	completion := request
	tenant := *request.Tenant
	tenant.Status, tenant.UpdatedAt = TenantOffboarded, now
	completion.Tenant = &tenant
	completion.EffectiveAt = now
	completion.Audit.Type, completion.Audit.At = AuditUnregisteredTenantOffboarded, now
	data, err := json.Marshal(completion)
	if err != nil {
		return err
	}
	if found {
		if canonical.Type != AuditUnregisteredTenantOffboarded || canonical.TenantID != requested.TenantID ||
			canonical.SchemaVersion != events.DefaultSchemaVersion || !bytes.Equal(canonical.Data, data) {
			return ErrMutationConflict
		}
		if err := o.mutations.projection.Apply(ctx, canonical); err != nil {
			return fmt.Errorf("%w: recover metadata offboard result: %v", ErrMutationPersistence, err)
		}
		return nil
	}
	current, err := NewPGStore(o.store).Tenant(ctx, requested.TenantID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrTenantStateConflict
		}
		return fmt.Errorf("%w: read pending customer offboard: %v", ErrMutationPersistence, err)
	}
	if current.Status != TenantOffboarding ||
		!current.CreatedAt.Equal(request.Tenant.CreatedAt.Truncate(time.Microsecond)) ||
		!current.UpdatedAt.Equal(request.Tenant.UpdatedAt.Truncate(time.Microsecond)) {
		return ErrTenantStateConflict
	}
	return o.withUnregisteredCustomer(ctx, requested.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		actor := request.Erasure.Actor
		canonical, err := o.log.Append(ctx, events.Event{ID: id, Type: AuditUnregisteredTenantOffboarded,
			TenantID: requested.TenantID, Time: now, SchemaVersion: events.DefaultSchemaVersion, Actor: &actor, Data: data})
		if err != nil {
			return err
		}
		// Append may outlive SQL. The exact source completion and the standard
		// ordered receipts make a crash retry safe without repeating admission.
		if canonical.ID != id || canonical.Type != AuditUnregisteredTenantOffboarded ||
			canonical.TenantID != requested.TenantID || !bytes.Equal(canonical.Data, data) {
			return ErrMutationConflict
		}
		return o.mutations.projection.ApplyTx(ctx, tx, canonical)
	})
}
