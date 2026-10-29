// SPDX-License-Identifier: BUSL-1.1

package eventprivacy_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

type administrativeScopeGuard struct{ tenant string }

func (guard *administrativeScopeGuard) WithTenantEventProtection(ctx context.Context, tenant string, visit func(context.Context) error) error {
	guard.tenant = tenant
	return visit(ctx)
}

func TestSourceAdmissionPreservesOnlyKnownAdministrativeScope(t *testing.T) {
	guard := &administrativeScopeGuard{}
	admission := eventprivacy.SourceAdmission{Guard: guard}
	// No tenant key/provider exists for this historical deployment partition.
	// Its allowlist predates this feature; no general non-UUID bypass is valid.
	for _, kind := range []string{"provider.isolation.drill", "audit.archived"} {
		event := events.Event{TenantID: events.LegacyProviderGlobalAuditScope, Type: kind, SchemaVersion: 1}
		if err := admission.WithTenantEventProtection(t.Context(), event.TenantID, func(ctx context.Context) error {
			decision, err := admission.EventProtectionFor(ctx, event)
			if err != nil || decision.Mode != events.EventProtectionLegacy {
				t.Fatalf("known administrative audit lost compatibility: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		mapped, err := store.AuditCheckpointRLSID(events.LegacyProviderGlobalAuditScope)
		if err != nil || guard.tenant != mapped {
			t.Fatal("legacy scope did not use its existing isolated UUID fence")
		}
	}
	for _, event := range []events.Event{
		{TenantID: events.LegacyProviderGlobalAuditScope, Type: "identity.issued", SchemaVersion: 1},
		{TenantID: events.LegacyProviderGlobalAuditScope, Type: "provider.future.state_changed", SchemaVersion: 1},
		{TenantID: "arbitrary-text-scope", Type: "provider.isolation.drill", SchemaVersion: 1},
		{TenantID: events.LegacyProviderGlobalAuditScope, Type: "provider.isolation.drill", SchemaVersion: 999},
		{TenantID: events.LegacyProviderGlobalAuditScope, Type: "audit.archived", SchemaVersion: 1, SensitiveErased: true},
	} {
		if _, err := admission.EventProtectionFor(t.Context(), event); !errors.Is(err, eventprivacy.ErrSource) {
			t.Fatalf("unknown administrative authority became plaintext: %+v %v", event, err)
		}
	}
}
