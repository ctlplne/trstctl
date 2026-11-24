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

func TestCR143ReservedProviderAuthorityGetsOnlyKnownPublicControlEvents(t *testing.T) {
	if events.ProviderAuthorityTenantID != store.ZeroUUID {
		t.Fatal("event admission and PostgreSQL disagree about the reserved Provider partition")
	}
	guard := &administrativeScopeGuard{}
	admission := eventprivacy.SourceAdmission{Guard: guard}
	for _, kind := range []string{"provider.operator.upserted", "provider.operator.offboarded", "provider.operator.role_revoked",
		"provider.role.upserted", "provider.role.deleted", "provider.template.recorded", "provider.isolation.drill"} {
		event := events.Event{TenantID: store.ZeroUUID, Type: kind, SchemaVersion: 1}
		if err := admission.WithTenantEventProtection(t.Context(), event.TenantID, func(ctx context.Context) error {
			decision, err := admission.EventProtectionFor(ctx, event)
			if err != nil || decision.Mode != events.EventProtectionPublicControl {
				t.Fatalf("provider authority %s was refused: decision=%+v err=%v", kind, decision, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if guard.tenant != store.ZeroUUID {
			t.Fatalf("provider authority guard used %q, want its isolated UUID", guard.tenant)
		}
	}
	for _, event := range []events.Event{
		{TenantID: store.ZeroUUID, Type: "identity.issued", SchemaVersion: 1},
		{TenantID: store.ZeroUUID, Type: "provider.future.state_changed", SchemaVersion: 1},
		{TenantID: store.ZeroUUID, Type: "provider.operator.offboarded", SchemaVersion: 2},
		{TenantID: store.ZeroUUID, Type: "provider.operator.offboarded", SchemaVersion: 1, SensitiveErased: true},
	} {
		if _, err := admission.EventProtectionFor(t.Context(), event); !errors.Is(err, eventprivacy.ErrSource) {
			t.Fatalf("unrecognized or altered provider event became public control: %+v %v", event, err)
		}
	}
}
