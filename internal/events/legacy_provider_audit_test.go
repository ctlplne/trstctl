// SPDX-License-Identifier: BUSL-1.1

package events_test

import (
	"testing"

	"trstctl.com/trstctl/internal/events"
)

func TestLegacyProviderConsumersDistinguishAuditOnlyAndCheckpointEvents(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		event       events.Event
		outboxNoop  bool
		projectNoop bool
	}{
		{"historical Provider audit", events.Event{TenantID: "provider-control-plane", Type: "provider.isolation.drill"}, true, true},
		{"legacy archive checkpoint", events.Event{TenantID: "provider-control-plane", Type: "audit.archived"}, true, false},
		{"unknown legacy scope event", events.Event{TenantID: "provider-control-plane", Type: "identity.issued"}, false, false},
		{"unknown future Provider event", events.Event{TenantID: "provider-control-plane", Type: "provider.future.state_changed"}, false, false},
		{"ordinary tenant archive", events.Event{TenantID: "11111111-1111-1111-1111-111111111111", Type: "audit.archived"}, false, false},
		{"ordinary tenant Provider event", events.Event{TenantID: "11111111-1111-1111-1111-111111111111", Type: "provider.isolation.drill"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := events.IsLegacyProviderGlobalAudit(tc.event); got != tc.outboxNoop {
				t.Fatalf("outbox no-op = %v, want %v", got, tc.outboxNoop)
			}
			if got := events.IsLegacyProviderCoreProjectionNoop(tc.event); got != tc.projectNoop {
				t.Fatalf("projection no-op = %v, want %v", got, tc.projectNoop)
			}
		})
	}
}
