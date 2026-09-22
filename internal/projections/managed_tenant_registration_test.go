// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func managedRegistrationFixture() map[string]any {
	return map[string]any{
		"name": "Hosted tenant",
		"managed_offering": map[string]any{
			"enabled": true, "deployment_model": "managed_provider",
			"provider_tenant_id": "provider-tenant", "provisioned_at": "2026-09-22T00:00:00Z",
		},
	}
}

func TestManagedTenantRegistrationPrivacyShapesRemainClosed(t *testing.T) {
	ctx := context.Background()
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	tests := []struct {
		name   string
		change func(map[string]any)
		valid  bool
	}{
		{"managed minimal", func(map[string]any) {}, true},
		{"ordinary registration", func(p map[string]any) { delete(p, "managed_offering") }, true},
		{"managed complete", func(p map[string]any) {
			m := p["managed_offering"].(map[string]any)
			for _, key := range []string{"region", "data_residency", "plan", "support_tier", "slo_tier", "provisioned_by"} {
				m[key] = "test-value"
			}
		}, true},
		{"unknown root", func(p map[string]any) { p["unexpected"] = "value" }, false},
		{"unknown nested", func(p map[string]any) { p["managed_offering"].(map[string]any)["unexpected"] = "value" }, false},
		{"missing name", func(p map[string]any) { delete(p, "name") }, false},
		{"null metadata", func(p map[string]any) { p["managed_offering"] = nil }, false},
		{"array metadata", func(p map[string]any) { p["managed_offering"] = []any{} }, false},
		{"wrong enabled kind", func(p map[string]any) { p["managed_offering"].(map[string]any)["enabled"] = "true" }, false},
		{"wrong provider kind", func(p map[string]any) { p["managed_offering"].(map[string]any)["provider_tenant_id"] = 42 }, false},
	}
	for _, key := range []string{"enabled", "deployment_model", "provider_tenant_id", "provisioned_at"} {
		tests = append(tests, struct {
			name   string
			change func(map[string]any)
			valid  bool
		}{"missing " + key, func(p map[string]any) { delete(p["managed_offering"].(map[string]any), key) }, false})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := managedRegistrationFixture()
			tt.change(payload)
			data, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			_, err = log.Append(ctx, events.Event{Type: EventTenantRegistered, TenantID: "33333333-3333-4333-8333-333333333333", SchemaVersion: 1, Data: data})
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%t err=%v", tt.valid, err)
			}
		})
	}
	var recorded int
	if err := log.Replay(ctx, 0, func(events.Event) error { recorded++; return nil }); err != nil {
		t.Fatal(err)
	}
	if recorded != 3 {
		t.Fatalf("recorded %d events, want exactly the three accepted variants", recorded)
	}
}

func TestManagedTenantRegistrationStillRejectsUnauthorizedSubjectRewrite(t *testing.T) {
	for _, field := range []string{"name", "provisioned_by", "region"} {
		t.Run(field, func(t *testing.T) {
			payload := managedRegistrationFixture()
			if field == "name" {
				payload[field] = "erased-subject"
			} else {
				payload["managed_offering"].(map[string]any)[field] = "erased-subject"
			}
			data, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := events.PseudonymizeEventDataForSubject(data, "hosted-tenant", "erased-subject", EventTenantRegistered, 1); err == nil || !strings.Contains(err.Error(), "rejects subject-bearing") {
				t.Fatalf("unauthorized rewrite must fail closed: %v", err)
			}
		})
	}
}
