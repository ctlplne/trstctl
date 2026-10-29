// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"encoding/json"
	"testing"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestADCSMembershipDoesNotWidenHistoricalShapes(t *testing.T) {
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	payload := map[string]any{"run_id": "run", "source_id": "source", "domain": "domain", "agent_id": "agent", "agent_name": "relay", "directory_verified": true, "templates": []any{map[string]any{"name": "Nested", "enrollee_supplies_subject": false, "enrollee_supplies_san": false, "requires_manager_approval": false, "exportable_key": false, "enrollment_membership": map[string]any{"state": "incomplete", "domain_dn": "DC=example", "matching_rule": "1.2.840.113556.1.4.1941", "observed_at": "2026-10-28T00:00:00Z", "trustees": []any{}, "members": []any{}, "limitations": []string{}}}}, "findings": []any{}}
	for _, version := range []int{1, 2, 3} {
		if version >= 2 {
			payload["enrollment_services"] = []any{}
		}
		wire, _ := json.Marshal(payload)
		_, err := log.Append(t.Context(), events.Event{Type: EventADCSInventoryObserved, TenantID: "11111111-1111-4111-8111-111111111111", SchemaVersion: version, Data: wire})
		if (err == nil) != (version == 3) {
			t.Fatalf("nested shape under version %d accepted=%t", version, err == nil)
		}
	}
	queued := []byte(`{"id":"run","source_id":"source","job_kind":"adcs.inventory.enrollment_groups","dry_run":false,"execution":"relay","required_agent_role":"network","nested_groups_enabled":true,"membership_domain_dn":"DC=example"}`)
	for _, version := range []int{1, 2} {
		_, err := log.Append(t.Context(), events.Event{Type: EventDiscoveryRunQueued, TenantID: "11111111-1111-4111-8111-111111111111", SchemaVersion: version, Data: queued})
		if (err == nil) != (version == 2) {
			t.Fatalf("nested command under version %d accepted=%t", version, err == nil)
		}
	}
}
