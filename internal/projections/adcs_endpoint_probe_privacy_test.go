// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"encoding/json"
	"testing"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestADCSEndpointProbeDoesNotWidenHistoricalShapes(t *testing.T) {
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	tenant := "11111111-1111-4111-8111-111111111111"
	queued := []byte(`{"id":"run","source_id":"source","job_kind":"adcs.inventory.endpoint_probe","dry_run":false,"execution":"relay","required_agent_role":"network","endpoint_probe":{"enabled":true,"dns_suffixes":["example"]},"previous_probe_page":{"plan_digest":"digest","next_offset":24}}`)
	for _, version := range []int{1, 2, 3} {
		_, err := log.Append(t.Context(), events.Event{Type: EventDiscoveryRunQueued, TenantID: tenant, SchemaVersion: version, Data: queued})
		if (err == nil) != (version == 3) {
			t.Fatalf("probe command v%d accepted=%t: %v", version, err == nil, err)
		}
	}
	payload := map[string]any{"run_id": "run", "source_id": "source", "domain": "domain", "agent_id": "agent", "agent_name": "relay", "directory_verified": true, "templates": []any{}, "enrollment_services": []any{map[string]any{"name": "CA", "agent_restrictions": map[string]any{"state": "unobserved", "source": "fixture"}, "endpoint_probe": map[string]any{"state": "not_in_page", "plan_digest": "digest", "total_targets": 40, "offset": 24, "next_offset": 0, "targets_on_page": 0, "complete": false}}}, "findings": []any{}}
	wire, _ := json.Marshal(payload)
	for _, version := range []int{1, 2, 3, 4} {
		_, err := log.Append(t.Context(), events.Event{Type: EventADCSInventoryObserved, TenantID: tenant, SchemaVersion: version, Data: wire})
		if (err == nil) != (version == 4) {
			t.Fatalf("probe observation v%d accepted=%t: %v", version, err == nil, err)
		}
	}
}
