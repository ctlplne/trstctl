// SPDX-License-Identifier: BUSL-1.1

package revoke

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestIntervalExceedanceIndexedReadSurvivesColdRestart(t *testing.T) {
	ctx := t.Context()
	const tenant = "11111111-1111-4111-8111-111111111111"
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := events.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := log.Close(); err != nil {
			t.Error(err)
		}
	}()
	appendFact := func(tenantID, eventType string, data []byte) {
		t.Helper()
		if _, err := log.Append(ctx, events.Event{TenantID: tenantID, Type: eventType, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	payload, err := json.Marshal(IntervalExceededPayload{DirectiveID: "directive-a"})
	if err != nil {
		t.Fatal(err)
	}
	appendFact(tenant, "unrelated.event", []byte(`{}`))
	appendFact("22222222-2222-4222-8222-222222222222", TypeRevocationIntervalExceeded, payload)
	monitor := &IntervalMonitor{log: log}
	if found, err := monitor.exceedanceRecorded(ctx, tenant, "directive-a"); err != nil || found {
		t.Fatalf("cross-tenant exceedance found=%v err=%v", found, err)
	}
	appendFact(tenant, TypeRevocationIntervalExceeded, []byte(`{`)) // malformed prior fact names no directive
	appendFact(tenant, TypeRevocationIntervalExceeded, payload)
	for _, directiveID := range []string{"directive-a", "directive-b"} {
		found, err := monitor.exceedanceRecorded(ctx, tenant, directiveID)
		if err != nil || found != (directiveID == "directive-a") {
			t.Fatalf("indexed exceedance %s found=%v err=%v", directiveID, found, err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = events.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	monitor.log = log
	if found, err := monitor.exceedanceRecorded(ctx, tenant, "directive-a"); err != nil || !found {
		t.Fatalf("cold indexed exceedance found=%v err=%v", found, err)
	}
}
