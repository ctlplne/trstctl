// SPDX-License-Identifier: BUSL-1.1
package eventprivacy

import (
	"testing"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestLifetimeFoldUsesExactFiniteCutBeforeLaterMalformedControl(t *testing.T) {
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	const tenant = "6c5d311d-a317-4520-8646-e416aa7f6064"
	for _, event := range []events.Event{
		{ID: "finite-old-registration", Type: eventRegistered, Data: []byte(`{"name":"old"}`)},
		{ID: "finite-offboard", Type: eventOffboarded, Data: []byte(`{"rows_deleted":0}`)},
		{ID: "finite-current-registration", Type: eventRegistered, Data: []byte(`{"name":"new"}`)},
		{ID: "finite-malformed-control", Type: EventRequested, Data: []byte(`{"invalid":true}`)},
	} {
		event.TenantID = tenant
		if _, err := log.Append(t.Context(), event); err != nil {
			t.Fatal(err)
		}
	}
	policy := SourcePolicy{Log: log}
	var atTwo []Lifetime
	if err := policy.replayLifetimesThrough(t.Context(), tenant, 2, func(life Lifetime) error { atTwo = append(atTwo, life); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(atTwo) != 1 || atTwo[0].Registration.ID != "finite-old-registration" || atTwo[0].Offboard == nil || atTwo[0].Offboard.Sequence != 2 {
		t.Fatal("finite fold consumed later lifetime")
	}
	var atThree []Lifetime
	if err := policy.replayLifetimesThrough(t.Context(), tenant, 3, func(life Lifetime) error { atThree = append(atThree, life); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(atThree) != 2 || atThree[1].Registration.Sequence != 3 || atThree[1].Offboard != nil {
		t.Fatal("finite fold lost later live registration")
	}
	called := false
	if err := policy.replayLifetimes(t.Context(), tenant, func(Lifetime) error { called = true; return nil }); err == nil || called {
		t.Fatal("full fold published partial authority before malformed control")
	}
}
