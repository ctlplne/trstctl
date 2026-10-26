// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func transitFactEvent(id, typ string, version int, seq uint64, data string) events.Event {
	return events.Event{
		ID: id, Type: typ, TenantID: tenantA, Sequence: seq, SchemaVersion: version,
		Time: time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC), Data: []byte(data),
	}
}

// A126: a schema-2 transit lifecycle fact projects once under its fact ID; the
// schema-1 audit record projects nothing; and a fact whose event, ID, kind or
// version does not hold together is refused.
func TestTransitKeyFactsProjectFromTheirEvents(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	p := projections.New(s)
	const created = "tf-0123456789abcdef0123456789abcdef"
	const rotated = "tf-fedcba9876543210fedcba9876543210"

	if err := p.Apply(ctx, transitFactEvent("legacy-audit", projections.EventTransitKeyCreated, 1, 9, `{"key":"orders"}`)); err != nil {
		t.Fatalf("a schema-1 audit record: %v", err)
	}
	for _, e := range []events.Event{
		transitFactEvent(created, projections.EventTransitKeyCreated, 2, 10, `{"key":"orders","kind":"aead","version":1}`),
		transitFactEvent(rotated, projections.EventTransitKeyRotated, 2, 11, `{"key":"orders","kind":"aead","version":2}`),
		transitFactEvent(created, projections.EventTransitKeyCreated, 2, 10, `{"key":"orders","kind":"aead","version":1}`),
	} {
		if err := p.Apply(ctx, e); err != nil {
			t.Fatalf("apply %s v%d: %v", e.Type, e.SchemaVersion, err)
		}
	}
	got, err := s.TransitKeyFactsRecorded(ctx, tenantA, []string{created, rotated, "legacy-audit"})
	if err != nil || len(got) != 2 {
		t.Fatalf("recorded facts = %v, %v; want the two schema-2 facts", got, err)
	}

	for name, e := range map[string]events.Event{
		"rotation at version 1": transitFactEvent("tf-11111111111111111111111111111111", projections.EventTransitKeyRotated, 2, 12, `{"key":"k","kind":"hmac","version":1}`),
		"creation at version 3": transitFactEvent("tf-22222222222222222222222222222222", projections.EventTransitKeyCreated, 2, 13, `{"key":"k","kind":"hmac","version":3}`),
		"not a fact ID":         transitFactEvent("event-1", projections.EventTransitKeyCreated, 2, 14, `{"key":"k","kind":"hmac","version":1}`),
		"unknown kind":          transitFactEvent("tf-33333333333333333333333333333333", projections.EventTransitKeyCreated, 2, 15, `{"key":"k","kind":"rsa","version":1}`),
		"no key":                transitFactEvent("tf-44444444444444444444444444444444", projections.EventTransitKeyCreated, 2, 16, `{"key":"","kind":"hmac","version":1}`),
	} {
		if err := p.Apply(ctx, e); err == nil {
			t.Errorf("%s was projected", name)
		}
	}
	future := transitFactEvent("tf-55555555555555555555555555555555", projections.EventTransitKeyCreated, 3, 17, `{"key":"k","kind":"hmac","version":1}`)
	if err := p.Apply(ctx, future); !errors.Is(err, projections.ErrUnknownSchemaVersion) {
		t.Fatalf("a schema-3 fact = %v, want ErrUnknownSchemaVersion", err)
	}
}
