// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A126: a projected transit lifecycle fact is kept once per fact ID (a replay
// changes nothing), reads back by ID only for its own tenant, and the table
// refuses a fact whose event does not match its version.
func TestTransitKeyFactsProjectOncePerFactAndStayWithTheirTenant(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	const tenantA = "a1260000-0000-4000-8000-000000000001"
	const tenantB = "b1260000-0000-4000-8000-000000000002"
	seedTenant(t, s, tenantA)
	seedTenant(t, s, tenantB)
	at := time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	created := store.TransitKeyFact{
		TenantID: tenantA, FactID: "tf-0123456789abcdef0123456789abcdef", KeyName: "orders", Kind: "aead",
		Version: 1, EventType: "transit.key.created", EventSeq: 41, RecordedAt: at,
	}
	apply := func(tenantID string, f store.TransitKeyFact) error {
		return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error { return s.ApplyTransitKeyFactTx(ctx, tx, f) })
	}
	if err := apply(tenantA, created); err != nil {
		t.Fatalf("project the fact: %v", err)
	}
	replay := created
	replay.KeyName, replay.EventSeq, replay.RecordedAt = "renamed-in-a-replay", 99, at.Add(time.Hour)
	if err := apply(tenantA, replay); err != nil {
		t.Fatalf("replay the fact: %v", err)
	}
	got, err := s.TransitKeyFactsRecorded(ctx, tenantA, []string{created.FactID, "tf-ffffffffffffffffffffffffffffffff"})
	if err != nil || len(got) != 1 || !got[created.FactID].Equal(at) {
		t.Fatalf("recorded facts = %v, %v; want the first projection kept", got, err)
	}
	if got, err := s.TransitKeyFactsRecorded(ctx, tenantB, []string{created.FactID}); err != nil || len(got) != 0 {
		t.Fatalf("tenant B sees tenant A's fact: %v, %v", got, err)
	}
	for name, bad := range map[string]store.TransitKeyFact{
		"rotation at version 1": {TenantID: tenantA, FactID: "tf-11111111111111111111111111111111", KeyName: "k", Kind: "hmac", Version: 1, EventType: "transit.key.rotated", EventSeq: 42, RecordedAt: at},
		"creation at version 2": {TenantID: tenantA, FactID: "tf-22222222222222222222222222222222", KeyName: "k", Kind: "hmac", Version: 2, EventType: "transit.key.created", EventSeq: 43, RecordedAt: at},
		"malformed fact ID":     {TenantID: tenantA, FactID: "fact-1", KeyName: "k", Kind: "hmac", Version: 1, EventType: "transit.key.created", EventSeq: 44, RecordedAt: at},
		"unknown kind":          {TenantID: tenantA, FactID: "tf-33333333333333333333333333333333", KeyName: "k", Kind: "rsa", Version: 1, EventType: "transit.key.created", EventSeq: 45, RecordedAt: at},
		"no stream sequence":    {TenantID: tenantA, FactID: "tf-44444444444444444444444444444444", KeyName: "k", Kind: "hmac", Version: 1, EventType: "transit.key.created", RecordedAt: at},
	} {
		if err := apply(tenantA, bad); err == nil {
			t.Errorf("%s was projected", name)
		}
	}
	if got, err := s.TransitKeyFactsRecorded(ctx, tenantA, nil); err != nil || len(got) != 0 {
		t.Fatalf("no fact IDs = %v, %v", got, err)
	}
}
