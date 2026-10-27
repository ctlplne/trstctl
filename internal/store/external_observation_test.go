// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A180: observers and their observations project per tenant; an endpoint's
// expectation is what its newest verification expects, with the renewal that
// produced it; rotation events queue once per enabled observer with an events
// URL, converge on replay, and are not resent when old.
func TestExternalObservationsAndObserverEvents(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Microsecond)
	// Fingerprints no other test in this package uses: the database is shared.
	expected, successor := strings.Repeat("8a", 32), strings.Repeat("8b", 32)
	const (
		withEvents    = "18000000-0000-4000-8000-000000000001"
		withoutEvents = "18000000-0000-4000-8000-000000000002"
		disabled      = "18000000-0000-4000-8000-000000000003"
	)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		for i, o := range []store.ExternalObserver{
			{TenantID: tenantA, ID: withEvents, Name: "probectl-eu", EventsURL: "https://probectl.example.test/events", CredentialRef: "secret://observers/eu", Enabled: true},
			{TenantID: tenantA, ID: withoutEvents, Name: "reporter-only", Enabled: true},
			{TenantID: tenantA, ID: disabled, Name: "retired", EventsURL: "https://old.example.test/events", Enabled: false},
		} {
			o.UpdatedAt, o.EventSequence = now, uint64(10+i)
			if err := s.ApplyExternalObserverUpsertedTx(ctx, tx, o); err != nil {
				return err
			}
		}
		if err := s.ApplyEndpointVerificationTx(ctx, tx, store.EndpointVerification{TenantID: tenantA, EndpointID: "edge:443",
			Address: "checkout.example.test:443", Vantage: "relay", Reached: true, ExpectedFingerprint: expected,
			ObservedFingerprint: expected, LastCheckedAt: now, EventSequence: 20}); err != nil {
			return err
		}
		completed := now.Add(-time.Hour)
		return s.ApplyRotationRunRecordedTx(ctx, tx, store.RotationRun{ID: "18000000-0000-4000-8000-0000000000a1", TenantID: tenantA,
			IdentityID: "18000000-0000-4000-8000-0000000000b1", Status: "succeeded", Trigger: "scheduler",
			PredecessorFingerprint: strings.Repeat("8c", 32), SuccessorFingerprint: expected, IdempotencyKey: "a180-run",
			CreatedAt: completed, UpdatedAt: completed, CompletedAt: &completed})
	}); err != nil {
		t.Fatal(err)
	}

	observers, err := s.ListExternalObservers(ctx, tenantA)
	if err != nil || len(observers) != 3 || observers[0].Name != "probectl-eu" {
		t.Fatalf("observers = %+v, %v", observers, err)
	}
	if others, err := s.ListExternalObservers(ctx, tenantB); err != nil || len(others) != 0 {
		t.Fatalf("tenant B sees observers: %+v, %v", others, err)
	}

	expectation, found, err := s.ExpectationForEndpoint(ctx, tenantA, "checkout.example.test:443")
	if err != nil || !found || expectation.Fingerprint != expected || expectation.EndpointID != "edge:443" || expectation.RotatedAt == nil {
		t.Fatalf("expectation = %+v found=%v err=%v", expectation, found, err)
	}
	if _, found, err := s.ExpectationForEndpoint(ctx, tenantA, "unknown.example.test:443"); err != nil || found {
		t.Fatalf("an unknown endpoint has an expectation: %v %v", found, err)
	}

	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyExternalObservationRecordedTx(ctx, tx, store.ExternalObservation{TenantID: tenantA,
			ID: "18000000-0000-4000-8000-0000000000c1", ObserverID: withEvents, Endpoint: "checkout.example.test:443",
			Vantage: "eu-west-1", ObservedAt: now, Reachable: true, Health: "healthy", ServedFingerprint: expected,
			ExpectedFingerprint: expected, Verdict: store.ObservationMatch, RecordedAt: now, EventSequence: 30})
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListExternalObservations(ctx, tenantA, store.ExternalObservationFilter{Fingerprint: expected})
	if err != nil || len(got) != 1 || got[0].ObserverName != "probectl-eu" || got[0].Verdict != store.ObservationMatch || got[0].ChainFingerprints == nil {
		t.Fatalf("observations = %+v, %v", got, err)
	}

	event := store.ObserverEvent{ID: "rotation:a180", Type: store.ObserverEventRotationCompleted, TenantID: tenantA,
		OccurredAt: now, PreviousFingerprint: strings.Repeat("8c", 32), CurrentFingerprint: expected}
	queue := func(ev store.ObserverEvent, at time.Time) {
		t.Helper()
		if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.QueueObserverEventTx(ctx, tx, ev, at) }); err != nil {
			t.Fatal(err)
		}
	}
	queue(event, now)
	queue(event, now) // a replay converges
	stale := event
	stale.ID, stale.OccurredAt = "rotation:stale", now.Add(-48*time.Hour)
	queue(stale, now)
	var rows []struct {
		key     string
		payload []byte
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		r, err := tx.Query(ctx, `SELECT idempotency_key, payload FROM outbox WHERE tenant_id = $1 AND destination = $2 ORDER BY id`, tenantA, store.ObserverEventDestination)
		if err != nil {
			return err
		}
		defer r.Close()
		for r.Next() {
			var row struct {
				key     string
				payload []byte
			}
			if err := r.Scan(&row.key, &row.payload); err != nil {
				return err
			}
			rows = append(rows, row)
		}
		return r.Err()
	}); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].key != "observer-event:"+withEvents+":rotation:a180" {
		t.Fatalf("queued = %+v, want one row for the observer with an events URL", rows)
	}
	var envelope struct {
		ObserverID string              `json:"observer_id"`
		Event      store.ObserverEvent `json:"event"`
	}
	if err := json.Unmarshal(rows[0].payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.ObserverID != withEvents || envelope.Event.CurrentFingerprint != expected ||
		len(envelope.Event.Endpoints) != 1 || envelope.Event.Endpoints[0] != "checkout.example.test:443" {
		t.Fatalf("envelope = %+v", envelope)
	}
	_ = successor
}
