// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/billing"
)

// Only the scheduling/failure point is injected. Reads, lifecycle fences,
// counter transactions and persisted coverage all use real PostgreSQL.
type heldObservationStore struct {
	*billing.PGStore
	entered          chan struct{}
	release          chan struct{}
	hold             atomic.Bool
	failRegistration atomic.Bool
}

func (s *heldObservationStore) ObservationRegistration(ctx context.Context, tenantID string) (string, error) {
	if s.failRegistration.Swap(false) {
		return "", errors.New("controlled registration read unavailable")
	}
	return s.PGStore.ObservationRegistration(ctx, tenantID)
}

func (s *heldObservationStore) FlushObservedCounters(ctx context.Context, tenantID, registration string, from, to time.Time, deltas []billing.CounterDelta) error {
	if s.hold.Swap(false) {
		close(s.entered)
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.PGStore.FlushObservedCounters(ctx, tenantID, registration, from, to, deltas)
}

func TestRegistrationFailureCannotBeCoveredByAnOlderInflightFlush(t *testing.T) {
	pg, connection := newBillingStoreOn(t, "billing_observation_interruption")
	seedBillingRegistration(t, connection, quotaTenant)
	store := &heldObservationStore{PGStore: pg, entered: make(chan struct{}), release: make(chan struct{})}
	store.hold.Store(true)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	now := start
	recorder := billing.NewRecorder(store, nil).WithClock(func() time.Time { return now })
	recorder.Record(quotaTenant, "certificates_issued", 1)
	now = start.Add(30 * time.Minute)
	finished := make(chan error, 1)
	go func() { finished <- recorder.Flush(ctx) }()
	select {
	case <-store.entered:
	case <-ctx.Done():
		t.Fatal("flush did not reach the controlled persistence boundary")
	}
	now = start.Add(40 * time.Minute)
	store.failRegistration.Store(true)
	recorder.Record(quotaTenant, "certificates_issued", 5)
	now = start.Add(45 * time.Minute)
	recorder.Record(quotaTenant, "certificates_issued", 2)
	close(store.release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	now = start.Add(2 * time.Hour)
	if err := recorder.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	coverage, err := pg.CoverageFor(ctx, quotaTenant)
	if err != nil {
		t.Fatal(err)
	}
	gapPeriod := billing.EvidencePeriod{CustomerID: quotaTenant, Start: start, End: start.Add(time.Hour)}
	if got := billing.MaySign(gapPeriod, coverage, now); got.Signable {
		t.Fatalf("older flush restored continuity across a failed observation: %+v", coverage)
	}
	healthyPeriod := billing.EvidencePeriod{CustomerID: quotaTenant, Start: start.Add(time.Hour), End: now}
	if got := billing.MaySign(healthyPeriod, coverage, now); !got.Signable {
		t.Fatalf("recovery must allow later fully observed periods: %s", got.Reason)
	}
	rows, err := pg.Query(ctx, start, now, quotaTenant)
	if err != nil || len(rows) != 1 || rows[0].Value != 8 {
		t.Fatalf("registration read failure must not drop usage queued by the still-live registration: rows=%+v err=%v", rows, err)
	}
}
