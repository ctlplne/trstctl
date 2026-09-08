// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/observ"
	"trstctl.com/trstctl/internal/store"
)

// A datastore-reading probe that is shed by load answers degraded (readiness
// stays 200 and names the probe); a probe that fails for a real reason fails;
// and shedding that outlasts the grace window fails too, because a datastore
// that has been too slow for minutes is a stall, not a burst (DP2-054 review).
func TestShedProbeDegradesWithinGraceAndFailsBeyondIt(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	sp := &shedProbe{name: "projection", probe: func(context.Context) error { return store.ErrDatastoreBusy }, now: func() time.Time { return now }}
	err := sp.run(context.Background())
	var deg observ.DegradedError
	if !errors.As(err, &deg) {
		t.Fatalf("busy probe within grace = %v, want observ.DegradedError", err)
	}
	now = now.Add(loadSensitiveGrace - time.Second)
	if err := sp.run(context.Background()); !errors.As(err, &deg) {
		t.Fatalf("busy probe just inside the grace window = %v, want degraded", err)
	}
	now = now.Add(2 * time.Second)
	err = sp.run(context.Background())
	if err == nil || errors.As(err, &deg) || !store.IsBusy(err) {
		t.Fatalf("busy probe beyond the grace window = %v, want the underlying busy error (not ready)", err)
	}
	// A successful probe resets the window.
	sp.probe = func(context.Context) error { return nil }
	if err := sp.run(context.Background()); err != nil {
		t.Fatalf("recovered probe = %v, want nil", err)
	}
	sp.probe = func(context.Context) error { return store.ErrDatastoreBusy }
	if err := sp.run(context.Background()); !errors.As(err, &deg) {
		t.Fatalf("busy again after recovery = %v, want degraded (window restarted)", err)
	}
	// A real failure is never softened.
	sp.probe = func(context.Context) error {
		return errors.New("projection tail failed: applied_sequence=5 failed_sequence=6")
	}
	if err := sp.run(context.Background()); err == nil || errors.As(err, &deg) {
		t.Fatalf("genuine failure = %v, want the failure itself", err)
	}
}

func TestReadinessReportsDegradedProbesAs200WithTheList(t *testing.T) {
	r := observ.NewReadiness(nil,
		observ.Check{Name: "db", Probe: func(context.Context) error { return nil }},
		observ.Check{Name: "projection", Probe: func(context.Context) error { return observ.Degraded("shed by load") }},
	)
	ok, results, degraded := r.EvaluateDetailed(context.Background())
	if !ok || results["db"] != "ok" || results["projection"] != "degraded: shed by load" || len(degraded) != 1 || degraded[0] != "projection" {
		t.Fatalf("ok=%v results=%v degraded=%v", ok, results, degraded)
	}
	r = observ.NewReadiness(nil, observ.Check{Name: "projection", Probe: func(context.Context) error { return errors.New("stalled") }})
	if ok, _, _ := r.EvaluateDetailed(context.Background()); ok {
		t.Fatal("a failed probe must not read as ready")
	}
}
