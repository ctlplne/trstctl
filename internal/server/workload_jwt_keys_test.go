// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// N5-L3: a generation is next from its rotation until its activation, then
// active; the generation it replaced is retiring until the retain window ends,
// then retired. Only retired keys leave the published set.
func TestWorkloadJWTKeyScheduleN5L3(t *testing.T) {
	t0 := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	rotations := []store.WorkloadJWTKeyRotation{
		{Generation: 2, KeyID: "spiffe-jwt-g2", PublishedAt: t0, ActivatesAt: t0.Add(time.Hour), PreviousRetiresAt: t0.Add(3 * time.Hour)},
	}
	states := func(now time.Time, rotations []store.WorkloadJWTKeyRotation) map[string]string {
		out := map[string]string{}
		for _, k := range workloadJWTKeySchedule(rotations, now) {
			out[k.KeyID] = k.State
			if k.published() != (k.State != workloadJWTKeyRetired) {
				t.Fatalf("%s %s published = %v", k.KeyID, k.State, k.published())
			}
		}
		return out
	}
	check := func(when string, got map[string]string, want map[string]string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s: %v, want %v", when, got, want)
		}
		for id, state := range want {
			if got[id] != state {
				t.Fatalf("%s: %v, want %v", when, got, want)
			}
		}
	}
	check("before any rotation", states(t0, nil), map[string]string{"spiffe-jwt": "active"})
	check("published ahead", states(t0.Add(time.Minute), rotations), map[string]string{"spiffe-jwt": "active", "spiffe-jwt-g2": "next"})
	check("at activation", states(t0.Add(time.Hour), rotations), map[string]string{"spiffe-jwt": "retiring", "spiffe-jwt-g2": "active"})
	check("before retirement", states(t0.Add(3*time.Hour-time.Second), rotations), map[string]string{"spiffe-jwt": "retiring", "spiffe-jwt-g2": "active"})
	check("at retirement", states(t0.Add(3*time.Hour), rotations), map[string]string{"spiffe-jwt": "retired", "spiffe-jwt-g2": "active"})

	// A third generation rotated while the first still retires: three keys
	// are published, and each retires on its own schedule.
	rotations = append(rotations, store.WorkloadJWTKeyRotation{
		Generation: 3, KeyID: "spiffe-jwt-g3", PublishedAt: t0.Add(2 * time.Hour), ActivatesAt: t0.Add(2 * time.Hour), PreviousRetiresAt: t0.Add(5 * time.Hour),
	})
	check("two rotations", states(t0.Add(2*time.Hour), rotations), map[string]string{"spiffe-jwt": "retiring", "spiffe-jwt-g2": "retiring", "spiffe-jwt-g3": "active"})
	check("after both", states(t0.Add(5*time.Hour), rotations), map[string]string{"spiffe-jwt": "retired", "spiffe-jwt-g2": "retired", "spiffe-jwt-g3": "active"})
	if got := workloadJWTKeyHandle(1); got != spiffeJWTHandle {
		t.Fatalf("generation 1 handle = %q", got)
	}
	if got := workloadJWTKeyHandle(3); got != spiffeJWTHandle+"-g3" {
		t.Fatalf("generation 3 handle = %q", got)
	}
}
