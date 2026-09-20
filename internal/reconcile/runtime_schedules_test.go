// SPDX-License-Identifier: BUSL-1.1

package reconcile

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/reconcile/rounds"
)

// AUD-1: the runtime must actually CARRY its configured schedules.
//
// The original defect was not a bad schedule — it was that roundSchedules was
// declared and never assigned, so the rounds worker hit len(Schedules)==0 on
// its first tick and blocked for the life of the process. A registered,
// healthy-looking worker that compared nothing, and a served agreement report
// that answered "0 open witnesses" forever.
func TestRuntimeCarriesItsConfiguredSchedules(t *testing.T) {
	t.Parallel()
	rt, err := NewRuntime(RuntimeConfig{Schedules: []rounds.Config{
		{TenantID: "t1", Cadence: time.Hour, Planes: []rounds.PlaneConfig{
			{AuthorityID: "adcs"}, {AuthorityID: "vault"},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if rt.RoundsScheduled != 1 {
		t.Fatalf("RoundsScheduled = %d, want 1.\n\n"+
			"The worker's empty-schedules guard would fire on the first tick and block forever. "+
			"The served report would say collecting=false — honest, but nothing would ever "+
			"reconcile, and that is what shipped.", rt.RoundsScheduled)
	}
}

// An unconfigured runtime schedules nothing, and says so through the count
// rather than pretending.
func TestAnUnconfiguredRuntimeSchedulesNothing(t *testing.T) {
	t.Parallel()
	rt, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if rt.RoundsScheduled != 0 {
		t.Fatalf("RoundsScheduled = %d on an unconfigured runtime", rt.RoundsScheduled)
	}
}
