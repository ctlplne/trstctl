// SPDX-License-Identifier: BUSL-1.1

package server

import "testing"

// Reading a host's Workload API posture off its heartbeat (epic B3).
//
// The distinction under test is between an agent that SAID it is not serving
// and an agent that said NOTHING. They render identically under a boolean, and
// they call for opposite responses: the first is a flag an operator can change,
// the second is an agent build too old to report and the fix is an upgrade. A
// console that conflates them sends people to edit config on a host whose
// problem is its version.

func TestAnOlderAgentReadsAsUnreportedRatherThanNotServing(t *testing.T) {
	t.Parallel()
	// No counters at all: what an agent predating this epic sends.
	served, svids, reported := workloadAPIPosture(nil)
	if reported {
		t.Error("an empty inventory was read as a report; an agent that said nothing must not " +
			"be recorded as having answered")
	}
	if served || svids != 0 {
		t.Errorf("an empty inventory yielded served=%v svids=%d", served, svids)
	}

	// An inventory carrying OTHER counters but not ours is the same case: the
	// agent reported inventory, it just does not know about this feature.
	if _, _, reported := workloadAPIPosture(map[string]int64{"certificates": 12}); reported {
		t.Error("an inventory without the Workload API keys was read as a report")
	}
}

func TestAnAgentThatReportsNotServingIsDistinctFromSilence(t *testing.T) {
	t.Parallel()
	served, _, reported := workloadAPIPosture(map[string]int64{workloadAPIServedKey: 0})
	if !reported {
		t.Fatal("an explicit 'not serving' report was read as silence; the operator would be " +
			"told to upgrade an agent that is already current")
	}
	if served {
		t.Error("a zero counter was read as serving")
	}
}

func TestAServingHostReportsItsIssuanceCount(t *testing.T) {
	t.Parallel()
	served, svids, reported := workloadAPIPosture(map[string]int64{
		workloadAPIServedKey: 1, workloadAPIIssuedKey: 42,
	})
	if !reported || !served || svids != 42 {
		t.Fatalf("posture = served:%v svids:%d reported:%v, want serving with 42", served, svids, reported)
	}
}
