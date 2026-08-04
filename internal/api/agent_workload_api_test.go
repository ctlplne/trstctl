// SPDX-License-Identifier: MPL-2.0

package api

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// The console must keep three Workload API states apart (epic B3).
//
// "Not reported" and "not serving" render identically under a boolean and call
// for opposite responses: one is an agent build too old to answer, fixed by an
// upgrade; the other is a flag its operator chose. A surface that conflates them
// sends people to edit config on a host whose problem is its version.

// The served view must keep the three states apart, and must never imply a
// count for a host that is not serving.
func TestTheServedPostureKeepsTheThreeStatesApart(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)

	never := agentWorkloadAPIFor(store.Agent{})
	if never.State != workloadAPIUnreported {
		t.Errorf("an agent that never reported = %q, want %q", never.State, workloadAPIUnreported)
	}
	if never.ReportedAt != "" {
		t.Errorf("an agent that never reported carried a timestamp %q", never.ReportedAt)
	}

	off := agentWorkloadAPIFor(store.Agent{WorkloadAPIReportedAt: &at})
	if off.State != workloadAPINotServing {
		t.Errorf("a host reporting not-serving = %q, want %q", off.State, workloadAPINotServing)
	}
	if off.SVIDsIssued != 0 {
		t.Errorf("a non-serving host reported %d issuances", off.SVIDsIssued)
	}

	on := agentWorkloadAPIFor(store.Agent{
		WorkloadAPIServed: true, WorkloadAPISVIDs: 7, WorkloadAPIReportedAt: &at,
	})
	if on.State != workloadAPIServing || on.SVIDsIssued != 7 {
		t.Errorf("a serving host = %q with %d issuances, want %q with 7",
			on.State, on.SVIDsIssued, workloadAPIServing)
	}
	if on.ReportedAt == "" {
		t.Error("a serving host carried no report time, so staleness cannot be judged")
	}

	// Every state explains itself. An operator reading this surface mid-incident
	// should not have to consult documentation to know what to do next.
	for name, got := range map[string]agentWorkloadAPIStatus{"unreported": never, "not_serving": off, "serving": on} {
		if got.Detail == "" {
			t.Errorf("state %q carries no operator-facing explanation", name)
		}
	}
}
