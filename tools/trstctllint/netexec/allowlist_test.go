// SPDX-License-Identifier: MPL-2.0

package netexec

import (
	"reflect"
	"testing"
)

func TestReviewedExecAllowlistPinsPerfLiveSampler(t *testing.T) {
	want := map[string]bool{
		"liveSignerBinary": true,
		"commandOutput":    true,
	}
	if got := reviewedExecUses["internal/perf/live.go"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("internal/perf/live.go reviewed exec allowlist = %#v, want %#v", got, want)
	}
}

func TestReviewedExecAllowlistPinsDODCensusProcessBoundaries(t *testing.T) {
	want := map[string]map[string]bool{
		"tools/dodcensus/main.go": {
			"Run": true,
		},
		"tools/dodcensus/proof/proof.go": {
			"StartCommand":   true,
			"StartContainer": true,
		},
	}
	for file, functions := range want {
		if got := reviewedExecUses[file]; !reflect.DeepEqual(got, functions) {
			t.Fatalf("%s reviewed exec allowlist = %#v, want %#v", file, got, functions)
		}
	}
}
