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
		"tools/dodcensus/proof/launched.go": {
			"buildShippedProcess": true,
			"CreateToken":         true,
			"Start":               true,
		},
		"tools/dodcensus/runtime_runner.go": {
			"runHostCommand": true,
		},
		"tools/dodcensus/substrate_broker.go": {
			"launch": true,
		},
	}
	for file, functions := range want {
		if got := reviewedExecUses[file]; !reflect.DeepEqual(got, functions) {
			t.Fatalf("%s reviewed exec allowlist = %#v, want %#v", file, got, functions)
		}
	}
}

func TestReviewedExecAllowlistPinsConnectorLocalOpsBoundary(t *testing.T) {
	want := map[string]bool{"ExecContext": true}
	if got := reviewedExecUses["internal/connector/localops.go"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("internal/connector/localops.go reviewed exec allowlist = %#v, want %#v", got, want)
	}
}
