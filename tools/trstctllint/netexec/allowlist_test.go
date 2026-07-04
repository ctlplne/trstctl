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
