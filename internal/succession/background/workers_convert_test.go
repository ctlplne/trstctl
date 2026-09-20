// SPDX-License-Identifier: BUSL-1.1

package background

import (
	"math"
	"testing"
	"time"
)

// TestCheckpointTreeSize pins the transparency-log tree-size narrowing at its
// boundaries against hand-written expected values: in range it is the identity
// on the leaf count, and a negative size fails closed instead of wrapping to a
// huge unsigned tree size that no verifier could reconcile with the log.
func TestCheckpointTreeSize(t *testing.T) {
	cases := []struct {
		name    string
		in      int
		want    uint64
		wantErr bool
	}{
		{name: "empty log", in: 0, want: 0},
		{name: "one leaf", in: 1, want: 1},
		{name: "three leaves", in: 3, want: 3},
		{name: "max int32", in: 2147483647, want: 2147483647},
		{name: "negative", in: -1, wantErr: true},
		{name: "min int32", in: -2147483648, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := checkpointTreeSize(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("checkpointTreeSize(%d) = %d, want error", tc.in, got)
				}
				if got != 0 {
					t.Fatalf("checkpointTreeSize(%d) returned %d on error, want 0", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("checkpointTreeSize(%d): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("checkpointTreeSize(%d) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// TestValidityWindowDuration pins the retirement validity-window conversion at
// its boundaries against hand-written nanosecond literals. The largest
// representable window is math.MaxInt64/1e9 = 9223372036 seconds; one second
// beyond it must be rejected rather than wrapped into a negative duration, which
// would expire every relying-party attestation on arrival.
func TestValidityWindowDuration(t *testing.T) {
	const maxSeconds = 9223372036
	if maxValidityWindowSeconds != maxSeconds {
		t.Fatalf("maxValidityWindowSeconds = %d, want %d", maxValidityWindowSeconds, maxSeconds)
	}

	cases := []struct {
		name    string
		in      uint64
		want    time.Duration
		wantErr bool
	}{
		{name: "zero", in: 0, want: 0},
		{name: "one second", in: 1, want: 1000000000},
		{name: "one hour", in: 3600, want: 3600000000000},
		{name: "one day", in: 86400, want: 86400000000000},
		{name: "max representable", in: maxSeconds, want: 9223372036000000000},
		{name: "one past max", in: maxSeconds + 1, wantErr: true},
		{name: "max int64 seconds", in: math.MaxInt64, wantErr: true},
		{name: "max uint64 seconds", in: math.MaxUint64, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validityWindowDuration(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validityWindowDuration(%d) = %v, want error", tc.in, got)
				}
				if got != 0 {
					t.Fatalf("validityWindowDuration(%d) returned %v on error, want 0", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("validityWindowDuration(%d): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("validityWindowDuration(%d) = %d ns, want %d ns", tc.in, got, tc.want)
			}
			if got < 0 {
				t.Fatalf("validityWindowDuration(%d) is negative (%v)", tc.in, got)
			}
		})
	}
}
