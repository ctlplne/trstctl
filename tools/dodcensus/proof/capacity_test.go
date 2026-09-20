// SPDX-License-Identifier: BUSL-1.1
//go:build !windows

package proof

import "testing"

func TestRuntimeExecCapacityRejectsInvalidAndOverflowedMetadata(t *testing.T) {
	for _, tc := range []struct {
		name      string
		blocks    uint64
		blockSize int64
		want      bool
	}{
		{"exact", 1 << 18, 4096, true},
		{"zero-size", 1 << 18, 0, false},
		{"negative-size", 1 << 18, -4096, false},
		{"short", (1 << 18) - 1, 4096, false},
		{"large", (1 << 18) + 1, 4096, false},
		{"wrapped-product", (1 << 52) + (1 << 18), 4096, false},
		{"fractional-block", (1 << 30) / 4097, 4097, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasRuntimeExecCapacity(tc.blocks, tc.blockSize); got != tc.want {
				t.Fatalf("capacity admission = %v, want %v for blocks=%d size=%d", got, tc.want, tc.blocks, tc.blockSize)
			}
		})
	}
}
