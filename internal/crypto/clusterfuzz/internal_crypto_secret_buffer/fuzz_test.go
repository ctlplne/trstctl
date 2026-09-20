// SPDX-License-Identifier: BUSL-1.1

package clusterfuzz

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// FuzzWipe exercises the zeroization (zero path) with arbitrary inputs.
func FuzzWipe(f *testing.F) {
	f.Add([]byte("hunter2"))
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2, 255, 128})
	f.Fuzz(func(t *testing.T, data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)
		secret.Wipe(buf)
		for i, v := range buf {
			if v != 0 {
				t.Fatalf("byte %d = %d after Wipe, want 0", i, v)
			}
		}
	})
}
