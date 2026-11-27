// SPDX-License-Identifier: BUSL-1.1

package crypto

import "testing"

func FuzzOCSPRequestShape(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x03, 0x30, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, der []byte) {
		_ = validateOCSPRequestShape(der)
	})
}
