// SPDX-License-Identifier: BUSL-1.1
package crypto

import (
	"bytes"
	"testing"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestSharedAccountPasswordKeepsA240WindowsPolicy(t *testing.T) {
	for _, length := range []int{24, 32} {
		var previous []byte
		for i := 0; i < 128; i++ {
			value, err := RandomAccountPassword(length)
			if err != nil || len(value) != length || !ValidAccountPassword(value, length) {
				t.Fatal("shared account policy generation changed", err)
			}
			if bytes.Equal(previous, value) {
				t.Fatal("distinct draws reused the previous password")
			}
			secret.Wipe(previous)
			previous = value
		}
		secret.Wipe(previous)
	}
	for _, value := range [][]byte{nil, bytes.Repeat([]byte{'x'}, 32), {'A', 'b', '3', 0}} {
		if ValidAccountPassword(value, 24) {
			t.Fatal("weak or malformed account password accepted")
		}
	}
}
