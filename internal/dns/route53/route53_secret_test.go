// SPDX-License-Identifier: BUSL-1.1

package route53

import "testing"

func TestSigV4SigningKeyWipesIntermediateBuffers(t *testing.T) {
	var observed [][]byte
	key := sigV4SigningKey([]byte("secret-access-key"), "20260620", sigV4Region, service, func(_ string, b []byte) {
		observed = append(observed, b)
	})
	if len(key) == 0 {
		t.Fatal("signing key was empty")
	}
	for i, buf := range observed {
		if !allZero(buf) {
			t.Fatalf("intermediate buffer %d was not wiped: %x", i, buf)
		}
	}
}

func allZero(buf []byte) bool {
	for _, b := range buf {
		if b != 0 {
			return false
		}
	}
	return true
}
