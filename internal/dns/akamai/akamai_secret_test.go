// SPDX-License-Identifier: BUSL-1.1

package akamai

import "testing"

func TestEdgeGridSigningKeyWipesTimestampMAC(t *testing.T) {
	var observed [][]byte
	key := edgeGridSigningKey([]byte("client-secret"), "20260620T12:00:00+0000", func(_ string, b []byte) {
		observed = append(observed, b)
	})
	if len(key) == 0 {
		t.Fatal("signing key was empty")
	}
	if len(observed) == 0 {
		t.Fatal("test did not observe intermediate buffers")
	}
	if !allZero(observed[0]) {
		t.Fatalf("timestamp MAC was not wiped: %x", observed[0])
	}
	if allZero(key) {
		t.Fatal("returned signing key was wiped before caller could use it")
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
