// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/base64"
	"testing"
)

func TestDiscoveryRecentCursorRejectsCrossOrderAndMalformedValues(t *testing.T) {
	const id = "33333333-3333-4333-8333-333333333333"
	encoded := encodeDiscoveryRecentCursor(id)
	got, err := decodeDiscoveryRecentCursor(encoded)
	if err != nil || got != id {
		t.Fatalf("round trip = %q, %v", got, err)
	}
	for _, bad := range []string{
		"%%%", encodeCursor(id),
		base64.RawURLEncoding.EncodeToString([]byte("recent:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
		base64.RawURLEncoding.EncodeToString([]byte("recent:" + id + "extra")),
		string(make([]byte, 129)),
	} {
		if _, err := decodeDiscoveryRecentCursor(bad); err == nil {
			t.Fatalf("accepted malformed recent cursor %q", bad)
		}
	}
}
