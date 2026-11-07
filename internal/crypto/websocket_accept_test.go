// SPDX-License-Identifier: BUSL-1.1

package crypto

import "testing"

// TestWebSocketAcceptRFC6455: the RFC's own example key and accept value.
func TestWebSocketAcceptRFC6455(t *testing.T) {
	if got := WebSocketAccept("dGhlIHNhbXBsZSBub25jZQ=="); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("accept = %q", got)
	}
}
