// SPDX-License-Identifier: BUSL-1.1

package crypto_test

import (
	"bytes"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func TestTokenEncodersAppendToByteSlices(t *testing.T) {
	raw := []byte{0x00, 0x10, 0xff}
	if got := crypto.AppendHex(nil, raw); !bytes.Equal(got, []byte("0010ff")) {
		t.Fatalf("AppendHex = %q", got)
	}
	if got := crypto.AppendBase64RawURL(nil, []byte("token bytes")); !bytes.Equal(got, []byte("dG9rZW4gYnl0ZXM")) {
		t.Fatalf("AppendBase64RawURL = %q", got)
	}
}
