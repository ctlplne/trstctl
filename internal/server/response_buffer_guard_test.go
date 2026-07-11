// SPDX-License-Identifier: MPL-2.0

package server

import (
	"io"
	"os"
	"strings"
	"testing"
)

// retainingCredentialResponseBody models an untrusted response reader that
// keeps every destination slice supplied by the client. A wipe is only real if
// those retained aliases contain zeroes after the production call returns.
type retainingCredentialResponseBody struct {
	remaining []byte
	observed  [][]byte
}

func newRetainingCredentialResponseBody(body []byte) *retainingCredentialResponseBody {
	return &retainingCredentialResponseBody{remaining: append([]byte(nil), body...)}
}

func (b *retainingCredentialResponseBody) Read(destination []byte) (int, error) {
	if len(b.remaining) == 0 {
		return 0, io.EOF
	}
	n := copy(destination, b.remaining)
	b.observed = append(b.observed, destination[:n])
	b.remaining = b.remaining[n:]
	if len(b.remaining) == 0 {
		return n, io.EOF
	}
	return n, nil
}

func (*retainingCredentialResponseBody) Close() error { return nil }

func (b *retainingCredentialResponseBody) assertObservedBytesWiped(t *testing.T) {
	t.Helper()
	if len(b.observed) == 0 {
		t.Fatal("hostile response reader observed no caller-owned buffer")
	}
	for chunkIndex, chunk := range b.observed {
		for byteIndex, value := range chunk {
			if value != 0 {
				t.Fatalf("response buffer chunk %d byte %d retained 0x%02x after return", chunkIndex, byteIndex, value)
			}
		}
	}
}

func TestW1CredentialResponseReadersStayWipeable(t *testing.T) {
	for _, path := range []string{
		"connector_right_size.go",
		"external_ca_config.go",
		"managed_key_signer_config.go",
		"notifications_incident_config.go",
		"rekor.go",
		"run_connectors.go",
		"secret_integrations.go",
	} {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, forbidden := range []string{"io.ReadAll(", "io.Copy(", "io.CopyBuffer("} {
			if strings.Contains(string(source), forbidden) {
				t.Errorf("%s uses %s for a credential-bearing response; use crypto/secret's owned, wipeable reader", path, forbidden)
			}
		}
	}
}
