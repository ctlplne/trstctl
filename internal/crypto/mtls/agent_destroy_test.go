// SPDX-License-Identifier: MPL-2.0

package mtls

import (
	stdcrypto "crypto"
	"crypto/rand"
	"testing"
)

func TestAgentIdentityDestroyZeroesPrivateScalarAndFailsClosed(t *testing.T) {
	identity, err := GenerateAgentKey("external-ca-client")
	if err != nil {
		t.Fatal(err)
	}
	key := identity.key
	identity.Destroy()
	if key == nil {
		t.Fatal("test did not capture the client private key")
	}
	if _, err := key.Sign(rand.Reader, make([]byte, stdcrypto.SHA256.Size()), stdcrypto.SHA256); err == nil {
		t.Fatal("Destroy left the client private key usable for signing")
	}
	if _, err := identity.CSR(); err == nil {
		t.Fatal("destroyed identity produced a CSR")
	}
	if _, err := identity.ClientCertificate(); err == nil {
		t.Fatal("destroyed identity produced a TLS certificate")
	}
	identity.Destroy()
}
