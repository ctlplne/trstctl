// SPDX-License-Identifier: BUSL-1.1

package crypto_test

import (
	"bytes"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// A subject key born on the host that will serve it (epic B2).
//
// The property under test is where the private half is NOT: the CSR that goes
// up must carry the public key and the requested names and nothing else, and
// the private material must live in a locked buffer whose life the caller ends
// explicitly.

func TestAHostSubjectKeyProducesACSRCarryingNoPrivateMaterial(t *testing.T) {
	t.Parallel()
	key, err := crypto.GenerateHostSubjectKey("api.example.test", []string{"api.example.test", "www.example.test"})
	if err != nil {
		t.Fatalf("GenerateHostSubjectKey: %v", err)
	}
	defer key.Destroy()

	if len(key.CSRDER) == 0 {
		t.Fatal("no CSR was produced, so nothing could be sent up for signing")
	}
	// The CSR is what leaves the host. It must not contain a private key under
	// any encoding — this is the entire security claim of the epic.
	for _, marker := range [][]byte{
		[]byte("PRIVATE KEY"),
		[]byte("-----BEGIN RSA PRIVATE KEY-----"),
		[]byte("-----BEGIN EC PRIVATE KEY-----"),
	} {
		if bytes.Contains(key.CSRDER, marker) {
			t.Errorf("the CSR contains %q; the request that leaves the host must carry the public "+
				"key and the requested names and nothing else", marker)
		}
	}
	if len(key.PublicKeyDER) == 0 {
		t.Error("no public key was reported, so a caller cannot record which key was generated")
	}
}

// The private half is available exactly long enough to write one file, and the
// accessor hands out a copy so a caller that forgets to wipe cannot corrupt the
// locked original.
func TestTheHostPrivateKeyIsACopyAndDiesWithDestroy(t *testing.T) {
	t.Parallel()
	key, err := crypto.GenerateHostSubjectKey("api.example.test", nil)
	if err != nil {
		t.Fatalf("GenerateHostSubjectKey: %v", err)
	}

	first, err := key.PrivateKeyPEM()
	if err != nil {
		t.Fatalf("PrivateKeyPEM: %v", err)
	}
	if !bytes.Contains(first, []byte("PRIVATE KEY")) {
		t.Fatal("the exported material is not a private key PEM")
	}
	second, err := key.PrivateKeyPEM()
	if err != nil {
		t.Fatalf("second PrivateKeyPEM: %v", err)
	}
	if &first[0] == &second[0] {
		t.Error("two exports share backing memory; a caller wiping one would corrupt the other")
	}

	key.Destroy()
	if _, err := key.PrivateKeyPEM(); err == nil {
		t.Error("the private key was still exportable after Destroy")
	}
	// Deferred Destroy calls are common; a second call must not panic.
	key.Destroy()
}

// A request that names nothing is refused rather than certifying an empty
// subject, which no verifier would accept and which would waste an issuance.
func TestAHostSubjectKeyRequiresAName(t *testing.T) {
	t.Parallel()
	if _, err := crypto.GenerateHostSubjectKey("", nil); err == nil {
		t.Fatal("a key request naming nothing was accepted")
	}
	// A DNS name alone is enough; the common name is derived from it.
	key, err := crypto.GenerateHostSubjectKey("", []string{"api.example.test"})
	if err != nil {
		t.Fatalf("a DNS-only request was refused: %v", err)
	}
	defer key.Destroy()
	if len(key.CSRDER) == 0 {
		t.Error("a DNS-only request produced no CSR")
	}
}
