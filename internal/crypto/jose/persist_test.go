package jose_test

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto/jose"
)

// TestSigningKeyPersistRoundTrip is the R2.1 persistent-export-key acceptance at
// the crypto-boundary layer: a signing key marshals to PEM and parses back to the
// same key, so a bundle signed before a "restart" still verifies after the key is
// reloaded from disk (the export key no longer rotates each restart).
func TestSigningKeyPersistRoundTrip(t *testing.T) {
	sk, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := sk.MarshalPrivateKey()
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}

	// Sign before the "restart".
	jws, err := sk.Sign([]byte(`{"hello":"world"}`))
	if err != nil {
		t.Fatal(err)
	}

	// Reload the key (as a fresh process would on startup).
	reloaded, err := jose.ParseRSASigningKey("audit-export", pemBytes)
	if err != nil {
		t.Fatalf("ParseRSASigningKey: %v", err)
	}

	// The pre-restart signature still verifies against the reloaded key's JWKS.
	payload, err := reloaded.JWKS().Verify(jws)
	if err != nil {
		t.Fatalf("reloaded key does not verify a pre-restart signature: %v", err)
	}
	if string(payload) != `{"hello":"world"}` {
		t.Errorf("payload = %s, want the signed bytes", payload)
	}
}

// TestParseRSASigningKeyRejectsGarbage: a malformed PEM is a clear error, not a
// silent empty key.
func TestParseRSASigningKeyRejectsGarbage(t *testing.T) {
	if _, err := jose.ParseRSASigningKey("k", []byte("not a pem")); err == nil {
		t.Fatal("ParseRSASigningKey accepted garbage")
	}
}
