package crypto_test

import (
	"bytes"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func mkAuthorizer(t *testing.T) *crypto.SignAuthorizer {
	t.Helper()
	secret := bytes.Repeat([]byte{0xA5}, 32)
	a, err := crypto.NewSignAuthorizer(secret)
	if err != nil {
		t.Fatalf("NewSignAuthorizer: %v", err)
	}
	t.Cleanup(a.Destroy)
	return a
}

// TestSignAuthorizerRoundTrip: a token minted for an intent verifies for that
// exact intent.
func TestSignAuthorizerRoundTrip(t *testing.T) {
	a := mkAuthorizer(t)
	intent := crypto.SignIntent{
		KeyHandle: "issuing-ca",
		Purpose:   1, // CA_SIGN
		Hash:      crypto.SHA256,
		Digest:    bytes.Repeat([]byte{0x11}, 32),
	}
	token, err := a.Authorize(intent)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if len(token) == 0 {
		t.Fatal("empty token")
	}
	if !a.Verify(intent, token) {
		t.Fatal("Verify rejected a token it just minted")
	}
}

// TestSignAuthorizerBindsDigest is the heart of RED-003: a token authorizes ONE
// digest. Presenting the same token for a different digest (the forge attempt)
// must be rejected — the authorization cannot be replayed onto attacker bytes.
func TestSignAuthorizerBindsDigest(t *testing.T) {
	a := mkAuthorizer(t)
	approved := crypto.SignIntent{
		KeyHandle: "issuing-ca", Purpose: 1, Hash: crypto.SHA256,
		Digest: bytes.Repeat([]byte{0x11}, 32),
	}
	token, err := a.Authorize(approved)
	if err != nil {
		t.Fatal(err)
	}

	// Every single-field change must invalidate the token.
	forgeries := []struct {
		name   string
		intent crypto.SignIntent
	}{
		{"different digest", crypto.SignIntent{KeyHandle: "issuing-ca", Purpose: 1, Hash: crypto.SHA256, Digest: bytes.Repeat([]byte{0x22}, 32)}},
		{"different handle", crypto.SignIntent{KeyHandle: "other-ca", Purpose: 1, Hash: crypto.SHA256, Digest: approved.Digest}},
		{"different purpose", crypto.SignIntent{KeyHandle: "issuing-ca", Purpose: 3, Hash: crypto.SHA256, Digest: approved.Digest}},
		{"different hash", crypto.SignIntent{KeyHandle: "issuing-ca", Purpose: 1, Hash: crypto.SHA512, Digest: approved.Digest}},
		{"different padding", crypto.SignIntent{KeyHandle: "issuing-ca", Purpose: 1, Hash: crypto.SHA256, Padding: crypto.RSAPSS, Digest: approved.Digest}},
	}
	for _, f := range forgeries {
		if a.Verify(f.intent, token) {
			t.Errorf("token accepted for a %s — authorization is not bound to the tuple", f.name)
		}
	}
}

// TestSignAuthorizerRejectsForeignSecret: a token minted under a different secret
// is rejected — socket access without the approver secret cannot forge a token.
func TestSignAuthorizerRejectsForeignSecret(t *testing.T) {
	approver := mkAuthorizer(t)
	attacker, err := crypto.NewSignAuthorizer(bytes.Repeat([]byte{0x5A}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Destroy()

	intent := crypto.SignIntent{KeyHandle: "issuing-ca", Purpose: 1, Hash: crypto.SHA256, Digest: bytes.Repeat([]byte{0x11}, 32)}
	forged, err := attacker.Authorize(intent)
	if err != nil {
		t.Fatal(err)
	}
	if approver.Verify(intent, forged) {
		t.Fatal("approver accepted a token minted under a foreign secret")
	}
}

// TestSignAuthorizerShortSecretRejected: a too-short secret cannot create a
// trivially-forgeable gate.
func TestSignAuthorizerShortSecretRejected(t *testing.T) {
	if _, err := crypto.NewSignAuthorizer([]byte("short")); err == nil {
		t.Fatal("expected NewSignAuthorizer to reject a short secret")
	}
}

// TestSignAuthorizerNilAndDestroyedFailClosed: a nil authorizer, an empty token,
// and a destroyed authorizer all fail closed.
func TestSignAuthorizerNilAndDestroyedFailClosed(t *testing.T) {
	var nilAuth *crypto.SignAuthorizer
	intent := crypto.SignIntent{KeyHandle: "h", Purpose: 1, Hash: crypto.SHA256, Digest: make([]byte, 32)}
	if nilAuth.Verify(intent, []byte("x")) {
		t.Error("nil authorizer verified")
	}
	if _, err := nilAuth.Authorize(intent); err == nil {
		t.Error("nil authorizer minted a token")
	}

	a := mkAuthorizer(t)
	if a.Verify(intent, nil) {
		t.Error("verified an empty token")
	}
	a.Destroy()
	if _, err := a.Authorize(intent); err == nil {
		t.Error("destroyed authorizer minted a token")
	}
	if a.Verify(intent, []byte("x")) {
		t.Error("destroyed authorizer verified")
	}
}
