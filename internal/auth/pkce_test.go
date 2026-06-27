package auth_test

import (
	"testing"

	"trstctl.com/trstctl/internal/auth"
)

func TestPKCEChallengeS256RFCVector(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := auth.PKCEChallengeS256(verifier); got != want {
		t.Fatalf("PKCEChallengeS256 = %q, want %q", got, want)
	}
}

func TestGeneratePKCEVerifierMeetsLengthFloor(t *testing.T) {
	verifier, err := auth.GeneratePKCEVerifier()
	if err != nil {
		t.Fatalf("GeneratePKCEVerifier: %v", err)
	}
	if n := len(verifier); n < 43 || n > 128 {
		t.Fatalf("verifier length = %d, want RFC 7636 43..128", n)
	}
}
