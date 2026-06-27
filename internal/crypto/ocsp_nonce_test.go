package crypto

import (
	"bytes"
	"testing"
	"time"
)

func TestOCSPNonceRequestEchoesInSignedResponse(t *testing.T) {
	caDER, caSigner := caForRevocation(t)
	responderSigner, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey responder: %v", err)
	}
	t.Cleanup(responderSigner.Destroy)

	now := time.Date(2026, 6, 27, 13, 0, 0, 0, time.UTC)
	responderDER, err := CreateOCSPResponderCertificate(caDER, caSigner, responderSigner, "nonce OCSP responder", now.Add(-time.Minute), now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("CreateOCSPResponderCertificate: %v", err)
	}

	nonce := []byte("0123456789abcdef")
	reqDER, err := BuildOCSPRequestForSerialWithNonce(caDER, "abc123", nonce)
	if err != nil {
		t.Fatalf("BuildOCSPRequestForSerialWithNonce: %v", err)
	}
	gotNonce, present, err := ParseOCSPRequestNonce(reqDER)
	if err != nil {
		t.Fatalf("ParseOCSPRequestNonce: %v", err)
	}
	if !present || !bytes.Equal(gotNonce, nonce) {
		t.Fatalf("request nonce = %x present=%v, want %x present=true", gotNonce, present, nonce)
	}

	respDER, err := SignDelegatedOCSPResponseWithNonce(caDER, responderDER, responderSigner, OCSPGood, "abc123", now, now.Add(time.Hour), time.Time{}, 0, nonce)
	if err != nil {
		t.Fatalf("SignDelegatedOCSPResponseWithNonce: %v", err)
	}
	status, err := ParseOCSPResponse(respDER, caDER)
	if err != nil {
		t.Fatalf("ParseOCSPResponse: %v", err)
	}
	if !status.HasNonce || !bytes.Equal(status.Nonce, nonce) {
		t.Fatalf("response nonce = %x has=%v, want echoed %x", status.Nonce, status.HasNonce, nonce)
	}
}
