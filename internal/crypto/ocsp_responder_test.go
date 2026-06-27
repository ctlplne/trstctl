package crypto

import (
	"testing"
	"time"
)

func TestDelegatedOCSPResponderCertificateSignsResponses(t *testing.T) {
	caDER, caSigner := caForRevocation(t)
	responderSigner, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey responder: %v", err)
	}
	t.Cleanup(responderSigner.Destroy)

	now := time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)
	responderDER, err := CreateOCSPResponderCertificate(caDER, caSigner, responderSigner, "issuer-a OCSP responder", now.Add(-time.Minute), now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("CreateOCSPResponderCertificate: %v", err)
	}
	responder, err := InspectOCSPResponderCertificate(caDER, responderDER)
	if err != nil {
		t.Fatalf("InspectOCSPResponderCertificate: %v", err)
	}
	if responder.Serial == "" {
		t.Fatal("responder certificate has no serial")
	}
	if !responder.HasOCSPSigningEKU {
		t.Fatal("responder certificate is missing the OCSPSigning EKU")
	}
	if !responder.HasOCSPNoCheck {
		t.Fatal("responder certificate is missing the id-pkix-ocsp-nocheck extension")
	}
	if responder.IsCA {
		t.Fatal("OCSP responder certificate is a CA certificate")
	}

	respDER, err := SignDelegatedOCSPResponse(caDER, responderDER, responderSigner, OCSPGood, "abc123", now, now.Add(time.Hour), time.Time{}, 0)
	if err != nil {
		t.Fatalf("SignDelegatedOCSPResponse: %v", err)
	}
	status, err := ParseOCSPResponse(respDER, caDER)
	if err != nil {
		t.Fatalf("ParseOCSPResponse: %v", err)
	}
	if status.Status != OCSPGood {
		t.Fatalf("status = %q, want %q", status.Status, OCSPGood)
	}
	if status.ResponderIsIssuer {
		t.Fatal("OCSP response was signed directly by the CA, not a delegated responder")
	}
	if status.ResponderSerial != responder.Serial {
		t.Fatalf("response responder serial = %q, want delegated responder serial %q", status.ResponderSerial, responder.Serial)
	}
	if !status.ResponderHasOCSPSigningEKU || !status.ResponderHasOCSPNoCheck {
		t.Fatalf("response responder metadata EKU=%v noCheck=%v, want both true", status.ResponderHasOCSPSigningEKU, status.ResponderHasOCSPNoCheck)
	}
}
