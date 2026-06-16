package crypto

import (
	"errors"
	"testing"
	"time"
)

// caForRevocation builds a self-signed CA whose signing key is a DigestSigner —
// the same interface the out-of-process signer's RemoteSigner satisfies — and
// returns the CA cert DER plus that signer, so the revocation tests sign OCSP/CRL
// exactly the way the served path does (digest across the boundary, AN-4) rather
// than with an in-process *ecdsa.PrivateKey.
func caForRevocation(t *testing.T) ([]byte, DigestSigner) {
	t.Helper()
	signer, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey: %v", err)
	}
	t.Cleanup(signer.Destroy)
	caDER, err := SelfSignedCACert(signer, "Revocation Boundary Test CA", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("SelfSignedCACert: %v", err)
	}
	return caDER, signer
}

// TestSignOCSPResponseGoodVerifies signs a "good" OCSP response through a
// DigestSigner and confirms it parses and VERIFIES against the issuing CA, carries
// the queried serial, and is cacheable (a future nextUpdate).
func TestSignOCSPResponseGoodVerifies(t *testing.T) {
	caDER, signer := caForRevocation(t)
	// Serials are stored as big.Int.Text(16) (no leading zeros), the form real
	// random 128-bit serials take, so the OCSP serial round-trips exactly.
	const serial = "a1b2c3d4e5f"

	now := time.Now()
	respDER, err := SignOCSPResponse(caDER, signer, OCSPGood, serial, now, now.Add(time.Hour), time.Time{}, 0)
	if err != nil {
		t.Fatalf("SignOCSPResponse: %v", err)
	}
	status, err := ParseOCSPResponse(respDER, caDER)
	if err != nil {
		t.Fatalf("ParseOCSPResponse (signature must verify against the CA): %v", err)
	}
	if status.Status != OCSPGood {
		t.Errorf("status = %q, want good", status.Status)
	}
	if status.Serial != serial {
		t.Errorf("serial = %q, want %q", status.Serial, serial)
	}
	if !status.NextUpdate.After(time.Now()) {
		t.Errorf("nextUpdate = %v, want future (cacheable)", status.NextUpdate)
	}
}

// TestSignOCSPResponseRevokedVerifies signs a "revoked" OCSP response and confirms
// it carries the revocation time and reason and verifies against the CA.
func TestSignOCSPResponseRevokedVerifies(t *testing.T) {
	caDER, signer := caForRevocation(t)
	const serial = "f00dface"
	now := time.Now()
	revokedAt := now.Add(-time.Minute)

	respDER, err := SignOCSPResponse(caDER, signer, OCSPRevoked, serial, now, now.Add(time.Hour), revokedAt, 1)
	if err != nil {
		t.Fatalf("SignOCSPResponse: %v", err)
	}
	status, err := ParseOCSPResponse(respDER, caDER)
	if err != nil {
		t.Fatalf("ParseOCSPResponse: %v", err)
	}
	if status.Status != OCSPRevoked {
		t.Errorf("status = %q, want revoked", status.Status)
	}
	if status.Reason != 1 {
		t.Errorf("revocation reason = %d, want 1 (keyCompromise)", status.Reason)
	}
	if status.RevokedAt.IsZero() {
		t.Error("revoked response carries no revocation time")
	}
}

// TestCreateCRLContainsRevokedAndVerifies builds a CRL through a DigestSigner and
// confirms it VERIFIES against the issuing CA, is numbered as requested, and lists
// the revoked serial.
func TestCreateCRLContainsRevokedAndVerifies(t *testing.T) {
	caDER, signer := caForRevocation(t)
	const serial = "deadbeef01"
	now := time.Now()

	crlDER, err := CreateCRL(caDER, signer, []RevokedSerial{{Serial: serial, RevokedAt: now, Reason: 1}}, 1, now, now.Add(7*24*time.Hour))
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	info, err := ParseCRL(crlDER, caDER)
	if err != nil {
		t.Fatalf("ParseCRL (signature must verify against the CA): %v", err)
	}
	if info.Number != 1 {
		t.Errorf("CRL number = %d, want 1", info.Number)
	}
	if !info.NextUpdate.After(time.Now()) {
		t.Errorf("nextUpdate = %v, want future", info.NextUpdate)
	}
	found := false
	for _, s := range info.RevokedSerials {
		if s == serial {
			found = true
		}
	}
	if !found {
		t.Errorf("CRL revoked serials = %v, want to contain %s", info.RevokedSerials, serial)
	}
}

// TestParseOCSPResponseRejectsWrongIssuer is the fail-closed guard: a response
// signed by one CA must not verify against a different CA. This is what makes the
// served responder's signature meaningful — a relying party trusts the status only
// because it verifies against the issuer it expects.
func TestParseOCSPResponseRejectsWrongIssuer(t *testing.T) {
	caDER, signer := caForRevocation(t)
	otherDER, _ := caForRevocation(t)
	now := time.Now()

	respDER, err := SignOCSPResponse(caDER, signer, OCSPGood, "01", now, now.Add(time.Hour), time.Time{}, 0)
	if err != nil {
		t.Fatalf("SignOCSPResponse: %v", err)
	}
	if _, err := ParseOCSPResponse(respDER, otherDER); err == nil {
		t.Fatal("an OCSP response verified against the wrong issuer (not fail-closed)")
	}
}

// TestParseCRLRejectsWrongIssuer is the fail-closed guard for CRLs: a CRL signed
// by one CA must not verify against a different CA.
func TestParseCRLRejectsWrongIssuer(t *testing.T) {
	caDER, signer := caForRevocation(t)
	otherDER, _ := caForRevocation(t)
	now := time.Now()

	crlDER, err := CreateCRL(caDER, signer, nil, 1, now, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	if _, err := ParseCRL(crlDER, otherDER); err == nil {
		t.Fatal("a CRL verified against the wrong issuer (not fail-closed)")
	}
}

// TestBuildOCSPRequestForSerialRoundTrips: building an OCSP request for a serial
// and reading it back yields that serial — the path the served responder relies on
// to resolve a query.
func TestBuildOCSPRequestForSerialRoundTrips(t *testing.T) {
	caDER, _ := caForRevocation(t)
	const serial = "abc123def456"

	reqDER, err := BuildOCSPRequestForSerial(caDER, serial)
	if err != nil {
		t.Fatalf("BuildOCSPRequestForSerial: %v", err)
	}
	got, err := ParseOCSPRequestSerial(reqDER)
	if err != nil {
		t.Fatalf("ParseOCSPRequestSerial: %v", err)
	}
	if got != serial {
		t.Errorf("request serial = %q, want %q", got, serial)
	}
}

// TestParseOCSPRequestSerialClassifiesMalformed pins the boundary contract the
// served HTTP responder depends on: malformed request bytes are a client fault,
// not an undifferentiated responder/signing failure.
func TestParseOCSPRequestSerialClassifiesMalformed(t *testing.T) {
	_, err := ParseOCSPRequestSerial([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	if !errors.Is(err, ErrMalformedOCSPRequest) {
		t.Fatalf("ParseOCSPRequestSerial error = %v, want ErrMalformedOCSPRequest", err)
	}
}
