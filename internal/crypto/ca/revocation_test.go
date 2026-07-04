// SPDX-License-Identifier: MPL-2.0

package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"
)

func issueTestLeaf(t *testing.T, c *CA, cn string) (leafDER []byte, serial string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := c.IssueLeaf(csr, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(issued.CertificatePEM)
	if block == nil {
		t.Fatal("no leaf PEM block")
	}
	return block.Bytes, issued.Serial
}

// TestSignOCSPVerifies signs an OCSP "good" response and confirms it parses and
// verifies against the issuing CA, carries the queried serial, and is cacheable
// (a future NextUpdate).
func TestSignOCSPVerifies(t *testing.T) {
	c, err := NewRoot(CASpec{CommonName: "OCSP Test Root", TTL: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	_, serial := issueTestLeaf(t, c, "svc.internal")

	now := time.Now()
	respDER, err := c.SignOCSP(OCSPGood, serial, now, now.Add(time.Hour), time.Time{}, 0)
	if err != nil {
		t.Fatalf("SignOCSP: %v", err)
	}
	status, err := ParseOCSPResponse(respDER, c.CertificateDER())
	if err != nil {
		t.Fatalf("ParseOCSPResponse (signature must verify against issuer): %v", err)
	}
	if status.Status != OCSPGood {
		t.Errorf("status = %q, want good", status.Status)
	}
	if status.Serial != serial {
		t.Errorf("serial = %q, want %q", status.Serial, serial)
	}
	if !status.NextUpdate.After(time.Now()) {
		t.Errorf("NextUpdate = %v, want future (cacheable)", status.NextUpdate)
	}
}

// TestSignOCSPRevoked carries the revocation time and reason.
func TestSignOCSPRevoked(t *testing.T) {
	c, err := NewRoot(CASpec{CommonName: "OCSP Revoked Root", TTL: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	_, serial := issueTestLeaf(t, c, "gone.internal")
	now := time.Now()
	respDER, err := c.SignOCSP(OCSPRevoked, serial, now, now.Add(time.Hour), now.Add(-time.Minute), 1)
	if err != nil {
		t.Fatal(err)
	}
	status, err := ParseOCSPResponse(respDER, c.CertificateDER())
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != OCSPRevoked {
		t.Errorf("status = %q, want revoked", status.Status)
	}
	if status.Reason != 1 {
		t.Errorf("revocation reason = %d, want 1 (keyCompromise)", status.Reason)
	}
}

// TestCreateCRLContainsRevoked builds a CRL and confirms it parses and lists the
// revoked serial.
func TestCreateCRLContainsRevoked(t *testing.T) {
	c, err := NewRoot(CASpec{CommonName: "CRL Test Root", TTL: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	_, serial := issueTestLeaf(t, c, "revoked.internal")
	now := time.Now()
	crlDER, err := c.CreateCRL([]RevokedSerial{{Serial: serial, RevokedAt: now, Reason: 1}}, 1, now, now.Add(7*24*time.Hour))
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	info, err := ParseCRL(crlDER)
	if err != nil {
		t.Fatalf("ParseCRL: %v", err)
	}
	if info.Number != 1 {
		t.Errorf("CRL number = %d, want 1", info.Number)
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

// TestBuildOCSPRequestSerialRoundTrips: building an OCSP request for a leaf and
// reading its serial back yields the leaf's serial.
func TestBuildOCSPRequestSerialRoundTrips(t *testing.T) {
	c, err := NewRoot(CASpec{CommonName: "Req Root", TTL: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	leafDER, serial := issueTestLeaf(t, c, "req.internal")
	reqDER, err := BuildOCSPRequest(leafDER, c.CertificateDER())
	if err != nil {
		t.Fatalf("BuildOCSPRequest: %v", err)
	}
	got, err := ParseOCSPRequestSerial(reqDER)
	if err != nil {
		t.Fatalf("ParseOCSPRequestSerial: %v", err)
	}
	if got != serial {
		t.Errorf("request serial = %q, want %q", got, serial)
	}
}
