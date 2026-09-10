// SPDX-License-Identifier: MPL-2.0

package certinfo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T) (pemBytes, derBytes []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(12345),
		Subject:        pkix.Name{CommonName: "svc.acme.test", Organization: []string{"Acme"}},
		Issuer:         pkix.Name{CommonName: "Acme Root"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		DNSNames:       []string{"svc.acme.test", "alt.acme.test"},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.1")},
		EmailAddresses: []string{"ops@acme.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), der
}

func TestInspectPublicKeyBits(t *testing.T) {
	pemBytes, _ := testCert(t)
	info, err := Inspect(pemBytes)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info.PublicKeyBits != 256 {
		t.Errorf("PublicKeyBits = %d, want 256 (ECDSA P-256)", info.PublicKeyBits)
	}
}

func TestInspectExtractsMetadata(t *testing.T) {
	pemBytes, _ := testCert(t)
	info, err := Inspect(pemBytes)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info.CommonName != "svc.acme.test" {
		t.Fatalf("parsed CommonName = %q", info.CommonName)
	}
	if want := "svc.acme.test"; !contains(info.DNSNames, want) || !contains(info.DNSNames, "alt.acme.test") {
		t.Errorf("DNSNames = %v, want both SANs incl %q", info.DNSNames, want)
	}
	if !contains(info.IPAddresses, "10.0.0.1") {
		t.Errorf("IPAddresses = %v, want 10.0.0.1", info.IPAddresses)
	}
	if !contains(info.EmailAddresses, "ops@acme.test") {
		t.Errorf("EmailAddresses = %v", info.EmailAddresses)
	}
	if info.SerialNumber != "3039" { // 12345 in hex
		t.Errorf("Serial = %q, want 3039", info.SerialNumber)
	}
	if info.KeyAlgorithm != "ECDSA" {
		t.Errorf("KeyAlgorithm = %q, want ECDSA", info.KeyAlgorithm)
	}
	if len(info.SHA256Fingerprint) != 64 {
		t.Errorf("SHA256Fingerprint = %q, want 64 hex chars", info.SHA256Fingerprint)
	}
	if len(info.SPKISHA256) != 64 {
		t.Errorf("SPKISHA256 = %q, want 64 hex chars", info.SPKISHA256)
	}
	if d := info.NotAfter.Sub(info.NotBefore); d < 24*time.Hour || d > 26*time.Hour {
		t.Errorf("validity = %v, want ~25h", d)
	}
	if info.Subject == "" || info.Issuer == "" {
		t.Errorf("subject/issuer = %q / %q", info.Subject, info.Issuer)
	}
}

func TestInspectAllPreservesSPKIIdentity(t *testing.T) {
	t.Parallel()
	pemBytes, _ := testCert(t)
	direct, err := Inspect(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := InspectAll(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 1 || chain[0].SPKISHA256 == "" || chain[0].SPKISHA256 != direct.SPKISHA256 {
		t.Fatalf("chain SPKI identity = %+v, want direct identity %q", chain, direct.SPKISHA256)
	}
}

func TestInspectAcceptsDER(t *testing.T) {
	_, der := testCert(t)
	if _, err := Inspect(der); err != nil {
		t.Errorf("Inspect(DER): %v", err)
	}
}

func TestInspectRejectsGarbage(t *testing.T) {
	if _, err := Inspect([]byte("not a certificate")); err == nil {
		t.Error("Inspect accepted non-certificate bytes")
	}
}

func TestThumbprint(t *testing.T) {
	pemBytes, derBytes := testCert(t)

	fromPEM, err := Thumbprint(pemBytes)
	if err != nil {
		t.Fatalf("Thumbprint(PEM): %v", err)
	}
	// SHA-1 is 20 bytes -> 40 uppercase hex characters.
	if len(fromPEM) != 40 || fromPEM != strings.ToUpper(fromPEM) {
		t.Errorf("thumbprint = %q, want 40 uppercase hex chars", fromPEM)
	}
	fromDER, err := Thumbprint(derBytes)
	if err != nil {
		t.Fatalf("Thumbprint(DER): %v", err)
	}
	if fromPEM != fromDER {
		t.Errorf("thumbprint differs for PEM (%s) and DER (%s)", fromPEM, fromDER)
	}
	if _, err := Thumbprint([]byte("not a certificate")); err == nil {
		t.Error("Thumbprint of garbage should error")
	}
}

// TestPublicKeyJWKThumbprint verifies the RFC 7638 JWK thumbprint of the
// certificate's public key (used by the ACME revokeCert cert-key authz path,
// INTEROP-002): it is a stable non-empty base64url value, PEM and DER agree, and it
// equals an independently computed thumbprint over the canonical EC JWK — so it can
// be compared against a jose account-key thumbprint.
func TestPublicKeyJWKThumbprint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "rev.acme.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	fromDER, err := PublicKeyJWKThumbprint(der)
	if err != nil {
		t.Fatalf("PublicKeyJWKThumbprint(DER): %v", err)
	}
	fromPEM, err := PublicKeyJWKThumbprint(pemBytes)
	if err != nil {
		t.Fatalf("PublicKeyJWKThumbprint(PEM): %v", err)
	}
	if fromDER == "" || fromDER != fromPEM {
		t.Fatalf("thumbprint empty or PEM/DER mismatch: der=%q pem=%q", fromDER, fromPEM)
	}

	// Independently compute the RFC 7638 EC thumbprint and compare.
	enc := base64.RawURLEncoding.EncodeToString
	size := (key.Curve.Params().BitSize + 7) / 8
	xb := leftPad(key.X.Bytes(), size)
	yb := leftPad(key.Y.Bytes(), size)
	canonical := `{"crv":"P-256","kty":"EC","x":"` + enc(xb) + `","y":"` + enc(yb) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	want := enc(sum[:])
	if fromDER != want {
		t.Errorf("thumbprint = %q, want %q (canonical EC JWK)", fromDER, want)
	}

	if _, err := PublicKeyJWKThumbprint([]byte("not a certificate")); err == nil {
		t.Error("PublicKeyJWKThumbprint of garbage should error")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
