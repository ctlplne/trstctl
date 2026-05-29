package certinfo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
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

func TestInspectExtractsMetadata(t *testing.T) {
	pemBytes, _ := testCert(t)
	info, err := Inspect(pemBytes)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
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
	if d := info.NotAfter.Sub(info.NotBefore); d < 24*time.Hour || d > 26*time.Hour {
		t.Errorf("validity = %v, want ~25h", d)
	}
	if info.Subject == "" || info.Issuer == "" {
		t.Errorf("subject/issuer = %q / %q", info.Subject, info.Issuer)
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

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
