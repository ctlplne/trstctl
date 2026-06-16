package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

func leafOf(t *testing.T, cert tls.Certificate) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf
}

// TestClientCertificateTTLIs24h is the acceptance that platform-issued client
// certs are short-lived (24h) and usable for client auth.
func TestClientCertificateTTLIs24h(t *testing.T) {
	if ClientCertTTL != 24*time.Hour {
		t.Fatalf("ClientCertTTL = %v, want 24h", ClientCertTTL)
	}
	ca, err := NewCA("trstctl-agent-ca")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.IssueClientCertificate("agent-1", ClientCertTTL)
	if err != nil {
		t.Fatal(err)
	}
	leaf := leafOf(t, cert)
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got < 23*time.Hour || got > 25*time.Hour {
		t.Errorf("client cert validity = %v, want ~24h", got)
	}
	client := false
	for _, u := range leaf.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth {
			client = true
		}
	}
	if !client {
		t.Error("client cert missing ExtKeyUsageClientAuth")
	}
}

// TestRotatingSourceRotatesBeforeExpiry is the acceptance that client certs
// rotate before they expire (and are not churned while still fresh).
func TestRotatingSourceRotatesBeforeExpiry(t *testing.T) {
	ca, err := NewCA("ca")
	if err != nil {
		t.Fatal(err)
	}
	nearExpiry, err := ca.IssueClientCertificate("agent", time.Minute) // ~1m of validity left
	if err != nil {
		t.Fatal(err)
	}
	reissues := 0
	issue := func() (tls.Certificate, error) {
		reissues++
		return ca.IssueClientCertificate("agent", ClientCertTTL) // a fresh 24h cert
	}
	src := NewRotatingSource(nearExpiry, issue, 5*time.Minute) // refresh when < 5m remain

	c1, err := src.ClientCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if reissues != 1 {
		t.Fatalf("near-expiry cert was not rotated: %d reissues, want 1", reissues)
	}
	if rem := time.Until(leafOf(t, *c1).NotAfter); rem < 23*time.Hour {
		t.Errorf("rotated cert expires in %v, want ~24h (did not rotate to a fresh cert)", rem)
	}
	if _, err := src.ClientCertificate(); err != nil {
		t.Fatal(err)
	}
	if reissues != 1 {
		t.Errorf("a still-fresh cert was rotated again: %d reissues", reissues)
	}
}

// TestTLSConfigsPinTLS13 is the acceptance that the transport is TLS 1.3 with
// mutual auth — no downgrade, no plaintext.
func TestTLSConfigsPinTLS13(t *testing.T) {
	ca, err := NewCA("ca")
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := ca.IssueServerCertificate([]string{"agent.trstctl.local"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sc := serverTLSConfig(serverCert, ca.Pool())
	if sc.MinVersion != tls.VersionTLS13 || sc.MaxVersion != tls.VersionTLS13 {
		t.Errorf("server TLS = %d..%d, want 1.3 pinned", sc.MinVersion, sc.MaxVersion)
	}
	if sc.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("server ClientAuth = %v, want RequireAndVerifyClientCert", sc.ClientAuth)
	}
	cc := clientTLSConfig(nil, ca.Pool(), "agent.trstctl.local", nil)
	if cc.MinVersion != tls.VersionTLS13 || cc.MaxVersion != tls.VersionTLS13 {
		t.Errorf("client TLS = %d..%d, want 1.3 pinned", cc.MinVersion, cc.MaxVersion)
	}
}

// TestAEADOnly is the build-time check: only AEAD cipher suites are permitted.
func TestAEADOnly(t *testing.T) {
	if err := aeadOnly(aeadCipherSuites); err != nil {
		t.Errorf("the AEAD allowlist must satisfy aeadOnly: %v", err)
	}
	for _, bad := range []uint16{
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	} {
		if err := aeadOnly([]uint16{bad}); err == nil {
			t.Errorf("aeadOnly accepted non-AEAD suite 0x%04x", bad)
		}
	}
}
