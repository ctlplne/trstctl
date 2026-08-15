// SPDX-License-Identifier: MPL-2.0

// This test lives in package crypto (not crypto_test) because it must build a
// tls.ConnectionState and parse certificates directly, and AN-3 confines
// crypto/tls and crypto/x509 imports to this package.
package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

// TestVerifyTLSClientCertificateRejectsUntrustedIssuer is the negative-path guard
// for the EST mTLS authorization gate. VerifyTLSClientCertificate is what
// internal/protocols/est authorizes /simpleenroll, /simplereenroll and
// /serverkeygen with: if it returns nil, the caller is an enrolled client and the
// tenant CA will issue to it.
//
// Before this test the function had NO test reference anywhere in the repo, so
// deleting the x509 chain build inside it left the entire suite green while any
// self-signed certificate authenticated as an enrolled EST client. The negative
// case below is the one that dies when the chain check is removed; the positive
// case keeps it honest, so a function that simply always errors also fails.
func TestVerifyTLSClientCertificateRejectsUntrustedIssuer(t *testing.T) {
	trustedSigner, err := GenerateLockedKey(RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(trustedSigner.Destroy)
	trustedDER, err := SelfSignedCACert(trustedSigner, "trstctl EST client CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	trustedCert, err := x509.ParseCertificate(trustedDER)
	if err != nil {
		t.Fatal(err)
	}

	// A CA the deployment never configured — the attacker's own.
	foreignSigner, err := GenerateLockedKey(RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(foreignSigner.Destroy)
	foreignDER, err := SelfSignedCACert(foreignSigner, "attacker CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	foreignCert, err := x509.ParseCertificate(foreignDER)
	if err != nil {
		t.Fatal(err)
	}

	// The attack: present a certificate from an untrusted issuer to a server that
	// trusts only trustedDER. This MUST be refused.
	foreignState := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{foreignCert}}
	if err := VerifyTLSClientCertificate(foreignState, [][]byte{trustedDER}); err == nil {
		t.Fatal("client certificate from an untrusted issuer was accepted; the EST mTLS gate authorizes any self-signed certificate")
	}

	// Control: a certificate that does chain to the configured anchor is accepted,
	// so the guard above cannot be satisfied by a blanket rejection.
	trustedState := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{trustedCert}}
	if err := VerifyTLSClientCertificate(trustedState, [][]byte{trustedDER}); err != nil {
		t.Fatalf("client certificate chaining to the configured anchor must be accepted: %v", err)
	}

	// No peer certificate at all is refused.
	if err := VerifyTLSClientCertificate(&tls.ConnectionState{}, [][]byte{trustedDER}); err == nil {
		t.Fatal("a connection with no client certificate must be refused")
	}

	// An empty trust pool is refused rather than silently falling back to the
	// host's system roots, which would trust every public CA.
	if err := VerifyTLSClientCertificate(foreignState, nil); err == nil {
		t.Fatal("an empty trust-anchor pool must be refused, not treated as 'trust anything'")
	}
}
