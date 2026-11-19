// SPDX-License-Identifier: BUSL-1.1

// This test lives in package crypto (not crypto_test) because it must build a
// tls.ConnectionState and parse certificates directly, and AN-3 confines
// crypto/tls and crypto/x509 imports to this package.
package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// TestVerifyTLSClientCertificateRejectsUntrustedIssuer is the negative-path guard
// for the EST mTLS authorization gate. VerifyTLSClientCertificate is the first
// check internal/protocols/est runs on a mutual-TLS renewal: the leaf it returns
// then goes to the mount's own client certificate check.
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
	if _, err := VerifyTLSClientCertificate(foreignState, [][]byte{trustedDER}); err == nil {
		t.Fatal("client certificate from an untrusted issuer was accepted; the EST mTLS gate authorizes any self-signed certificate")
	}

	// Control: a clientAuth leaf the configured anchor issued is accepted and its
	// DER returned, so the guard above cannot be satisfied by a blanket rejection.
	caSigner, err := newX509Signer(trustedSigner)
	if err != nil {
		t.Fatal(err)
	}
	clientLeaf := issueTestClientLeaf(t, trustedCert, caSigner, x509.ExtKeyUsageClientAuth)
	leafDER, err := VerifyTLSClientCertificate(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientLeaf}}, [][]byte{trustedDER})
	if err != nil {
		t.Fatalf("a clientAuth leaf issued by the configured anchor must be accepted: %v", err)
	}
	if !bytes.Equal(leafDER, clientLeaf.Raw) {
		t.Fatal("the verified leaf's DER was not returned")
	}

	// No peer certificate at all is refused.
	if _, err := VerifyTLSClientCertificate(&tls.ConnectionState{}, [][]byte{trustedDER}); err == nil {
		t.Fatal("a connection with no client certificate must be refused")
	}

	// An empty trust pool is refused rather than silently falling back to the
	// host's system roots, which would trust every public CA.
	if _, err := VerifyTLSClientCertificate(foreignState, nil); err == nil {
		t.Fatal("an empty trust-anchor pool must be refused, not treated as 'trust anything'")
	}
}

// TestTLSClientCertificateMustBeAClientAuthLeafTheAnchorIssuedDirectly: the EST
// mutual-TLS listener trusts the platform issuing CA every tenant shares, so the
// presented certificate must be a clientAuth leaf that CA issued itself (CR-059).
func TestTLSClientCertificateMustBeAClientAuthLeafTheAnchorIssuedDirectly(t *testing.T) {
	trustedSigner, err := GenerateLockedKey(ECDSAP256)
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
	caSigner, err := newX509Signer(trustedSigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTLSClientCertificate(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{
		issueTestClientLeaf(t, trustedCert, caSigner, x509.ExtKeyUsageClientAuth)}}, [][]byte{trustedDER}); err != nil {
		t.Fatalf("control: a clientAuth leaf the anchor issued was refused: %v", err)
	}

	// CR-059: the leaf must list clientAuth itself. The anchor presented as its
	// own client certificate, a leaf with no EKU, an any-EKU leaf and a
	// serverAuth-only leaf are refused (the TLS handshake already refuses the
	// last; only this check refuses the others).
	for name, leaf := range map[string]*x509.Certificate{
		"the anchor itself":   trustedCert,
		"no EKU extension":    issueTestClientLeaf(t, trustedCert, caSigner),
		"anyExtendedKeyUsage": issueTestClientLeaf(t, trustedCert, caSigner, x509.ExtKeyUsageAny),
		"clientAuth and any":  issueTestClientLeaf(t, trustedCert, caSigner, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageAny),
		"serverAuth only":     issueTestClientLeaf(t, trustedCert, caSigner, x509.ExtKeyUsageServerAuth),
	} {
		if _, err := VerifyTLSClientCertificate(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}, [][]byte{trustedDER}); err == nil {
			t.Errorf("%s was accepted as an EST client certificate", name)
		}
	}

	// CR-059: only a leaf the anchor issued directly is accepted; a chain through
	// an intermediate the client supplies is refused. The anchor here permits one
	// intermediate (SelfSignedCACert's does not), and the chain is checked to be
	// valid when the intermediate is supplied, so only dropping the client's
	// intermediates can refuse it.
	rootKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rootKey.Destroy)
	rootSigner, err := newX509Signer(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "est client CA with one intermediate"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootSigner.Public(), rootSigner)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	intermediateKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(intermediateKey.Destroy)
	intermediateSigner, err := newX509Signer(intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediate := issueTestCertificate(t, root, rootSigner, intermediateSigner.Public(), true)
	viaIntermediate := issueTestClientLeaf(t, intermediate, intermediateSigner, x509.ExtKeyUsageClientAuth)
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	intermediates.AddCert(intermediate)
	if _, err := viaIntermediate.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("fixture: the chain through the intermediate must be valid: %v", err)
	}
	if _, err := VerifyTLSClientCertificate(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{viaIntermediate, intermediate}}, [][]byte{rootDER}); err == nil {
		t.Fatal("a leaf chained through a client-supplied intermediate was accepted")
	}
}

// issueTestClientLeaf issues a fresh leaf under parent with the given extended key
// usages (no EKU extension at all when none are given).
func issueTestClientLeaf(t *testing.T, parent *x509.Certificate, parentSigner *x509Signer, ekus ...x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()
	key, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	signer, err := newX509Signer(key)
	if err != nil {
		t.Fatal(err)
	}
	return issueTestCertificate(t, parent, parentSigner, signer.Public(), false, ekus...)
}

func issueTestCertificate(t *testing.T, parent *x509.Certificate, parentSigner *x509Signer, public any, isCA bool, ekus ...x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	name := "est client"
	if isCA {
		name = "est client intermediate"
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: ekus, BasicConstraintsValid: isCA, IsCA: isCA}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, public, parentSigner)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
