// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// testMLDSASigner is an in-package ML-DSA-65 key standing in for the
// signer-held one: it signs whatever bytes it is handed, as the isolated
// signer does for a pure-message request.
type testMLDSASigner struct {
	pub  []byte
	priv *mldsa65.PrivateKey
}

func newTestMLDSASigner(t *testing.T) *testMLDSASigner {
	t.Helper()
	pub, priv, err := mldsa65.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := pub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return &testMLDSASigner{pub: raw, priv: priv}
}

func (s *testMLDSASigner) Public() PublicKey {
	return PublicKey{Algorithm: Algorithm("ML-DSA-65"), DER: s.pub}
}
func (s *testMLDSASigner) Algorithm() Algorithm { return Algorithm("ML-DSA-65") }
func (s *testMLDSASigner) SignDigest(digest []byte, opts SignOptions) ([]byte, error) {
	return s.Sign(digest, opts)
}
func (s *testMLDSASigner) Sign(message []byte, _ SignOptions) ([]byte, error) {
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(s.priv, message, nil, false, sig); err != nil {
		return nil, err
	}
	return sig, nil
}

func requireOpenSSLWithMLDSA(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Skipf("stock OpenSSL is required for ML-DSA interoperability: %v", err)
	}
	out, err := exec.Command(path, "list", "-signature-algorithms").CombinedOutput() // #nosec G204 -- LookPath-resolved OpenSSL with fixed arguments
	if err != nil || !bytes.Contains(out, []byte("ML-DSA-65")) {
		t.Skipf("OpenSSL at %s lacks ML-DSA-65: %v", path, err)
	}
	return path
}

func openssl(t *testing.T, bin string, args ...string) string {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput() // #nosec G204 -- LookPath-resolved OpenSSL; arguments are test-owned paths and flags
	if err != nil {
		t.Fatalf("openssl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func writePEM(t *testing.T, dir, name, kind string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// P10 done-when: an ML-DSA-65 root and intermediate issue leaves whose chain,
// CRL and OCSP responses verify with stock OpenSSL, through the same builders
// the served hierarchy uses, with the CA key behind the DigestSigner seam.
func TestMLDSAHierarchyChainCRLAndOCSPVerifyWithOpenSSL(t *testing.T) {
	ossl := requireOpenSSLWithMLDSA(t)
	dir := t.TempDir()
	rootKey := newTestMLDSASigner(t)
	root, err := SelfSignedHierarchyCA(rootKey, HierarchyCAProfile{CommonName: "PQ Pilot Root", MaxPathLen: 1, TTL: 48 * time.Hour})
	if err != nil {
		t.Fatalf("ML-DSA root: %v", err)
	}
	interKey := newTestMLDSASigner(t)
	inter, err := SignIntermediateHierarchyCA(root.CertificateDER, rootKey, interKey.Public(), HierarchyCAProfile{
		CommonName: "PQ Pilot Issuing CA", MaxPathLen: 0, TTL: 24 * time.Hour, PermittedDNSDomains: []string{"pq.example.test"},
	})
	if err != nil {
		t.Fatalf("ML-DSA intermediate: %v", err)
	}
	for _, c := range []struct {
		name string
		der  []byte
	}{{"root", root.CertificateDER}, {"intermediate", inter.CertificateDER}} {
		cert, err := x509.ParseCertificate(c.der)
		if err != nil || cert.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm || !cert.IsCA {
			t.Fatalf("%s parses as %+v err=%v; want an ML-DSA CA", c.name, cert, err)
		}
		if pub, pure, err := purePublicKeyOfCertificate(cert); err != nil || !pure || pub.Algorithm != "ML-DSA-65" {
			t.Fatalf("%s public key = %+v pure=%v err=%v", c.name, pub.Algorithm, pure, err)
		}
	}
	rootCert, _ := x509.ParseCertificate(root.CertificateDER)
	interCert, _ := x509.ParseCertificate(inter.CertificateDER)
	if err := VerifyCertificateIssuedBy(interCert, rootCert); err != nil {
		t.Fatalf("intermediate under root: %v", err)
	}
	if err := VerifyCertificateIssuedBy(rootCert, rootCert); err != nil {
		t.Fatalf("root self-signature: %v", err)
	}

	// A classical subject (ECDSA host key) under the ML-DSA issuing CA.
	hostKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer hostKey.Destroy()
	csr, err := CreateCertificateRequest(CertificateRequestTemplate{CommonName: "host.pq.example.test", DNSNames: []string{"host.pq.example.test"}}, hostKey)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaLeaf, err := SignLeafFromCSRWithProfile(inter.CertificateDER, interKey, csr, 2*time.Hour, LeafProfile{ClampTTLToIssuer: true})
	if err != nil {
		t.Fatalf("ECDSA leaf under ML-DSA CA: %v", err)
	}
	// A pure ML-DSA subject under the same CA (RFC 9881 end to end).
	subject := newTestMLDSASigner(t)
	pqCSR, err := CreateOpaqueCertificateRequest(CertificateRequestTemplate{CommonName: "pq.pq.example.test", DNSNames: []string{"pq.pq.example.test"}}, mldsaX509OIDs["ML-DSA-65"].String(), subject)
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := InspectOpaqueCSR(pqCSR)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPureSignature(subject.Public(), opaque.RawTBS, opaque.Signature); err != nil {
		t.Fatalf("ML-DSA CSR proof of possession: %v", err)
	}
	opaque.Info.KeyAlgorithm = "ML-DSA-65"
	pqLeaf, err := SignOpaqueLeafFromVerifiedRequestWithProfile(inter.CertificateDER, interKey, OpaqueLeafRequest{
		Info: opaque.Info, RawSubject: opaque.RawSubject, SubjectPublicKeyInfoDER: opaque.RawSubjectPublicKeyInfo, SignatureOnly: true,
	}, 2*time.Hour, LeafProfile{ClampTTLToIssuer: true})
	if err != nil {
		t.Fatalf("ML-DSA leaf under ML-DSA CA: %v", err)
	}
	for _, leaf := range [][]byte{ecdsaLeaf, pqLeaf} {
		cert, err := x509.ParseCertificate(leaf)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyCertificateIssuedBy(cert, interCert); err != nil {
			t.Fatalf("leaf %s under intermediate: %v", cert.Subject.CommonName, err)
		}
		if !bytes.Equal(cert.AuthorityKeyId, interCert.SubjectKeyId) {
			t.Fatalf("leaf %s AKI %x != issuer SKI %x", cert.Subject.CommonName, cert.AuthorityKeyId, interCert.SubjectKeyId)
		}
	}

	// Stock OpenSSL builds and verifies the whole post-quantum chain.
	rootPEM := writePEM(t, dir, "root.pem", "CERTIFICATE", root.CertificateDER)
	interPEM := writePEM(t, dir, "inter.pem", "CERTIFICATE", inter.CertificateDER)
	// openssl ocsp takes the trust chain as one CAfile (it has no -untrusted).
	chainPEM := filepath.Join(dir, "chain.pem")
	if err := os.WriteFile(chainPEM, append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.CertificateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter.CertificateDER})...), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, der := range map[string][]byte{"ecdsa-leaf.pem": ecdsaLeaf, "pq-leaf.pem": pqLeaf} {
		leafPEM := writePEM(t, dir, name, "CERTIFICATE", der)
		out := openssl(t, ossl, "verify", "-CAfile", rootPEM, "-untrusted", interPEM, leafPEM)
		if !strings.Contains(out, ": OK") {
			t.Fatalf("openssl verify %s: %s", name, out)
		}
	}
	text := openssl(t, ossl, "x509", "-in", interPEM, "-noout", "-text")
	if !strings.Contains(text, "ML-DSA-65") {
		t.Fatalf("openssl does not report ML-DSA-65 on the intermediate:\n%s", text)
	}

	// The issuing CA revokes the ECDSA leaf: CRL and OCSP both carry its
	// pure signature and verify with OpenSSL and with the boundary's parsers.
	leafCert, _ := x509.ParseCertificate(ecdsaLeaf)
	serial := leafCert.SerialNumber.Text(16)
	now := time.Now().UTC().Truncate(time.Second)
	crlDER, err := CreateCRL(inter.CertificateDER, interKey, []RevokedSerial{{Serial: serial, RevokedAt: now, Reason: 1}}, 7, now, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("ML-DSA CRL: %v", err)
	}
	info, err := ParseCRL(crlDER, inter.CertificateDER)
	if err != nil || len(info.RevokedSerials) != 1 || info.Number != 7 {
		t.Fatalf("ParseCRL = %+v err=%v", info, err)
	}
	if _, err := ParseCRL(crlDER, root.CertificateDER); err == nil {
		t.Fatal("the CRL verified against the wrong ML-DSA issuer")
	}
	crlPath := filepath.Join(dir, "crl.der")
	if err := os.WriteFile(crlPath, crlDER, 0o600); err != nil {
		t.Fatal(err)
	}
	out := openssl(t, ossl, "crl", "-inform", "DER", "-in", crlPath, "-CAfile", interPEM, "-noout")
	if !strings.Contains(out, "verify OK") {
		t.Fatalf("openssl crl verify: %q", out)
	}

	ocspDER, err := SignOCSPResponse(inter.CertificateDER, interKey, OCSPRevoked, serial, now, now.Add(10*time.Minute), now, 1)
	if err != nil {
		t.Fatalf("ML-DSA OCSP response: %v", err)
	}
	status, err := ParseOCSPResponse(ocspDER, inter.CertificateDER)
	if err != nil || status.Status != OCSPRevoked || !status.ResponderIsIssuer {
		t.Fatalf("ParseOCSPResponse = %+v err=%v", status, err)
	}
	if _, err := ParseOCSPResponse(ocspDER, root.CertificateDER); err == nil {
		t.Fatal("the OCSP response verified against the wrong ML-DSA issuer")
	}
	ocspPath := filepath.Join(dir, "ocsp.der")
	if err := os.WriteFile(ocspPath, ocspDER, 0o600); err != nil {
		t.Fatal(err)
	}
	out = openssl(t, ossl, "ocsp", "-respin", ocspPath, "-issuer", interPEM, "-CAfile", chainPEM, "-no_nonce", "-resp_text")
	if !strings.Contains(out, "Response verify OK") || !strings.Contains(out, "revoked") {
		t.Fatalf("openssl ocsp verify: %s", out)
	}

	// A delegated classical responder certified by the ML-DSA CA.
	responderKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer responderKey.Destroy()
	responderDER, err := CreateOCSPResponderCertificate(inter.CertificateDER, interKey, responderKey, "PQ OCSP Responder", now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("responder certificate under ML-DSA CA: %v", err)
	}
	delegated, err := SignDelegatedOCSPResponse(inter.CertificateDER, responderDER, responderKey, OCSPGood, serial, now, now.Add(10*time.Minute), time.Time{}, 0)
	if err != nil {
		t.Fatalf("delegated OCSP response: %v", err)
	}
	status, err = ParseOCSPResponse(delegated, inter.CertificateDER)
	if err != nil || status.Status != OCSPGood || status.ResponderIsIssuer || !status.ResponderHasOCSPSigningEKU {
		t.Fatalf("delegated ParseOCSPResponse = %+v err=%v", status, err)
	}
	delegatedPath := filepath.Join(dir, "ocsp-delegated.der")
	if err := os.WriteFile(delegatedPath, delegated, 0o600); err != nil {
		t.Fatal(err)
	}
	out = openssl(t, ossl, "ocsp", "-respin", delegatedPath, "-issuer", interPEM, "-CAfile", chainPEM, "-no_nonce")
	if !strings.Contains(out, "Response verify OK") {
		t.Fatalf("openssl delegated ocsp verify: %s", out)
	}
}

// The classical hierarchy keeps working beside the post-quantum one, and a
// classical root can certify an ML-DSA intermediate (the transition shape).
func TestClassicalRootCertifiesMLDSAIntermediate(t *testing.T) {
	rootKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer rootKey.Destroy()
	root, err := SelfSignedHierarchyCA(rootKey, HierarchyCAProfile{CommonName: "Classical Root", MaxPathLen: 1, TTL: 48 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	interKey := newTestMLDSASigner(t)
	inter, err := SignIntermediateHierarchyCA(root.CertificateDER, rootKey, interKey.Public(), HierarchyCAProfile{CommonName: "PQ Issuing CA", TTL: 24 * time.Hour})
	if err != nil {
		t.Fatalf("ML-DSA intermediate under a classical root: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(root.CertificateDER)
	interCert, err := x509.ParseCertificate(inter.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := interCert.CheckSignatureFrom(rootCert); err != nil {
		t.Fatalf("classical signature over the ML-DSA intermediate: %v", err)
	}
	if pub, pure, err := purePublicKeyOfCertificate(interCert); err != nil || !pure || len(pub.DER) != mldsa65.PublicKeySize {
		t.Fatalf("intermediate key = %+v pure=%v err=%v", pub.Algorithm, pure, err)
	}
	if !bytes.Equal(interCert.SubjectKeyId, pureSubjectKeyID(interKey.Public())) {
		t.Fatal("intermediate SKI is not the method-1 identifier of its ML-DSA key")
	}
}
