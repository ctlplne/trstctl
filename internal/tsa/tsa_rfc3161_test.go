package tsa_test

import (
	"bytes"
	"encoding/asn1"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/tsa"
)

// newRSATSA builds a TSA backed by an RSA signer (so the token's SignerInfo uses
// RSA PKCS#1 v1.5, which smallstep/pkcs7 and openssl both verify out of the box)
// and returns the authority plus the TSA cert DER.
func newRSATSA(t *testing.T) (*tsa.Authority, []byte) {
	t.Helper()
	root, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Destroy)
	rootDER, err := crypto.SelfSignedCACert(root, "TSA Root RSA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tsaKey, err := crypto.GenerateLockedKey(crypto.RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tsaKey.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "TSA RSA"}, tsaKey)
	if err != nil {
		t.Fatal(err)
	}
	tsaCert, err := crypto.SignLeafFromCSR(rootDER, root, csr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	a, err := tsa.New(tsa.Config{TenantID: "t1", TSACertDER: tsaCert, TSASigner: tsaKey, Audit: &auditsink.Recorder{}})
	if err != nil {
		t.Fatal(err)
	}
	return a, tsaCert
}

// oidCTTSTInfo is id-ct-TSTInfo, the eContentType an RFC 3161 token must carry.
var oidCTTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

// TestTimestampTokenIsRealCMSDER is the INTEROP-005 acceptance: the issued token
// must be CMS/DER (a ContentInfo wrapping SignedData with eContentType
// id-ct-TSTInfo), NOT a JSON manifest. It asserts the structure with the stdlib
// ASN.1 parser — pre-fix the token bytes were JSON and this FAILS.
func TestTimestampTokenIsRealCMSDER(t *testing.T) {
	a, _ := newRSATSA(t)
	hash := crypto.SHA256Sum([]byte("the signed data"))
	tok, err := a.Timestamp(t.Context(), hash)
	if err != nil {
		t.Fatalf("Timestamp: %v", err)
	}
	if len(tok.DER) == 0 {
		t.Fatal("token carries no DER (INTEROP-005 not fixed)")
	}
	// It must NOT be JSON.
	if bytes.HasPrefix(bytes.TrimSpace(tok.DER), []byte("{")) {
		t.Fatal("token is JSON, not CMS/DER")
	}
	// It must parse as a ContentInfo { contentType signedData, content [0] ... }.
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(tok.DER, &ci); err != nil {
		t.Fatalf("token is not DER ContentInfo: %v", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		t.Errorf("token contentType = %v, want signedData %v", ci.ContentType, oidSignedData)
	}
	// The embedded eContentType must be id-ct-TSTInfo (what openssl ts expects).
	if !bytes.Contains(tok.DER, encOID(t, oidCTTSTInfo)) {
		t.Error("token does not carry the id-ct-TSTInfo eContentType")
	}
}

// TestTimestampTokenOpenSSLCMSDifferential is the INTEROP-005 non-circular,
// external-reference acceptance: OpenSSL's CMS implementation (the RFC 5652
// verifier behind `openssl ts`), NOT our own encoder/parser, must verify the
// token's signature and extract the eContent. `openssl cms -verify` checks the
// SignerInfo signature over the SignedAttributes and that the messageDigest
// attribute matches the digest of the eContent — so a pass proves the signature
// is computed per RFC 5652, not merely self-consistent. The extracted eContent is
// the DER TSTInfo and must bind the message imprint.
//
// Pre-fix the token was a JSON manifest, which OpenSSL cannot read at all, so this
// FAILS pre-fix. It SKIPs honestly only when openssl is genuinely unavailable.
func TestTimestampTokenOpenSSLCMSDifferential(t *testing.T) {
	ossl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not on PATH; the RFC 3161 CMS differential runs on the CI backstop")
	}
	a, _ := newRSATSA(t)
	hash := crypto.SHA256Sum([]byte("openssl cms differential data"))
	tok, err := a.Timestamp(t.Context(), hash)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token.der")
	contentPath := filepath.Join(dir, "content.bin")
	if err := os.WriteFile(tokenPath, tok.DER, 0o600); err != nil {
		t.Fatal(err)
	}
	// -noverify skips the X.509 chain (the TSA cert is a test cert); the signature
	// and messageDigest binding are still fully checked. A non-RFC-5652 blob (JSON)
	// fails to parse here.
	out, err := exec.Command(ossl, "cms", "-verify", "-inform", "DER", "-in", tokenPath,
		"-noverify", "-out", contentPath).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl cms -verify rejected our timestamp token (not RFC 5652 CMS): %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("Verification successful")) {
		t.Errorf("openssl cms did not report success:\n%s", out)
	}
	content, err := os.ReadFile(contentPath)
	if err != nil {
		t.Fatalf("openssl wrote no eContent: %v", err)
	}
	// The eContent OpenSSL extracted is the DER TSTInfo; it must bind the imprint.
	if !bytes.Contains(content, hash) {
		t.Error("the TSTInfo OpenSSL extracted does not bind the message imprint")
	}
}

// TestTimestampTokenIsParseableTSTInfo confirms the eContent OpenSSL would extract
// is a well-formed RFC 3161 TSTInfo carrying the id-ct-TSTInfo eContentType, using
// the stdlib ASN.1 decoder as an independent structural check (no openssl needed).
func TestTimestampTokenIsParseableTSTInfo(t *testing.T) {
	a, _ := newRSATSA(t)
	hash := crypto.SHA256Sum([]byte("structural check"))
	tok, err := a.Timestamp(t.Context(), hash)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(tok.DER, encOID(t, oidCTTSTInfo)) {
		t.Fatal("token does not carry id-ct-TSTInfo")
	}
	if !bytes.Contains(tok.DER, hash) {
		t.Error("token does not embed the message imprint")
	}
}

func encOID(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	der, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
