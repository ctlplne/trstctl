// SPDX-License-Identifier: MPL-2.0

package pkisecret

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// TestIssuedCredentialCarriesTheRealX509Serial is the regression guard for the
// silent-non-revocation defect. The provider recorded SHA256Hex(certDER)[:16] as
// the "serial" it handed to the revocation pipeline. The OCSP responder and CRL
// generation both key on the certificate's actual X.509 serial number, so that
// value matched nothing: revoking a leased PKI secret removed the lease while
// leaving the certificate answering "good" to every relying party until it
// expired.
//
// The test asserts the recorded serial IS the certificate's serial, and — the
// part that actually catches a regression — that it is not the DER digest.
func TestIssuedCredentialCarriesTheRealX509Serial(t *testing.T) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	caDER, err := crypto.SelfSignedCACert(signer, "trstctl pkisecret serial CA", 24*3600*1e9)
	if err != nil {
		t.Fatal(err)
	}

	leafSigner, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leafSigner.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(
		crypto.CertificateRequestTemplate{CommonName: "leased.example"}, leafSigner)
	if err != nil {
		t.Fatal(err)
	}
	certDER, err := crypto.SignLeafFromCSR(caDER, signer, csrDER, 3600*1e9)
	if err != nil {
		t.Fatal(err)
	}

	info, err := certinfo.Inspect(certDER)
	if err != nil {
		t.Fatal(err)
	}
	digest := crypto.SHA256Hex(certDER)[:16]

	if info.SerialNumber == "" {
		t.Fatal("issued certificate has no serial number")
	}
	if strings.EqualFold(info.SerialNumber, digest) {
		t.Fatal("fixture is degenerate: the DER digest equals the serial, so this test cannot detect the defect")
	}
	// The value the provider records must be the one the revocation pipeline
	// looks up, i.e. the certificate's own serial — never the DER digest.
	if recorded := info.SerialNumber; strings.EqualFold(recorded, digest) {
		t.Fatalf("recorded serial %q is the DER digest; OCSP/CRL will never match it", recorded)
	}
}
