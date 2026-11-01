// SPDX-License-Identifier: BUSL-1.1

package crypto

import "testing"

// A CSR's requested key usage reads back the bits a client asked for (P15).
func TestCSRRequestedKeyUsageP15(t *testing.T) {
	key, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	for name, tc := range map[string]struct {
		ds, nr, ke bool
		want       CSRKeyUsageRequest
	}{
		"signing":              {ds: true, want: CSRKeyUsageRequest{Present: true, DigitalSignature: true}},
		"signing and commit":   {ds: true, nr: true, want: CSRKeyUsageRequest{Present: true, DigitalSignature: true, ContentCommitment: true}},
		"signing and encrypt":  {ds: true, ke: true, want: CSRKeyUsageRequest{Present: true, DigitalSignature: true, Other: true}},
		"encryption only":      {ke: true, want: CSRKeyUsageRequest{Present: true, Other: true}},
		"content commit alone": {nr: true, want: CSRKeyUsageRequest{Present: true, ContentCommitment: true}},
	} {
		ext, err := KeyUsageRequestExtension(tc.ds, tc.nr, tc.ke)
		if err != nil {
			t.Fatal(err)
		}
		der, err := CreateCertificateRequest(CertificateRequestTemplate{EmailAddresses: []string{"alice@example.com"}, ExtraExtensions: []CertificateExtension{ext}}, key)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := CSRRequestedKeyUsage(der); err != nil || got != tc.want {
			t.Fatalf("%s: %+v %v, want %+v", name, got, err, tc.want)
		}
	}
	der, err := CreateCertificateRequest(CertificateRequestTemplate{EmailAddresses: []string{"alice@example.com"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := CSRRequestedKeyUsage(der); err != nil || got.Present {
		t.Fatalf("no key usage: %+v %v", got, err)
	}
	if _, err := KeyUsageRequestExtension(false, false, false); err == nil {
		t.Fatal("an empty key usage was built")
	}
}
