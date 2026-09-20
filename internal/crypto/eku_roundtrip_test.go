// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestEveryGoExtKeyUsageRoundTripsThroughTheSigningPath is the assertion
// eku_totality_test.go was missing (AUD-201 follow-up E1/V13): rendering
// became total, but three IPsec names and unrecognized-eku-N were tokens
// caExtKeyUsage could not parse back — so a parent CA carrying one of them
// hard-failed child issuance ("unsupported CA extended key usage") where the
// pre-totality code had silently dropped it and issued. Every EKU value the
// current Go release defines must render as something the signing path parses
// back to the same capability.
func TestEveryGoExtKeyUsageRoundTripsThroughTheSigningPath(t *testing.T) {
	for u := x509.ExtKeyUsageAny; u <= x509.ExtKeyUsageMicrosoftKernelCodeSigning; u++ {
		emitted := extKeyUsageString(u)
		if strings.HasPrefix(emitted, "unrecognized-eku-") {
			t.Errorf("usage %d renders as %q; add its OID to certinfo.ExtKeyUsageOID so issuance can parse it", u, emitted)
			continue
		}
		known, custom, err := caExtKeyUsage([]string{emitted})
		if err != nil {
			t.Errorf("usage %d renders as %q which the signing path cannot parse back: %v", u, emitted, err)
			continue
		}
		switch {
		case len(known) == 1 && len(custom) == 0:
			if known[0] != u {
				t.Errorf("usage %d round-tripped to usage %d via %q", u, known[0], emitted)
			}
		case len(known) == 0 && len(custom) == 1:
			// A dotted OID: it must be the exact OID for this usage, so the
			// issued certificate asserts the same capability.
			if want := wellKnownEKUOID(u); want == "" || custom[0].String() != want {
				t.Errorf("usage %d round-tripped to OID %s, want %s", u, custom[0], want)
			}
		default:
			t.Errorf("usage %d round-tripped to %d known + %d custom usages via %q", u, len(known), len(custom), emitted)
		}
	}

	// Canary for the loop's upper bound: the value one past the last constant
	// this test knows about must hit the unrecognized fallback. When Go adds a
	// new ExtKeyUsage this fails, and the loop bound plus certinfo's OID table
	// must both be extended.
	beyond := x509.ExtKeyUsageMicrosoftKernelCodeSigning + 1
	if got := extKeyUsageString(beyond); !strings.HasPrefix(got, "unrecognized-eku-") {
		t.Errorf("usage %d (beyond the known range) renders as %q; extend this test's loop bound", beyond, got)
	}
}

// wellKnownEKUOID pins the dotted OIDs independently of certinfo, so a typo in
// the shared table cannot round-trip to the WRONG capability and still pass.
func wellKnownEKUOID(u x509.ExtKeyUsage) string {
	switch u {
	case x509.ExtKeyUsageIPSECEndSystem:
		return "1.3.6.1.5.5.7.3.5"
	case x509.ExtKeyUsageIPSECTunnel:
		return "1.3.6.1.5.5.7.3.6"
	case x509.ExtKeyUsageIPSECUser:
		return "1.3.6.1.5.5.7.3.7"
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return "1.3.6.1.4.1.311.10.3.3"
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return "2.16.840.1.113730.4.1"
	case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
		return "1.3.6.1.4.1.311.2.1.22"
	case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
		return "1.3.6.1.4.1.311.61.1.1"
	default:
		return ""
	}
}

// TestIntermediateMintsUnderImportedRootWithIPsecAndSGCEKUs is the end-to-end
// half: a parent CA asserting ipsecTunnel + MicrosoftServerGatedCrypto (the
// shape of an imported ADCS/enterprise root reaching us via ImportOfflineRoot
// or ImportExisting) must mint a child intermediate, and the child must carry
// the intended inherited set. Before the fix this hard-failed: EKU inheritance
// rendered "ipsecTunnel", and caExtKeyUsage aborted issuance with
// "unsupported CA extended key usage".
func TestIntermediateMintsUnderImportedRootWithIPsecAndSGCEKUs(t *testing.T) {
	parentKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer parentKey.Destroy()
	adapter, err := newX509Signer(parentKey)
	if err != nil {
		t.Fatal(err)
	}

	// The parent is built the way an import delivers it: an externally created
	// CA certificate whose EKU extension carries usages our profile table does
	// not name. Crafted with x509 directly — inside the crypto boundary —
	// standing in for a certificate created by an external CA stack.
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Imported Enterprise Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(6 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageIPSECTunnel, x509.ExtKeyUsageMicrosoftServerGatedCrypto},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}
	parentDER, err := x509.CreateCertificate(rand.Reader, template, template, adapter.Public(), adapter)
	if err != nil {
		t.Fatalf("create imported-root fixture: %v", err)
	}

	childKey, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer childKey.Destroy()

	issued, err := SignIntermediateHierarchyCA(parentDER, parentKey, childKey.Public(), HierarchyCAProfile{
		CommonName: "Issuing CA 1",
		TTL:        time.Hour * 24 * 365,
		MaxPathLen: 0,
	})
	if err != nil {
		t.Fatalf("minting under an imported root with IPsec/SGC EKUs must succeed, got: %v", err)
	}

	child, err := x509.ParseCertificate(issued.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	got := extKeyUsageStringsForCertificate(child)
	want := []string{"1.3.6.1.5.5.7.3.6", "1.3.6.1.4.1.311.10.3.3"}
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("child EKUs = %v, missing inherited %s", got, w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("child EKUs = %v, want exactly the inherited pair %v", got, want)
	}
}
