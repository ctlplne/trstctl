// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/x509"
	"encoding/asn1"
	"slices"
	"testing"
)

// TestExtKeyUsageStringsNeverSilentlyDrops is the regression guard for the
// ceremony-bypass defect. extKeyUsageStrings listed five usages and silently
// dropped everything else, so a CA carrying [serverAuth, ocspSigning] rendered
// as ["serverAuth"] and compared EQUAL to a reviewed profile of ["serverAuth"].
// The ceremony then accepted a more capable authority than it had approved —
// one able to sign OCSP responses, or timestamps, on behalf of the tenant.
func TestExtKeyUsageStringsNeverSilentlyDrops(t *testing.T) {
	all := []x509.ExtKeyUsage{
		x509.ExtKeyUsageAny,
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageCodeSigning,
		x509.ExtKeyUsageEmailProtection,
		x509.ExtKeyUsageIPSECEndSystem,
		x509.ExtKeyUsageIPSECTunnel,
		x509.ExtKeyUsageIPSECUser,
		x509.ExtKeyUsageTimeStamping,
		x509.ExtKeyUsageOCSPSigning,
		x509.ExtKeyUsageMicrosoftServerGatedCrypto,
		x509.ExtKeyUsageNetscapeServerGatedCrypto,
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
		x509.ExtKeyUsageMicrosoftKernelCodeSigning,
	}
	got := extKeyUsageStrings(all)
	if len(got) != len(all) {
		t.Fatalf("rendered %d tokens for %d usages; a usage was dropped and would vanish from a profile comparison",
			len(got), len(all))
	}

	// The two that mattered most must be named, not merely present.
	for _, want := range []string{"timeStamping", "ocspSigning"} {
		if !slices.Contains(got, want) {
			t.Errorf("%q is not rendered; a CA asserting it would compare equal to a profile without it", want)
		}
	}
}

// TestExtKeyUsageComparisonFailsOnExtraUsage is the property that actually
// protects the ceremony: a certificate MORE capable than the reviewed profile
// must not compare equal to it.
func TestExtKeyUsageComparisonFailsOnExtraUsage(t *testing.T) {
	reviewed := []string{"serverAuth"}
	actual := extKeyUsageStrings([]x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageOCSPSigning,
	})
	if sameStringSet(reviewed, actual) {
		t.Fatal("a CA that can also sign OCSP responses compared equal to a serverAuth-only profile")
	}
}

// TestExtKeyUsageIncludesCustomOIDs pins the other half: Go parks unrecognized
// usages in UnknownExtKeyUsage, so a comparison that reads only ExtKeyUsage
// ignores a custom OID entirely.
func TestExtKeyUsageIncludesCustomOIDs(t *testing.T) {
	cert := &x509.Certificate{
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}},
	}
	got := extKeyUsageStringsForCertificate(cert)
	if !slices.Contains(got, "1.3.6.1.4.1.311.20.2.2") {
		t.Fatalf("custom-OID usage missing from %v; it would be invisible to the profile check", got)
	}
	if sameStringSet([]string{"serverAuth"}, got) {
		t.Fatal("a certificate asserting a custom OID compared equal to a serverAuth-only profile")
	}
}
