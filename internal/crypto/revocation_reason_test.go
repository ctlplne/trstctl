package crypto

import "testing"

func TestRevocationReasonsRoundTripToCRLReasonCodes(t *testing.T) {
	cases := []struct {
		reason RevocationReason
		code   int
	}{
		{RevocationReasonUnspecified, 0},
		{RevocationReasonKeyCompromise, 1},
		{RevocationReasonCACompromise, 2},
		{RevocationReasonAffiliationChanged, 3},
		{RevocationReasonSuperseded, 4},
		{RevocationReasonCessationOfOperation, 5},
		{RevocationReasonCertificateHold, 6},
		{RevocationReasonRemoveFromCRL, 8},
		{RevocationReasonPrivilegeWithdrawn, 9},
		{RevocationReasonAACompromise, 10},
	}
	for _, tc := range cases {
		if !IsValidRevocationReason(string(tc.reason)) {
			t.Fatalf("%q is not reported as a valid revocation reason", tc.reason)
		}
		if got := CRLReasonCode(tc.reason); got != tc.code {
			t.Fatalf("CRLReasonCode(%q) = %d, want %d", tc.reason, got, tc.code)
		}
		got, ok := RevocationReasonFromCRLCode(tc.code)
		if !ok {
			t.Fatalf("RevocationReasonFromCRLCode(%d) did not find a reason", tc.code)
		}
		if got != tc.reason {
			t.Fatalf("RevocationReasonFromCRLCode(%d) = %q, want %q", tc.code, got, tc.reason)
		}
	}
}

func TestRevocationReasonValidationRejectsUnknownNamesAndCodes(t *testing.T) {
	if IsValidRevocationReason("operator typed a paragraph") {
		t.Fatal("free-form text must not be accepted as an RFC 5280 revocation reason")
	}
	if ValidCRLReasonCode(7) {
		t.Fatal("CRL reason code 7 is unassigned in RFC 5280 and must be rejected")
	}
	if _, ok := RevocationReasonFromCRLCode(99); ok {
		t.Fatal("unknown CRL reason code 99 mapped to a reason")
	}
}
