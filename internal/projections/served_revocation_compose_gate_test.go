package projections_test

import (
	"os"
	"strings"
	"testing"
)

// TestServedRevocationComposeGateAssertsOCSPAndCRL locks CORRECT-102's live
// compose proof: the shipped Docker stack must check the actual revoked serial
// through both relying-party surfaces, not only prove the endpoints are mounted.
func TestServedRevocationComposeGateAssertsOCSPAndCRL(t *testing.T) {
	body, err := os.ReadFile("../../scripts/ci/compose-e2e.sh")
	if err != nil {
		t.Fatalf("read compose e2e gate: %v", err)
	}
	script := string(body)
	for _, want := range []string{
		`SERIAL="$(certificate_field serial)"`,
		`"$BASE_URL/ocsp/$TENANT" -o "$ocsp_resp"`,
		`openssl ocsp -respin "$ocsp_resp"`,
		`cert status: revoked`,
		`"$BASE_URL/crl/$TENANT" -o "$crl_der"`,
		`openssl crl -inform DER -in "$crl_der" -CAfile served-ca.pem -verify`,
		`CRL lists revoked serial $SERIAL`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("compose e2e does not assert served revocation OCSP/CRL state; missing %q", want)
		}
	}
}
