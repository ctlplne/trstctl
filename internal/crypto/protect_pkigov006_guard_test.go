// SPDX-License-Identifier: MPL-2.0

package crypto_test

import (
	"errors"
	"os"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// PKIGOV-006 (19-PKIGOV) PROTECT regression guard.
//
// Confirmed strength: the FIPS posture is HONEST and FAIL-CLOSED. trstctl is
// FIPS-capable (it routes the standard library through the Go FIPS 140-3 module when
// built/run for it) but is NOT itself product-CMVP-certified, and the code says so;
// the power-on self-test runs a known-answer sign/verify/reject round-trip and, when
// the operator REQUIRES FIPS, fails closed with ErrFIPSRequiredButInactive if the
// module is not active. The honest residuals (product CMVP cert is external and
// an external HSM/KMS is validated by the device) are documented at the
// boundary. Anchor: internal/crypto/fips.go.
//
// Part 1 is BEHAVIORAL against the real exported PowerOnSelfTest: the known-answer
// self-test (selfTestKAT) is pure in-memory ECDSA-P256/SHA-256 — no Postgres, no NATS,
// no network — so we run it directly and assert it passes and the status reflects it.
// Part 2 is an ANCHOR-LOCK that the fail-closed sentinel and the honest residual
// documentation remain. If the self-test stops failing closed, or the honest "not
// product-certified" framing is removed, this guard goes RED.
func TestProtectPKIGOV006_PowerOnSelfTestRunsAndIsHonest(t *testing.T) {
	// Not requiring FIPS: the POST must still run the known-answer self-test and pass
	// in either build mode (the KAT uses primitives present in both the stdlib and the
	// FIPS module). This is the live sign->verify->reject check the strength describes.
	status, err := crypto.PowerOnSelfTest(false)
	if err != nil {
		t.Fatalf("PKIGOV-006: PowerOnSelfTest(false) failed: %v; the boundary's known-answer self-test must pass at boot", err)
	}
	if !status.SelfTestPassed {
		t.Fatal("PKIGOV-006: PowerOnSelfTest reported SelfTestPassed=false on success; the POST result is no longer recorded")
	}
	// The reported module-active flag must agree with the boundary's single read of the
	// FIPS state (honest reporting, not a hard-coded claim).
	if status.ModuleActive != crypto.FIPSEnabled() {
		t.Errorf("PKIGOV-006: FIPSStatus.ModuleActive (%v) disagrees with FIPSEnabled() (%v); the posture is no longer read from the real module state", status.ModuleActive, crypto.FIPSEnabled())
	}
	if status.Required {
		t.Error("PKIGOV-006: PowerOnSelfTest(false) reported Required=true; the operator did not require FIPS")
	}

	// Summary renders all three facets honestly (mode / requirement / self-test).
	summary := status.Summary()
	for _, want := range []string{"FIPS module:", "self-test"} {
		if !strings.Contains(summary, want) {
			t.Errorf("PKIGOV-006: FIPS Summary() = %q, missing %q; the posture banner must report the module + self-test state", summary, want)
		}
	}
}

func TestProtectPKIGOV006_FailClosedSentinelAndHonestResidualsAnchor(t *testing.T) {
	// The fail-closed sentinel must exist and be a real distinct error: a deployment
	// that requires FIPS but is not built for it must refuse to start.
	if crypto.ErrFIPSRequiredButInactive == nil {
		t.Fatal("PKIGOV-006: ErrFIPSRequiredButInactive is nil; the fail-closed FIPS-required signal is gone")
	}
	if !errors.Is(crypto.ErrFIPSRequiredButInactive, crypto.ErrFIPSRequiredButInactive) {
		t.Fatal("PKIGOV-006: ErrFIPSRequiredButInactive does not match itself; sentinel is malformed")
	}

	src, err := os.ReadFile("fips.go")
	if err != nil {
		t.Fatalf("PKIGOV-006 anchor: cannot read fips.go: %v", err)
	}
	body := string(src)

	// The fail-closed control flow: required && !module-active -> return the sentinel.
	for _, needle := range []string{
		"func PowerOnSelfTest(",
		"if required && !status.ModuleActive {",
		"return status, ErrFIPSRequiredButInactive",
		"if err := selfTestKAT(); err != nil {", // always runs the KAT, even when not required
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("PKIGOV-006: fips.go no longer contains %q; the fail-closed power-on self-test may have regressed", needle)
		}
	}

	// Honest residuals must remain documented at the boundary: FIPS-*capable*
	// (not product-certified), the external CMVP certificate, and the
	// external-HSM/KMS caveat.
	residualPhrases := map[string]string{
		"FIPS-*capable*": "the honest FIPS-capable (not product-certified) framing",
		"CMVP":           "the external product CMVP certificate residual",
		"HSM":            "the external-HSM/KMS validated-by-device caveat",
	}
	for phrase, why := range residualPhrases {
		if !strings.Contains(body, phrase) {
			t.Errorf("PKIGOV-006: fips.go no longer documents %s (missing %q); the FIPS posture must stay honest about its residuals", why, phrase)
		}
	}
}
