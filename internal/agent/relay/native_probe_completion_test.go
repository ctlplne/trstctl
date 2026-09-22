// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
)

func TestHostNativeReadbackRequiresExactDeployedCertificate(t *testing.T) {
	executable, address, served := nativeHostProbeFixture(t)
	intent := DeployIntent{Connector: "nginx", TargetID: "test-target", VerifyAddress: address, VerifyServerName: "api.example.test"}
	material := Material{"credential.cert_pem": served}
	outcome, detail, evidence := postDeployVerificationWithNative(t.Context(), intent, material, executable)
	if outcome != transport.OutcomeVerified || evidence == "" {
		t.Fatalf("actual matching native listener was not verified: %s %s", outcome, detail)
	}
	var report EndpointVerifyReport
	if err := json.Unmarshal([]byte(detail), &report); err != nil || len(report.Results) != 1 {
		t.Fatal("native result did not use the existing signed transcript envelope")
	}
	transcript := report.Results[0].Transcript
	if err := transcript.Validate(); err != nil || transcript.Digest() != evidence || !transcript.Reached {
		t.Fatal("native result has no valid bound transcript")
	}
	expected, err := certinfo.ExpectationFromChain(served)
	if err != nil {
		t.Fatal(err)
	}
	if transcript.ExpectedFingerprint != expected.SHA256Fingerprint || transcript.ObservedFingerprint != expected.SHA256Fingerprint || transcript.Mismatch != certinfo.MismatchNone {
		t.Fatal("native receipt describes a different certificate")
	}
	other, err := tlsprobe.NewServingTestServer("api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Close)
	outcome, detail, evidence = postDeployVerificationWithNative(t.Context(), intent, Material{"credential.cert_pem": other.LeafPEM}, executable)
	if outcome != transport.OutcomeVerifyFailed || evidence == "" {
		t.Fatalf("uninstalled certificate became verified: %s", outcome)
	}
	if err := json.Unmarshal([]byte(detail), &report); err != nil || len(report.Results) != 1 {
		t.Fatal("mismatch receipt missing")
	}
	if report.Results[0].Transcript.ObservedFingerprint != expected.SHA256Fingerprint || report.Results[0].Transcript.Mismatch != certinfo.MismatchFingerprint {
		t.Fatal("mismatch lost the actually served leaf")
	}
	intent.VerifyServerName = "wrong.example.test"
	outcome, _, _ = postDeployVerificationWithNative(t.Context(), intent, material, executable)
	if outcome != transport.OutcomeVerifyFailed {
		t.Fatal("native backend bypassed hostname checking")
	}
}
