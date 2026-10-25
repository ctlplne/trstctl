// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/servedstatus"
)

// B1: a deploy report carries the appliance's own readback beside the TLS
// handshake. The control plane admits it (the strict decode knows the field),
// requires "verified" only when the handshake passes AND the readback confirms
// (the relay downgrades a contradicted handshake, and admission used to refuse
// that as "outcome contradicts its verification observation"), and the
// verification receipt names the readback that failed it.
func TestDeploymentVerificationWeighsTheApplianceReadback(t *testing.T) {
	fingerprint := strings.Repeat("a", 64)
	expected := certinfo.Expectation{SHA256Fingerprint: fingerprint, DNSNames: []string{"edge.example.test"}}
	intent := relay.DeployIntent{Connector: "f5", Target: "edge-vip", TargetID: "edge-vip-target", Fingerprint: fingerprint,
		VerifyAddress: "10.0.0.5:443", VerifyServerName: "edge.example.test"}
	now := time.Now().Unix()
	tr := transport.ProbeTranscript{Address: intent.VerifyAddress, ServerName: intent.VerifyServerName, Vantage: transport.VantageLocal,
		Reached: true, ExpectedFingerprint: fingerprint, ObservedFingerprint: fingerprint,
		ExpectedSANDigest: transport.SANSetDigest(expected.DNSNames), ObservedSANDigest: transport.SANSetDigest(expected.DNSNames), CheckedSANs: true,
		NotBeforeUnix: now - 3600, NotAfterUnix: now + 86400, ObservedAtUnix: now, HandshakeMillis: 3}
	report := func(readback *relay.ApplianceReadback) string {
		t.Helper()
		raw, err := json.Marshal(relay.EndpointVerifyReport{Results: []relay.EndpointVerifyResult{{EndpointID: intent.TargetID,
			Transcript: tr, Detail: "the listener serves the deployed certificate", ApplianceReadback: readback}}})
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	notBound := &relay.ApplianceReadback{Verdict: string(connector.ReadbackInstalledNotBound),
		Detail: "the certificate is installed on the appliance as \"trstctl-edge\" but is not bound to the serving object"}
	serving := &relay.ApplianceReadback{Verdict: string(connector.ReadbackServing), Detail: "the appliance reports \"trstctl-edge\" bound to this target"}

	// The relay's downgrade: a passing handshake contradicted by the readback.
	result, err := validateDeploymentVerificationReport(intent, expected, report(notBound), tr.Digest(), transport.JobOutcomeVerifyFailed)
	if err != nil {
		t.Fatalf("contradicted handshake reported verify_failed was refused: %v", err)
	}
	receipt := deploymentVerificationReceipt(intent, result.Transcript, result.Detail, result.ApplianceReadback)
	if receipt.Status != servedstatus.ConnectorVerifyFailed || receipt.Reason != "appliance_readback_installed_not_bound" || !strings.Contains(receipt.Detail, "not bound") {
		t.Fatalf("receipt for a contradicted handshake = %s/%s %q", receipt.Status, receipt.Reason, receipt.Detail)
	}
	if _, err := validateDeploymentVerificationReport(intent, expected, report(notBound), tr.Digest(), transport.JobOutcomeVerified); err == nil {
		t.Fatal("verified was admitted over a readback that contradicts it")
	}
	// A confirming readback: verified, and the receipt keeps the sentence.
	result, err = validateDeploymentVerificationReport(intent, expected, report(serving), tr.Digest(), transport.JobOutcomeVerified)
	if err != nil {
		t.Fatalf("verified with a confirming readback was refused: %v", err)
	}
	receipt = deploymentVerificationReceipt(intent, result.Transcript, result.Detail, result.ApplianceReadback)
	if receipt.Status != servedstatus.ConnectorVerified || !strings.Contains(receipt.Detail, "bound to this target") {
		t.Fatalf("receipt for a confirmed deploy = %s/%s %q", receipt.Status, receipt.Reason, receipt.Detail)
	}
	// An unknown verdict or an oversized sentence is not admitted.
	for _, bad := range []*relay.ApplianceReadback{{Verdict: "maybe", Detail: "x"}, {Verdict: "serving", Detail: strings.Repeat("x", 4096)}} {
		if _, err := validateDeploymentVerificationReport(intent, expected, report(bad), tr.Digest(), transport.JobOutcomeVerified); err == nil {
			t.Fatalf("readback %q/%d bytes admitted", bad.Verdict, len(bad.Detail))
		}
	}
	// A sweep result never carries a readback: the same sweep is admitted
	// without one and refused with one.
	sweepTr := transport.ProbeTranscript{Address: "127.0.0.1:443", Vantage: transport.VantageRelay, Reached: true,
		ExpectedFingerprint: fingerprint, ObservedFingerprint: fingerprint, NotBeforeUnix: now - 3600, NotAfterUnix: now + 86400, ObservedAtUnix: now}
	sweepIntent, err := json.Marshal(relay.EndpointVerifyIntent{Endpoints: []relay.EndpointExpectation{{EndpointID: "sweep-1", Address: "127.0.0.1:443", Fingerprint: fingerprint}}})
	if err != nil {
		t.Fatal(err)
	}
	sweepDigest := transport.SweepDigest(append(sweepTr.Canonical(), '\n'))
	for _, withReadback := range []bool{false, true} {
		result := relay.EndpointVerifyResult{EndpointID: "sweep-1", Transcript: sweepTr}
		if withReadback {
			result.ApplianceReadback = serving
		}
		sweep, err := json.Marshal(relay.EndpointVerifyReport{Results: []relay.EndpointVerifyResult{result}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := validateEndpointVerificationReport(sweepIntent, string(sweep), sweepDigest); (err == nil) == withReadback {
			t.Fatalf("sweep with readback=%t: admitted=%t (%v)", withReadback, err == nil, err)
		}
	}
}
