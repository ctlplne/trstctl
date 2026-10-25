// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
)

// B1 (design-limit review lead): the relay appended " | appliance readback:
// <sentence>" to a deploy's detail after verification had made that detail the
// JSON EndpointVerifyReport, so the control plane's strict decode refused every
// f5, kemp, netscaler, a10, fortigate, paloalto or GCP Certificate Manager
// deploy that had both a verify address and a readback answer. The readback now
// travels inside the report: its verdict and its sentence, so the server can
// weigh it. A detail that is not a report still gets the sentence appended.
func TestApplianceReadbackTravelsInsideTheVerificationReport(t *testing.T) {
	report := EndpointVerifyReport{Results: []EndpointVerifyResult{{EndpointID: "edge-vip",
		Transcript: transport.ProbeTranscript{Address: "10.0.0.5:443", Vantage: transport.VantageLocal, Reached: true},
		Detail:     "the listener serves the deployed certificate"}}}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	sentence := readbackDetail(connector.ReadbackInstalledNotBound, connector.Installed{ObjectName: "trstctl-edge-2026"})
	got := withApplianceReadback(string(encoded), connector.ReadbackInstalledNotBound, sentence)
	var decoded EndpointVerifyReport
	dec := json.NewDecoder(bytes.NewReader([]byte(got)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&decoded); err != nil {
		t.Fatalf("detail with a readback is not a strictly decodable report: %v\n%s", err, got)
	}
	readback := decoded.Results[0].ApplianceReadback
	if readback == nil || readback.Verdict != string(connector.ReadbackInstalledNotBound) || readback.Detail != sentence ||
		decoded.Results[0].Detail != "the listener serves the deployed certificate" {
		t.Fatalf("readback in the report = %+v", decoded.Results[0])
	}
	if ReadbackConfirms(readback) {
		t.Fatal("an installed-but-not-bound readback confirmed the deploy")
	}
	for _, confirming := range []*ApplianceReadback{nil, {}, {Verdict: string(connector.ReadbackServing)}} {
		if !ReadbackConfirms(confirming) {
			t.Fatalf("readback %+v did not confirm", confirming)
		}
	}

	// No verification report (no verify address, or a sentence explaining why
	// verification could not run): the sentence is appended as before.
	if got := withApplianceReadback("", connector.ReadbackServing, "the appliance reports \"x\" bound to this target"); got != "appliance readback: the appliance reports \"x\" bound to this target" {
		t.Fatalf("empty detail = %q", got)
	}
	if got := withApplianceReadback("post-deploy verification could not run: timeout", "", "the appliance did not answer a readback after the deploy"); !strings.HasPrefix(got, "post-deploy verification could not run: timeout | appliance readback: ") {
		t.Fatalf("sentence detail = %q", got)
	}
	// A long object name is bounded, inside the report too.
	long := withApplianceReadback(string(encoded), connector.ReadbackDiverged, strings.Repeat("x", 4096))
	if err := json.Unmarshal([]byte(long), &decoded); err != nil || len(decoded.Results[0].ApplianceReadback.Detail) > applianceReadbackLimit {
		t.Fatalf("bounded readback = %d bytes (%v)", len(decoded.Results[0].ApplianceReadback.Detail), err)
	}
}
