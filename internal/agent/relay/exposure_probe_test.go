// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
)

// A102: an exposure probe's endpoints come from discovery metadata, not
// operator configuration, so the relay connects only to public addresses. A
// listener on loopback that an ordinary sweep reaches is refused, at the
// address the socket would connect to, and reported unreached.
func TestExposureProbeConnectsOnlyToPublicAddresses(t *testing.T) {
	server, err := tlsprobe.NewServingTestServer("exposed.example.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	expect, err := certinfo.ExpectationFromChain(server.LeafPEM)
	if err != nil {
		t.Fatal(err)
	}
	sweep := func(intent EndpointVerifyIntent) EndpointVerifyResult {
		t.Helper()
		payload, err := json.Marshal(intent)
		if err != nil {
			t.Fatal(err)
		}
		ch := &trustTestChannel{jobs: []Job{{JobID: 41, Attempt: 1, Kind: KindEndpointVerify, Payload: payload}}}
		if _, err := RunOnce(t.Context(), ch, http.DefaultClient, 1, 30); err != nil {
			t.Fatal(err)
		}
		var report EndpointVerifyReport
		if len(ch.reports) != 1 || ch.reports[0].outcome != OutcomeExecuted || json.Unmarshal([]byte(ch.reports[0].detail), &report) != nil || len(report.Results) != 1 {
			t.Fatalf("sweep report = %+v", ch.reports)
		}
		if ch.reports[0].evidence != sweepDigest(report) {
			t.Fatal("evidence digest does not commit to the sweep")
		}
		return report.Results[0]
	}

	ordinary := sweep(EndpointVerifyIntent{Endpoints: []EndpointExpectation{
		{EndpointID: "configured", Address: server.Addr, ServerName: "exposed.example.test", Fingerprint: expect.SHA256Fingerprint},
	}})
	if !ordinary.Transcript.Reached || ordinary.Transcript.Mismatch != certinfo.MismatchNone {
		t.Fatalf("an operator-configured sweep did not reach the loopback listener: %+v", ordinary.Transcript)
	}

	probed := sweep(EndpointVerifyIntent{
		Endpoints: []EndpointExpectation{{EndpointID: "exposure|finding/x|" + server.Addr, Address: server.Addr, ServerName: "exposed.example.test"}},
		Exposure:  &EndpointVerifyExposure{RequestID: "req-1", RunID: "run-1"},
	})
	tr := probed.Transcript
	if tr.Reached || tr.ObservedFingerprint != "" || !strings.Contains(tr.Error, "tlsprobe: dial ") || !strings.Contains(tr.Error, "SSRF guard") {
		t.Fatalf("an exposure probe connected to a loopback address: %+v", tr)
	}
	if err := tr.Validate(); err != nil {
		t.Fatalf("refused probe transcript is invalid: %v", err)
	}
}
