// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/netsec"
)

// A190: the connections a relay opens to run jobs follow its egress policy. An
// endpoint check against an address the allowlist does not name is refused at
// the dial and reported unreached with the reason; once the address is listed
// the same check verifies; cloud instance metadata is refused with no
// allowlist at all.
func TestRelayJobConnectionsFollowTheEgressPolicy(t *testing.T) {
	server, err := tlsprobe.NewServingTestServer("appliance.example.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	expect, err := certinfo.ExpectationFromChain(server.LeafPEM)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { SetEgressPolicy(nil) })
	check := func(address string) (EndpointVerifyResult, string) {
		t.Helper()
		payload, err := json.Marshal(EndpointVerifyIntent{Endpoints: []EndpointExpectation{{
			EndpointID: "appliance", Address: address, ServerName: "appliance.example.test", Fingerprint: expect.SHA256Fingerprint,
		}}})
		if err != nil {
			t.Fatal(err)
		}
		ch := &trustTestChannel{jobs: []Job{{JobID: 190, Attempt: 1, Kind: KindEndpointVerify, Payload: payload}}}
		if _, err := RunOnce(t.Context(), ch, http.DefaultClient, 1, 30); err != nil {
			t.Fatal(err)
		}
		var report EndpointVerifyReport
		if len(ch.reports) != 1 || json.Unmarshal([]byte(ch.reports[0].detail), &report) != nil || len(report.Results) != 1 {
			t.Fatalf("endpoint check report = %+v", ch.reports)
		}
		raw, err := json.Marshal(report.Results[0])
		if err != nil {
			t.Fatal(err)
		}
		return report.Results[0], string(raw)
	}

	elsewhere, err := netsec.ParseRelayEgress([]string{"10.20.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	SetEgressPolicy(elsewhere)
	if res, raw := check(server.Addr); res.Transcript.Reached || !strings.Contains(raw, "egress allowlist") {
		t.Fatalf("an unlisted address was reached or refused without the reason: %s", raw)
	}
	listed, err := netsec.ParseRelayEgress([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	SetEgressPolicy(listed)
	if res, raw := check(server.Addr); !res.Transcript.Reached || res.Transcript.Mismatch != certinfo.MismatchNone {
		t.Fatalf("a listed address did not verify: %s", raw)
	}
	SetEgressPolicy(nil)
	if res, raw := check("169.254.169.254:443"); res.Transcript.Reached || !strings.Contains(raw, "cloud metadata") {
		t.Fatalf("instance metadata was dialed: %s", raw)
	}
}
