// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// B9-R1: a rollback whose restore ran but whose re-verification failed used to
// leave a receipt that said only that; the agent's transcript was discarded and
// the cause was unrecoverable. The receipt now says what the listener served.
func TestRollbackVerificationDetailNamesWhatTheListenerServedB9R1(t *testing.T) {
	report := func(tr transport.ProbeTranscript, detail string) string {
		body, err := json.Marshal(relay.EndpointVerifyReport{Results: []relay.EndpointVerifyResult{{EndpointID: "t1", Transcript: tr, Detail: detail}}})
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	mismatch := rollbackVerificationDetail(report(transport.ProbeTranscript{
		Address: "192.168.68.52:10443", ServerName: "b5b9.example.test", Vantage: transport.VantageLocal, Reached: true,
		Mismatch: certinfo.MismatchFingerprint, ExpectedFingerprint: "9f32b159c58a917b551c0498052fd5465ec7d84dfb0f668b5ef75aa3a6969375",
		ObservedFingerprint: "0eb10abfdcf274a376b515e11f10731cc57bbb4bbe2707e5fa3e2fc448f26e87",
	}, "the listener still serves the successor"))
	for _, want := range []string{"192.168.68.52:10443", "SNI b5b9.example.test", "served 0eb10abfdcf2…", "9f32b159c58a… was expected", "fingerprint mismatch", "still serves the successor"} {
		if !strings.Contains(mismatch, want) {
			t.Errorf("mismatch detail %q lacks %q", mismatch, want)
		}
	}
	unreachable := rollbackVerificationDetail(report(transport.ProbeTranscript{Address: "10.0.0.9:443", Reached: false, Error: "dial tcp: connection refused"}, ""))
	if !strings.Contains(unreachable, "could not be reached: dial tcp: connection refused") {
		t.Errorf("unreachable detail = %q", unreachable)
	}
	clean := rollbackVerificationDetail(report(transport.ProbeTranscript{Address: "10.0.0.9:443", Reached: true, ObservedFingerprint: strings.Repeat("ab", 32)}, ""))
	if !strings.Contains(clean, "the expected predecessor") {
		t.Errorf("clean detail = %q", clean)
	}
	if got := rollbackVerificationDetail("not a report"); got != "" {
		t.Errorf("undecodable detail = %q, want empty", got)
	}
	if got := rollbackVerificationDetail(""); got != "" {
		t.Errorf("empty detail = %q, want empty", got)
	}
}
