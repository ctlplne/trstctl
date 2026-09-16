// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

func TestVerificationAdmissionAcceptsEpochValidityWithoutAcceptingMissingWindows(t *testing.T) {
	const observedAt = int64(1800000000)
	fingerprint := strings.Repeat("a", 64)
	intent, err := json.Marshal(relay.EndpointVerifyIntent{Endpoints: []relay.EndpointExpectation{{EndpointID: "epoch-listener", Address: "127.0.0.1:443", Fingerprint: fingerprint}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		before, after int64
		mismatch      certinfo.Mismatch
		accept        bool
	}{
		{"starts-at-epoch", 0, observedAt + 60, certinfo.MismatchNone, true},
		{"starts-before-epoch", -86400, observedAt + 60, certinfo.MismatchNone, true},
		{"missing-window", 0, 0, certinfo.MismatchNone, false},
		{"inverted-window", observedAt + 60, observedAt - 60, certinfo.MismatchNone, false},
		{"not-yet-valid-clean", observedAt + 1, observedAt + 60, certinfo.MismatchNone, false},
		{"expired-clean", 0, observedAt - 1, certinfo.MismatchNone, false},
		{"expired-at-epoch-clean", -86400, 0, certinfo.MismatchNone, false},
		{"expired-at-epoch-reported", -86400, 0, certinfo.MismatchExpired, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := transport.ProbeTranscript{Address: "127.0.0.1:443", Vantage: transport.VantageRelay, Reached: true, ExpectedFingerprint: fingerprint, ObservedFingerprint: fingerprint, NotBeforeUnix: tc.before, NotAfterUnix: tc.after, Mismatch: tc.mismatch, ObservedAtUnix: observedAt}
			payload, err := json.Marshal(relay.EndpointVerifyReport{Results: []relay.EndpointVerifyResult{{EndpointID: "epoch-listener", Transcript: tr}}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = validateEndpointVerificationReport(intent, string(payload), transport.SweepDigest(append(tr.Canonical(), '\n')))
			if (err == nil) != tc.accept {
				t.Fatalf("report accepted=%t, want %t: %v", err == nil, tc.accept, err)
			}
		})
	}
}
