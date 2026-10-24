// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/netsec"
)

// A102: each probed endpoint is classified from its signed transcript. The
// not_public case reads the relay's real refusal: the SSRF guard's dial error
// as the probe reports it.
func TestExposureProbeOutcome(t *testing.T) {
	_, err := tlsprobe.Probe(context.Background(), "127.0.0.1:1", tlsprobe.WithDialControl(netsec.SafeDialControl))
	if err == nil {
		t.Fatal("the dial control did not refuse a loopback address")
	}
	refused := transport.SanitizeProbeError(err)
	for _, tc := range []struct {
		name      string
		tr        transport.ProbeTranscript
		outcome   string
		reachable bool
	}{
		{"tls", transport.ProbeTranscript{Reached: true, ObservedFingerprint: "ab"}, ExposureProbeTLSCertificate, true},
		{"unparseable", transport.ProbeTranscript{Reached: true, Error: "x509: malformed certificate"}, ExposureProbeUnparseableLeaf, true},
		{"plaintext", transport.ProbeTranscript{Error: "tlsprobe: handshake a.example.com:80: tls: first record does not look like a TLS handshake"}, ExposureProbeListenerWithoutTLS, true},
		{"refused", transport.ProbeTranscript{Error: refused}, ExposureProbeNotPublic, false},
		{"dark", transport.ProbeTranscript{Error: "tlsprobe: dial a.example.com:443: i/o timeout"}, ExposureProbeUnreachable, false},
	} {
		outcome, reachable := exposureProbeOutcome(tc.tr)
		if outcome != tc.outcome || reachable != tc.reachable {
			t.Errorf("%s: (%q, %v); want (%q, %v) for %q", tc.name, outcome, reachable, tc.outcome, tc.reachable, tc.tr.Error)
		}
	}
}
