// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/pqc/compatlab"
)

// B7-L1: a pilot's verdict names the expected leaf's algorithm and, where the
// handshake shows it, why the client refused it.
func TestPQCPilotRefusalNamesTheLeafAlgorithmAndCauseB7L1(t *testing.T) {
	const fp = "aa"
	for _, tc := range []struct {
		name      string
		tr        transport.ProbeTranscript
		algorithm string
		outcome   compatlab.Outcome
		want      []string
	}{
		{"the endpoint ends the handshake", transport.ProbeTranscript{Error: "tlsprobe: handshake 10.0.0.5:443: remote error: tls: handshake failure"}, "ML-DSA-65",
			compatlab.OutcomeRejected, []string{"the client does not offer ML-DSA-65 among its signature algorithms", "the ML-DSA-65 leaf", "handshake failure"}},
		{"the client cannot verify the signature", transport.ProbeTranscript{Error: "tlsprobe: handshake 10.0.0.5:443: tls: peer certificate: x509: unsupported signature algorithm"}, "ML-DSA-87",
			compatlab.OutcomeRejected, []string{"the client cannot verify ML-DSA-87 signatures", "the ML-DSA-87 leaf"}},
		{"the client cannot verify the leaf", transport.ProbeTranscript{Error: "tlsprobe: handshake 10.0.0.5:443: remote error: tls: bad certificate"}, "ML-DSA-44",
			compatlab.OutcomeRejected, []string{"the client could not verify the ML-DSA-44 leaf"}},
		{"another refusal", transport.ProbeTranscript{Error: "tlsprobe: handshake 10.0.0.5:443: EOF"}, "ML-DSA-65",
			compatlab.OutcomeRejected, []string{"the client refused the handshake with the ML-DSA-65 leaf: tlsprobe: handshake 10.0.0.5:443: EOF"}},
		{"an unknown leaf", transport.ProbeTranscript{Error: "tlsprobe: handshake 10.0.0.5:443: remote error: tls: handshake failure"}, "",
			compatlab.OutcomeRejected, []string{"the client does not offer the leaf's algorithm", "the post-quantum leaf"}},
		{"negotiated", transport.ProbeTranscript{Reached: true, ObservedFingerprint: "AA"}, "ML-DSA-65",
			compatlab.OutcomeNegotiated, []string{"the client negotiated the ML-DSA-65 leaf"}},
		{"another leaf served", transport.ProbeTranscript{Reached: true, ObservedFingerprint: "bb"}, "ML-DSA-65",
			compatlab.OutcomeRejected, []string{"the endpoint served a different leaf than the pilot deployed"}},
		{"unreachable", transport.ProbeTranscript{Error: "tlsprobe: dial 10.0.0.5:443: connection refused"}, "ML-DSA-65",
			compatlab.OutcomeUnreachable, []string{"the endpoint could not be reached"}},
	} {
		outcome, detail := orchestrator.ClassifyPQCPilotTranscript(tc.tr, fp, tc.algorithm)
		if outcome != tc.outcome {
			t.Fatalf("%s: outcome %s, want %s (%s)", tc.name, outcome, tc.outcome, detail)
		}
		for _, want := range tc.want {
			if !strings.Contains(detail, want) {
				t.Fatalf("%s: %q does not say %q", tc.name, detail, want)
			}
		}
	}
}
