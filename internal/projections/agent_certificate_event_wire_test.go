// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/aimodel"
)

func TestAgentCertEnrolledV2PublicIdentifiersKeepExactBindingWithoutSecretLikeRuns(t *testing.T) {
	original := AgentCertEnrolled{
		ID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", Agent: "edge-relay",
		Serial: strings.Repeat("ab", 16), Fingerprint: strings.Repeat("cd", 32),
	}
	wire := AgentCertEnrolledPublicWire(original)
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if aimodel.ResidualSecret(string(encoded)) {
		t.Fatal("public enrollment identifiers resemble credential material in the event payload")
	}
	if err := canonicalAgentCertEnrolledV2(&wire); err != nil {
		t.Fatal(err)
	}
	if wire.Serial != original.Serial || wire.Fingerprint != original.Fingerprint {
		t.Fatalf("public identifiers changed on projection: serial=%q fingerprint=%q", wire.Serial, wire.Fingerprint)
	}
	for _, malformed := range []string{
		strings.Repeat("cd", 32),
		strings.Repeat("cd", 16) + ":" + strings.Repeat("cd", 16),
		"zz:invalid",
	} {
		bad := AgentCertEnrolled{Serial: original.Serial, Fingerprint: malformed}
		if err := canonicalAgentCertEnrolledV2(&bad); err == nil {
			t.Fatalf("accepted malformed v2 fingerprint %q", malformed)
		}
	}
}
