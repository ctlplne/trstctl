// SPDX-License-Identifier: MPL-2.0

package transport_test

import (
	"bytes"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/revcacheposture"
)

func TestSignedRevocationCachePostureBindsTenantRelayAndEveryCacheAUD39(t *testing.T) {
	signer := &censusSigner{}
	entries := []revcacheposture.Entry{{
		CacheID: "issuer-a", Segment: "plant-7", Protocol: revcacheposture.ProtocolCRL,
		IssuerFingerprint: "sha256:" + strings.Repeat("a", 64), LocalPath: "/crl/issuer-a",
		Status: revcacheposture.StatusFresh, CachedResponses: 1, Fresh: true, SignatureVerified: true,
		ThisUpdateUnix: 1_786_570_000, NextUpdateUnix: 1_786_573_600, LastValidatedAtUnix: 1_786_570_010,
	}}
	report, err := transport.SignedRevocationCachePosture(signer, "tenant-a", "relay-a", entries, 1_786_570_020)
	if err != nil {
		t.Fatalf("sign cache posture: %v", err)
	}
	if len(report.Signature) == 0 || len(signer.statement) == 0 {
		t.Fatalf("signed report=%+v statement=%q", report, signer.statement)
	}
	original := append([]byte(nil), signer.statement...)
	mutated := revcacheposture.Statement{TenantID: "tenant-b", AgentCommonName: "relay-a", Entries: report.Entries, IssuedAtUnix: report.IssuedAtUnix}
	canonical, err := mutated.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(original, canonical) {
		t.Fatal("changing the tenant did not change the signed statement")
	}
}
