// SPDX-License-Identifier: MPL-2.0

package revcacheposture_test

import (
	"bytes"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/revcacheposture"
)

func TestRevocationCachePostureCanonicalizesEveryIssuerProtocolAndIdentityAUD39(t *testing.T) {
	t.Parallel()
	entries := []revcacheposture.Entry{
		{
			CacheID: "issuer-b", Segment: "plant-7", Protocol: revcacheposture.ProtocolOCSP,
			IssuerFingerprint: "sha256:" + strings.Repeat("b", 64), LocalPath: "/ocsp/issuer-b",
			Status: revcacheposture.StatusFresh, CachedResponses: 2, Fresh: true,
			SignatureVerified: true, ThisUpdateUnix: 1_786_570_000, NextUpdateUnix: 1_786_573_600,
			LastValidatedAtUnix: 1_786_570_010, ServedRequests: 7, RefusedRequests: 1,
		},
		{
			CacheID: "issuer-a", Segment: "plant-7", Protocol: revcacheposture.ProtocolCRL,
			IssuerFingerprint: "sha256:" + strings.Repeat("a", 64), LocalPath: "/crl/issuer-a",
			Status: revcacheposture.StatusStale, CachedResponses: 1, Fresh: false,
			SignatureVerified: true, ThisUpdateUnix: 1_786_560_000, NextUpdateUnix: 1_786_563_600,
			LastValidatedAtUnix: 1_786_560_010, ServedRequests: 3, RefusedRequests: 2,
			DetailCode: "next_update_passed",
		},
	}

	normalized, err := revcacheposture.Normalize(entries)
	if err != nil {
		t.Fatalf("normalize cache posture: %v", err)
	}
	if normalized[0].CacheID != "issuer-a" || normalized[1].CacheID != "issuer-b" {
		t.Fatalf("cache posture order = %+v", normalized)
	}
	statement := revcacheposture.Statement{
		TenantID: "11111111-1111-1111-1111-111111111111", AgentCommonName: "plant-7-relay-a",
		Entries: normalized, IssuedAtUnix: 1_786_570_020,
	}
	canonical, err := statement.Canonical()
	if err != nil {
		t.Fatalf("canonical cache posture: %v", err)
	}
	mutated := statement
	mutated.TenantID = "22222222-2222-2222-2222-222222222222"
	other, err := mutated.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(canonical, other) {
		t.Fatal("tenant mutation did not change the signed cache statement")
	}
	for _, forbidden := range []string{"upstream", "credential", "private_key", "response_der", "issuer_der"} {
		if bytes.Contains(bytes.ToLower(canonical), []byte(forbidden)) {
			t.Fatalf("metadata-only statement contains forbidden field %q: %s", forbidden, canonical)
		}
	}
}

func TestRevocationCachePostureRejectsAmbiguousOrUnsafeRowsAUD39(t *testing.T) {
	t.Parallel()
	valid := revcacheposture.Entry{
		CacheID: "issuer-a", Segment: "plant-7", Protocol: revcacheposture.ProtocolCRL,
		IssuerFingerprint: "sha256:" + strings.Repeat("a", 64), LocalPath: "/crl/issuer-a",
		Status: revcacheposture.StatusEmpty,
	}
	tests := []struct {
		name    string
		entries []revcacheposture.Entry
	}{
		{name: "duplicate", entries: []revcacheposture.Entry{valid, valid}},
		{name: "URL instead of local path", entries: []revcacheposture.Entry{func() revcacheposture.Entry {
			row := valid
			row.LocalPath = "https://secret.example/crl?token=x"
			return row
		}()}},
		{name: "bad fingerprint", entries: []revcacheposture.Entry{func() revcacheposture.Entry { row := valid; row.IssuerFingerprint = "sha256:abc"; return row }()}},
		{name: "unknown protocol", entries: []revcacheposture.Entry{func() revcacheposture.Entry { row := valid; row.Protocol = "ldap"; return row }()}},
		{name: "fresh without proof", entries: []revcacheposture.Entry{func() revcacheposture.Entry {
			row := valid
			row.Status = revcacheposture.StatusFresh
			row.Fresh = true
			return row
		}()}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := revcacheposture.Normalize(tc.entries); err == nil {
				t.Fatal("unsafe cache posture was accepted")
			}
		})
	}
}
