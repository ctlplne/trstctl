// SPDX-License-Identifier: BUSL-1.1

package cli_test

import (
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/crypto/jose"
)

func TestAuditVerifyRetentionJWSRequiresPinnedTrustAndChecksArchive(t *testing.T) {
	t.Parallel()
	f := newPlainAuditVerifyFixture(t)
	artifact := signedRetentionBundle(t, f, f.bundle)
	code, raw, stderr := runPlainAuditVerify(t, artifact,
		"--artifact", "-", "--format", "retention-jws", "--audit-jwks", f.keysPath,
		"--expected-tenant", f.bundle.TenantID)
	if code != 0 {
		t.Fatalf("retention verifier = %d, stderr %q", code, stderr)
	}
	var receipt struct {
		ArtifactType           string `json:"artifact_type"`
		TenantID               string `json:"tenant_id"`
		Count                  int    `json:"count"`
		AuditSignatureVerified bool   `json:"audit_signature_verified"`
		ChainVerified          bool   `json:"chain_verified"`
		AnchorVerified         bool   `json:"anchor_verified"`
	}
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.ArtifactType != "audit.retention" || receipt.TenantID != f.bundle.TenantID ||
		receipt.Count != len(f.bundle.Records) || !receipt.AuditSignatureVerified ||
		!receipt.ChainVerified || receipt.AnchorVerified {
		t.Fatalf("misleading retention receipt: %+v", receipt)
	}
	for _, tc := range []struct {
		name     string
		artifact []byte
		flags    []string
	}{
		{name: "missing pinned key", artifact: artifact},
		{name: "wrong tenant", artifact: artifact, flags: []string{"--audit-jwks", f.keysPath, "--expected-tenant", "other-tenant"}},
		{name: "wrong previous head", artifact: artifact, flags: []string{"--audit-jwks", f.keysPath, "--previous-head", strings.Repeat("0", 64)}},
		{name: "timestamp policy", artifact: artifact, flags: []string{"--audit-jwks", f.keysPath, "--require-anchor"}},
		{name: "wrong signer domain", artifact: signedExportBundle(t, f, f.bundle), flags: []string{"--audit-jwks", f.keysPath}},
		{name: "damaged bytes", artifact: append(append([]byte(nil), artifact...), 'x'), flags: []string{"--audit-jwks", f.keysPath}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flags := append([]string{"--artifact", "-", "--format", "retention-jws"}, tc.flags...)
			if code, _, stderr := runPlainAuditVerify(t, tc.artifact, flags...); code == 0 {
				t.Fatalf("unsafe retention artifact accepted: %s", stderr)
			}
		})
	}
	for _, tc := range []struct {
		name string
		edit func(*audit.Bundle)
	}{
		{name: "signed wrong count", edit: func(b *audit.Bundle) { b.Count++ }},
		{name: "signed wrong query tenant", edit: func(b *audit.Bundle) { b.Query.TenantID = "foreign-tenant" }},
		{name: "signed foreign record", edit: func(b *audit.Bundle) {
			b.Records[0].TenantID = "foreign-tenant"
			b.ChainHead = auditchain.Seal(b.Records)
		}},
		{name: "signed skipped sequence", edit: func(b *audit.Bundle) { b.Records[1].Sequence++; b.ChainHead = auditchain.Seal(b.Records) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundle := f.bundle
			bundle.Records = append([]audit.Record(nil), f.bundle.Records...)
			tc.edit(&bundle)
			code, _, _ := runPlainAuditVerify(t, signedRetentionBundle(t, f, bundle),
				"--artifact", "-", "--format", "retention-jws", "--audit-jwks", f.keysPath)
			if code == 0 {
				t.Fatal("inconsistent signed archive accepted")
			}
		})
	}
}

func signedRetentionBundle(t *testing.T, f plainAuditVerifyFixture, bundle audit.Bundle) []byte {
	t.Helper()
	payload, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := f.signer.SignArtifact(jose.ArtifactAuditRetention, payload)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(signed)
}

func signedExportBundle(t *testing.T, f plainAuditVerifyFixture, bundle audit.Bundle) []byte {
	t.Helper()
	payload, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := f.signer.SignArtifact(jose.ArtifactAuditExport, payload)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(signed)
}
