// SPDX-License-Identifier: BUSL-1.1

package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/tsa"
)

// Plain core exports still carry an authenticated JWS and verifiable record
// chain. Their verification must never claim an independent timestamp.
func TestAuditVerifyPlainSignedExportWithoutUnrelatedTSATrust(t *testing.T) {
	t.Parallel()
	f := newPlainAuditVerifyFixture(t)
	for _, format := range []string{"auto", "jws"} {
		for _, input := range []string{"file", "stdin"} {
			t.Run(format+"/"+input, func(t *testing.T) {
				artifact := f.envelope(t, f.bundle, f.anchor)
				path := "-"
				if input == "file" {
					path = filepath.Join(t.TempDir(), "audit.json")
					if err := os.WriteFile(path, artifact, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				code, stdout, stderr := runPlainAuditVerify(t, artifact,
					"--artifact", path, "--format", format, "--audit-jwks", f.keysPath)
				if code != 0 {
					t.Fatalf("plain signed export exit=%d stderr=%q", code, stderr)
				}
				var result struct {
					auditanchor.VerificationResult
					AuditSignatureVerified bool   `json:"audit_signature_verified"`
					AnchorVerified         bool   `json:"anchor_verified"`
					AnchorDetail           string `json:"anchor_detail"`
				}
				if err := json.Unmarshal(stdout, &result); err != nil {
					t.Fatal(err)
				}
				if result.TenantID != f.bundle.TenantID || result.RecordCount != len(f.bundle.Records) ||
					result.ChainHead != f.bundle.ChainHead || !result.AuditSignatureVerified ||
					result.AnchorVerified || result.AnchorKind != auditanchor.KindNone ||
					!result.AnchoredAt.IsZero() || strings.TrimSpace(result.AnchorDetail) == "" {
					t.Fatalf("plain verification must identify its signed but unanchored scope: %s", stdout)
				}
			})
		}
	}
	t.Run("archived-prefix", func(t *testing.T) {
		bundle := f.bundle
		bundle.Records = append([]auditchain.Record(nil), f.bundle.Records...)
		bundle.PrevHash = strings.Repeat("ab", 32)
		bundle.ChainHead = auditchain.SealFrom(bundle.PrevHash, bundle.Records)
		anchor := f.anchor
		anchor.ChainHead = bundle.ChainHead
		code, stdout, stderr := runPlainAuditVerify(t, f.envelope(t, bundle, anchor), "--artifact", "-", "--audit-jwks", f.keysPath)
		if code != 0 {
			t.Fatalf("signed continuation exit=%d stderr=%q", code, stderr)
		}
		var result auditanchor.VerificationResult
		if err := json.Unmarshal(stdout, &result); err != nil {
			t.Fatal(err)
		}
		if result.PrevHash != bundle.PrevHash || result.ChainHead != bundle.ChainHead || !result.AuditSignatureVerified || result.AnchorVerified {
			t.Fatalf("incorrect signed-continuation receipt: %s", stdout)
		}
	})
}

func TestAuditVerifyPlainExportRetainsIntegrityAndTimestampRefusals(t *testing.T) {
	t.Parallel()
	f := newPlainAuditVerifyFixture(t)
	valid := f.envelope(t, f.bundle, f.anchor)
	wrong, err := jose.GenerateRSASigningKey("plain-audit-verifier")
	if err != nil {
		t.Fatal(err)
	}
	wrongKeys, err := wrong.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	wrongPath := filepath.Join(t.TempDir(), "wrong.jwks.json")
	if err := os.WriteFile(wrongPath, wrongKeys, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		artifact []byte
		keys     string
		flags    []string
	}{
		{"missing audit trust", valid, "", nil},
		{"wrong audit trust", valid, wrongPath, nil},
		{"explicit empty TSA root", valid, f.keysPath, []string{"--tsa-root", ""}},
		{"explicit whitespace TSA root", valid, f.keysPath, []string{"--tsa-root", " \t"}},
		{"required anchor", valid, f.keysPath, []string{"--require-anchor"}},
		{"required backdate protection", valid, f.keysPath, []string{"--max-anchor-delay", "1h"}},
		{"duplicate envelope field", bytes.Replace(valid, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1), f.keysPath, nil},
		{"trailing document", append(append([]byte(nil), valid...), []byte(`{}`)...), f.keysPath, nil},
	}
	for _, mutate := range []struct {
		name string
		fn   func(*audit.Bundle, *auditanchor.Anchor)
	}{
		{"signed wrong count", func(b *audit.Bundle, _ *auditanchor.Anchor) { b.Count++ }},
		{"signed wrong archived prefix", func(b *audit.Bundle, _ *auditanchor.Anchor) { b.PrevHash = strings.Repeat("ab", 32) }},
		{"signed wrong query tenant", func(b *audit.Bundle, _ *auditanchor.Anchor) { b.Query.TenantID = "another-tenant" }},
		{"signed foreign record", func(b *audit.Bundle, _ *auditanchor.Anchor) { b.Records[0].TenantID = "another-tenant" }},
		{"signed broken record chain", func(b *audit.Bundle, _ *auditanchor.Anchor) { b.Records[0].Data = json.RawMessage(`{"changed":true}`) }},
		{"anchor names another head", func(_ *audit.Bundle, a *auditanchor.Anchor) { a.ChainHead = strings.Repeat("0", 64) }},
		{"unknown anchor kind", func(_ *audit.Bundle, a *auditanchor.Anchor) { a.Kind = "unrecognized" }},
		{"none with timestamp token", func(_ *audit.Bundle, a *auditanchor.Anchor) { a.Token = &tsa.Token{} }},
		{"none with asserted timestamp", func(_ *audit.Bundle, a *auditanchor.Anchor) { a.AnchoredAt = time.Now().UTC() }},
		{"timestamped without trust", func(_ *audit.Bundle, a *auditanchor.Anchor) { a.Kind = auditanchor.KindRFC3161 }},
	} {
		bundle := f.bundle
		bundle.Records = append([]auditchain.Record(nil), f.bundle.Records...)
		anchor := f.anchor
		mutate.fn(&bundle, &anchor)
		cases = append(cases, struct {
			name     string
			artifact []byte
			keys     string
			flags    []string
		}{mutate.name, f.envelope(t, bundle, anchor), f.keysPath, nil})
	}
	var modified auditanchor.EvidenceEnvelope
	if err := json.Unmarshal(valid, &modified); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(modified.Bundle, ".")
	if len(parts) != 3 {
		t.Fatal("fixture is not compact JWS")
	}
	parts[1] = "e30" // Change the signed payload without changing its signature.
	modified.Bundle = strings.Join(parts, ".")
	tampered, err := json.Marshal(modified)
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, struct {
		name     string
		artifact []byte
		keys     string
		flags    []string
	}{"tampered signature input", tampered, f.keysPath, nil})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"--artifact", "-", "--format", "auto"}
			if tc.keys != "" {
				args = append(args, "--audit-jwks", tc.keys)
			}
			args = append(args, tc.flags...)
			code, stdout, stderr := runPlainAuditVerify(t, tc.artifact, args...)
			if code == 0 || len(bytes.TrimSpace(stdout)) != 0 || strings.TrimSpace(stderr) == "" {
				t.Fatalf("invalid or insufficient evidence accepted: exit=%d stdout=%s stderr=%q", code, stdout, stderr)
			}
		})
	}
	// Existing library callers requested full timestamp verification. A CLI
	// improvement must not silently weaken their default policy.
	if _, err := auditanchor.VerifyArtifact(valid, auditanchor.VerificationOptions{
		Format: auditanchor.FormatJWS, AuditKeys: f.signer.JWKS(),
	}); err == nil {
		t.Fatal("strict library verification accepted unanchored evidence")
	}
}

func TestAuditVerifyTimestampedExportStillRequiresCorrectExternalTrust(t *testing.T) {
	t.Parallel()
	f := newPlainAuditVerifyFixture(t)
	h := newAuditVerifyHarness(t, f.bundle.Records[1].Time.Add(time.Minute))
	anchor, err := auditanchor.AnchorHead(t.Context(), h.authority, f.bundle.ChainHead)
	if err != nil {
		t.Fatal(err)
	}
	artifact := f.envelope(t, f.bundle, anchor)
	rootPath := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(rootPath, crypto.EncodeCertificatePEM(h.rootDER), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runPlainAuditVerify(t, artifact, "--artifact", "-", "--audit-jwks", f.keysPath, "--tsa-root", rootPath, "--require-anchor")
	if code != 0 {
		t.Fatalf("valid anchored export exit=%d stderr=%q", code, stderr)
	}
	var receipt auditanchor.VerificationResult
	if err := json.Unmarshal(stdout, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.AnchorKind != auditanchor.KindRFC3161 || receipt.AnchoredAt.IsZero() {
		t.Fatalf("missing verified timestamp: %s", stdout)
	}
	// Trust or timestamp failures must not become signature-only successes.
	wrong := newAuditVerifyHarness(t, f.bundle.GeneratedAt)
	wrongRootPath := filepath.Join(t.TempDir(), "wrong-root.pem")
	if err := os.WriteFile(wrongRootPath, crypto.EncodeCertificatePEM(wrong.rootDER), 0o600); err != nil {
		t.Fatal(err)
	}
	tamperedAnchor := anchor
	badToken := *anchor.Token
	badToken.Signature = append([]byte(nil), badToken.Signature...)
	if len(badToken.Signature) == 0 {
		t.Fatal("timestamp fixture must have a signature")
	}
	badToken.Signature[0] ^= 1
	tamperedAnchor.Token = &badToken
	for _, tc := range []struct {
		name     string
		artifact []byte
		root     string
	}{
		{"wrong timestamp root", artifact, wrongRootPath},
		{"damaged timestamp signature", f.envelope(t, f.bundle, tamperedAnchor), rootPath},
		{"missing timestamp with supplied trust", f.envelope(t, f.bundle, f.anchor), rootPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runPlainAuditVerify(t, tc.artifact, "--artifact", "-", "--audit-jwks", f.keysPath, "--tsa-root", tc.root)
			if code == 0 || len(bytes.TrimSpace(stdout)) != 0 || strings.TrimSpace(stderr) == "" {
				t.Fatalf("timestamp policy failed open: exit=%d stdout=%s stderr=%q", code, stdout, stderr)
			}
		})
	}
	code, stdout, stderr = runPlainAuditVerify(t, artifact, "--artifact", "-", "--audit-jwks", f.keysPath)
	if code == 0 || len(bytes.TrimSpace(stdout)) != 0 {
		t.Fatalf("timestamped export accepted without TSA trust: %d %s %q", code, stdout, stderr)
	}
}

func TestAuditVerifyPlainPermissionDoesNotAuthenticateUnsignedStreams(t *testing.T) {
	t.Parallel()
	f := newPlainAuditVerifyFixture(t)
	for _, format := range []auditanchor.Format{
		auditanchor.FormatCSV, auditanchor.FormatNDJSON,
		auditanchor.FormatSplunkHEC, auditanchor.FormatSentinel,
	} {
		t.Run(string(format), func(t *testing.T) {
			var artifact bytes.Buffer
			if err := auditanchor.WriteRecords(&artifact, format, f.bundle.Records, "", f.bundle.ChainHead, f.anchor); err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := runPlainAuditVerify(t, artifact.Bytes(), "--artifact", "-", "--format", string(format), "--audit-jwks", f.keysPath)
			if code == 0 || len(bytes.TrimSpace(stdout)) != 0 || strings.TrimSpace(stderr) == "" {
				t.Fatalf("unsigned stream accepted by plain JWS policy: exit=%d stdout=%s stderr=%q", code, stdout, stderr)
			}
		})
	}
}

type plainAuditVerifyFixture struct {
	signer   *jose.SigningKey
	keysPath string
	bundle   audit.Bundle
	anchor   auditanchor.Anchor
}

func newPlainAuditVerifyFixture(t *testing.T) plainAuditVerifyFixture {
	t.Helper()
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	records := []auditchain.Record{
		{Sequence: 1, ID: "plain-first", Type: "identity.created", TenantID: "plain-customer", Time: at, Data: json.RawMessage(`{"name":"owned-endpoint"}`)},
		{Sequence: 2, ID: "plain-second", Type: "certificate.revoked", TenantID: "plain-customer", Time: at.Add(time.Second)},
	}
	head := auditchain.Seal(records)
	signer, err := jose.GenerateRSASigningKey("plain-audit-verifier")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := signer.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jwks.json")
	if err := os.WriteFile(path, keys, 0o600); err != nil {
		t.Fatal(err)
	}
	return plainAuditVerifyFixture{signer: signer, keysPath: path,
		bundle: audit.Bundle{TenantID: "plain-customer", GeneratedAt: at.Add(time.Minute), Query: audit.Query{TenantID: "plain-customer"}, Records: records, Count: len(records), ChainHead: head},
		anchor: auditanchor.Anchor{Kind: auditanchor.KindNone, ChainHead: head, Detail: "anchoring requires an Enterprise licence"}}
}

func (f plainAuditVerifyFixture) envelope(t *testing.T, bundle audit.Bundle, anchor auditanchor.Anchor) []byte {
	t.Helper()
	payload, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := f.signer.SignArtifact(jose.ArtifactAuditExport, payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(auditanchor.EvidenceEnvelope{SchemaVersion: auditanchor.EvidenceEnvelopeSchemaVersion, Format: auditanchor.FormatJWS, Bundle: signed, ChainHead: bundle.ChainHead, Anchor: anchor})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func runPlainAuditVerify(t *testing.T, artifact []byte, flags ...string) (int, []byte, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	args := append([]string{"audit", "verify"}, flags...)
	code := cli.Run(t.Context(), args, cli.Env{Server: "https://must-not-be-contacted.invalid"}, bytes.NewReader(artifact), &stdout, &stderr)
	return code, stdout.Bytes(), stderr.String()
}
