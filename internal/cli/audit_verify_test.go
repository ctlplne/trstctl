// SPDX-License-Identifier: BUSL-1.1

package cli_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/tsa"
)

func TestAuditVerifyIsAShippedOfflineCommandForEveryExportFormatAUD53(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 8, 13, 6, 0, 0, 0, time.UTC)
	recs := []auditchain.Record{
		{Sequence: 1, ID: "audit-53-1", Type: "identity.created", TenantID: "tenant-53", Time: at, Data: json.RawMessage(`{"name":"api"}`)},
		{Sequence: 2, ID: "audit-53-2", Type: "certificate.issued", TenantID: "tenant-53", Time: at.Add(time.Second)},
	}
	head := auditchain.Seal(recs)
	h := newAuditVerifyHarness(t, at.Add(time.Minute))
	anchor, err := auditanchor.AnchorHead(t.Context(), h.authority, head)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.GenerateRSASigningKey("audit-verify-cli-53")
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	rootPath := filepath.Join(dir, "tsa-root.pem")
	if err := os.WriteFile(rootPath, crypto.EncodeCertificatePEM(h.rootDER), 0o600); err != nil {
		t.Fatal(err)
	}
	jwks, err := signer.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	jwksPath := filepath.Join(dir, "audit.jwks.json")
	if err := os.WriteFile(jwksPath, jwks, 0o600); err != nil {
		t.Fatal(err)
	}

	artifacts := map[auditanchor.Format][]byte{}
	for _, format := range []auditanchor.Format{
		auditanchor.FormatCSV,
		auditanchor.FormatNDJSON,
		auditanchor.FormatSplunkHEC,
		auditanchor.FormatSentinel,
	} {
		var out bytes.Buffer
		if err := auditanchor.WriteRecords(&out, format, recs, "", head, anchor); err != nil {
			t.Fatal(err)
		}
		artifacts[format] = out.Bytes()
	}
	bundle := audit.Bundle{
		TenantID: "tenant-53", GeneratedAt: at.Add(time.Minute), Query: audit.Query{TenantID: "tenant-53"},
		Records: recs, Count: len(recs), ChainHead: head,
	}
	payload, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.SignArtifact(jose.ArtifactAuditExport, payload)
	if err != nil {
		t.Fatal(err)
	}
	artifacts[auditanchor.FormatJWS], err = json.Marshal(auditanchor.EvidenceEnvelope{
		SchemaVersion: auditanchor.EvidenceEnvelopeSchemaVersion,
		Format:        auditanchor.FormatJWS, Bundle: signed, ChainHead: head, Anchor: anchor,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, format := range auditanchor.Formats() {
		format := format
		t.Run(string(format), func(t *testing.T) {
			t.Parallel()
			artifactPath := filepath.Join(dir, "audit."+string(format))
			stdin := ""
			if format == auditanchor.FormatNDJSON {
				artifactPath = "-"
				stdin = string(artifacts[format])
			} else if err := os.WriteFile(artifactPath, artifacts[format], 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{
				"audit", "verify", "--artifact", artifactPath, "--format", "auto",
				"--tsa-root", rootPath, "--max-anchor-delay", "1h",
			}
			if format == auditanchor.FormatJWS {
				args = append(args, "--audit-jwks", jwksPath)
			}
			var stdout, stderr bytes.Buffer
			code := cli.Run(t.Context(), args, cli.Env{}, strings.NewReader(stdin), &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit=%d stderr=%q", code, stderr.String())
			}
			var result auditanchor.VerificationResult
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatalf("decode output %q: %v", stdout.String(), err)
			}
			if result.Format != format || result.RecordCount != len(recs) || result.ChainHead != head ||
				result.AnchorKind != auditanchor.KindRFC3161 {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestAuditVerifyHelpAndFailuresDoNotNeedOrContactAServerAUD53(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := cli.Run(t.Context(), []string{"audit", "verify", "--help"}, cli.Env{}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("help exit=%d stderr=%q", code, stderr.String())
	}
	for _, marker := range []string{"--artifact", "--format", "--audit-jwks", "--tsa-root", "PEM or DER", "--max-anchor-delay", "jws", "ndjson", "csv", "splunk-hec", "sentinel"} {
		if !strings.Contains(stdout.String(), marker) {
			t.Errorf("help missing %q:\n%s", marker, stdout.String())
		}
	}

	stdout.Reset()
	stderr.Reset()
	code = cli.Run(t.Context(), []string{
		"audit", "verify", "--artifact", "-", "--format", "jws", "--tsa-root", "missing-root.der",
	}, cli.Env{Server: "https://must-not-be-contacted.invalid"}, strings.NewReader(`{"format":"jws"}`), &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "audit verification failed") {
		t.Fatalf("invalid artifact exit=%d stderr=%q", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = cli.Run(t.Context(), []string{
		"audit", "verify", "--artifact", "-", "--format", "ndjson", "--tsa-root", "unread-root.der",
	}, cli.Env{}, strings.NewReader(strings.Repeat("x", auditanchor.MaxArtifactBytes+1)), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "input exceeds the 16777216-byte limit") {
		t.Fatalf("oversized artifact exit=%d stderr=%q", code, stderr.String())
	}
}

func TestAuditVerificationKeysCommandDownloadsOnlyPublicTrustAUD53(t *testing.T) {
	t.Parallel()
	var requestedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"keys":[{"kty":"RSA","kid":"audit-53","n":"AQAB","e":"AQAB"}]}`)
	}))
	t.Cleanup(server.Close)

	var stdout, stderr bytes.Buffer
	code := cli.Run(t.Context(), []string{"audit", "verification-keys"}, cli.Env{
		Server: server.URL, Token: "auditor-token", HTTPClient: server.Client(),
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if requestedPath != "/api/v1/audit/verification-keys" {
		t.Fatalf("requested path=%q", requestedPath)
	}
	if strings.Contains(stdout.String(), `"d"`) || !strings.Contains(stdout.String(), `"keys"`) {
		t.Fatalf("unsafe or malformed trust output: %s", stdout.String())
	}
}

func TestAuditExportCommandSelectsEveryOfflineVerifierFormatAUD53(t *testing.T) {
	t.Parallel()
	for _, format := range auditanchor.Formats() {
		format := format
		t.Run(string(format), func(t *testing.T) {
			t.Parallel()
			var gotPath, gotFormat string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotFormat = r.URL.Query().Get("format")
				_, _ = io.WriteString(w, `{}`)
			}))
			t.Cleanup(server.Close)

			var stdout, stderr bytes.Buffer
			code := cli.Run(t.Context(), []string{"audit", "export", "--format", string(format)}, cli.Env{
				Server: server.URL, HTTPClient: server.Client(),
			}, strings.NewReader(""), &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit=%d stderr=%q", code, stderr.String())
			}
			if gotPath != "/api/v1/audit/export" || gotFormat != string(format) {
				t.Fatalf("request=%s?format=%s", gotPath, gotFormat)
			}
		})
	}
}

type auditVerifyHarness struct {
	authority *tsa.Authority
	rootDER   []byte
}

func newAuditVerifyHarness(t *testing.T, at time.Time) auditVerifyHarness {
	t.Helper()
	root, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Destroy)
	rootDER, err := crypto.SelfSignedCACert(root, "AUD-53 TSA Root", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tsaKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tsaKey.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "AUD-53 TSA"}, tsaKey)
	if err != nil {
		t.Fatal(err)
	}
	tsaCert, err := crypto.SignTimestampingCertFromCSR(rootDER, root, csr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := tsa.New(tsa.Config{
		TenantID: "tenant-53", TSACertDER: tsaCert, TSASigner: tsaKey,
		Audit: &auditsink.Recorder{}, Clock: func() time.Time { return at },
	})
	if err != nil {
		t.Fatal(err)
	}
	return auditVerifyHarness{authority: authority, rootDER: rootDER}
}
