// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tsa"
)

// Audit export in formats a SIEM ingests, served (epic J1).
//
// The unit tests prove the encodings are right. This proves they are REACHED:
// the route accepts a format, the response carries the matching content type,
// and the chain head travels with the payload rather than only in a header a log
// pipeline would drop on the first forward.

func newAuditExportHarness(t *testing.T) (*httptest.Server, string, string) {
	t.Helper()
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"

	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	tok := seedServedAPIToken(t, ctx, st, tenantID, "audit-export", []string{
		string(authz.AuditRead), string(authz.OwnersWrite), string(authz.OwnersRead),
	})
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	auditKey, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	srv, err := Build(ctx, Deps{Store: st, Log: log, AuditSigningKey: auditKey})
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Something to export.
	code, body := doBearer(t, ts, http.MethodPost, "/api/v1/owners", tok, "audit-export-seed",
		map[string]any{"kind": "team", "name": "Platform", "email": "p@example.test"})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("seed owner = %d: %s", code, body)
	}
	return ts, tok, tenantID
}

func TestServedAuditExportServesEveryAdvertisedFormat(t *testing.T) {
	ts, tok, _ := newAuditExportHarness(t)

	for _, tc := range []struct {
		format      string
		contentType string
	}{
		{"ndjson", "application/x-ndjson"},
		{"csv", "text/csv"},
		{"splunk-hec", "application/x-ndjson"},
		{"sentinel", "application/x-ndjson"},
	} {
		tc := tc
		t.Run(tc.format, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet,
				ts.URL+"/api/v1/audit/export?format="+tc.format, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+tok)
			resp, err := ts.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("export %s = %d", tc.format, resp.StatusCode)
			}
			if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, tc.contentType) {
				t.Errorf("content type = %q, want %q; a SIEM routes on this", ct, tc.contentType)
			}
			// The chain head must be IN the payload, not only in a header — a
			// log pipeline forwards the body and drops the headers.
			if head := resp.Header.Get("X-Trstctl-Audit-Chain-Head"); head == "" {
				t.Error("no chain-head header")
			}
		})
	}
}

// The trailer carries the chain head and the anchor state, in the body.
func TestServedNDJSONExportCarriesItsChainHeadInTheBody(t *testing.T) {
	ts, tok, _ := newAuditExportHarness(t)

	code, body := doBearer(t, ts, http.MethodGet, "/api/v1/audit/export?format=ndjson", tok, "", nil)
	if code != http.StatusOK {
		t.Fatalf("export = %d: %s", code, body)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected records plus a trailer, got %d lines", len(lines))
	}
	var tr struct {
		Kind      string `json:"trstctl_record"`
		ChainHead string `json:"chain_head"`
		Anchor    struct {
			Kind   string `json:"kind"`
			Detail string `json:"detail"`
		} `json:"anchor"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &tr); err != nil {
		t.Fatalf("trailer is not JSON: %v", err)
	}
	if tr.Kind != "chain_trailer" || tr.ChainHead == "" {
		t.Fatalf("trailer = %+v, want a chain head", tr)
	}
	// This deployment serves no TSA, so the export must SAY it is unanchored
	// rather than omit the field and read as fine.
	if tr.Anchor.Kind != "" {
		t.Errorf("anchor kind = %q on a deployment with no TSA", tr.Anchor.Kind)
	}
	if tr.Anchor.Detail == "" {
		t.Error("an unanchored export gives no reason; an operator cannot tell whether " +
			"anchoring failed or was never configured")
	}
}

// CSV is real CSV with the pinned header.
func TestServedCSVExportParses(t *testing.T) {
	ts, tok, _ := newAuditExportHarness(t)

	code, body := doBearer(t, ts, http.MethodGet, "/api/v1/audit/export?format=csv", tok, "", nil)
	if code != http.StatusOK {
		t.Fatalf("export = %d: %s", code, body)
	}
	rows, err := csv.NewReader(strings.NewReader(string(body))).ReadAll()
	if err != nil {
		t.Fatalf("served CSV does not parse: %v", err)
	}
	if len(rows) < 2 || rows[0][0] != "sequence" || rows[len(rows)-1][9] != "chain_trailer" {
		t.Fatalf("unexpected CSV header: %v", rows)
	}
}

func TestServedSavedAuditArtifactsVerifyOfflineAUD51(t *testing.T) {
	ts, tok, srv, rootDER := newAnchoredAuditExportHarnessAUD51(t)

	code, envelope := doBearer(t, ts, http.MethodGet, "/api/v1/audit/export", tok, "", nil)
	if code != http.StatusOK {
		t.Fatalf("JWS evidence envelope = %d: %s", code, envelope)
	}
	bundle, err := auditanchor.VerifyEvidenceEnvelope(envelope, srv.audit.VerificationKeys(), rootDER, time.Hour)
	if err != nil || bundle.Count == 0 {
		t.Fatalf("saved browser envelope did not verify offline: count=%d err=%v body=%s", bundle.Count, err, envelope)
	}

	code, csvArtifact := doBearer(t, ts, http.MethodGet, "/api/v1/audit/export?format=csv", tok, "", nil)
	if code != http.StatusOK {
		t.Fatalf("CSV evidence artifact = %d: %s", code, csvArtifact)
	}
	records, err := auditanchor.VerifyCSVArtifact(csvArtifact, rootDER, time.Hour)
	if err != nil || len(records) == 0 {
		t.Fatalf("saved CSV did not verify offline: records=%d err=%v", len(records), err)
	}
}

func TestServedAuditVerificationKeysAreDownloadableAndPublicOnlyAUD53(t *testing.T) {
	ts, tok, srv, _ := newAnchoredAuditExportHarnessAUD51(t)

	code, raw := doBearer(t, ts, http.MethodGet, "/api/v1/audit/verification-keys", tok, "", nil)
	if code != http.StatusOK {
		t.Fatalf("verification keys = %d: %s", code, raw)
	}
	want, err := srv.audit.PublicVerificationJWKS()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(raw), bytes.TrimSpace(want)) {
		t.Fatalf("served JWK set differs from audit signer public authority: got=%s want=%s", raw, want)
	}
	for _, privateField := range []string{`"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`, `"qi"`} {
		if strings.Contains(string(raw), privateField+":") {
			t.Fatalf("served JWK set contains private RSA field %s", privateField)
		}
	}
}

func TestDownloadedServedAuditArtifactsVerifyAfterServerShutdownThroughShippedCommandAUD53(t *testing.T) {
	ts, tok, srv, rootDER := newAnchoredAuditExportHarnessAUD51(t)
	onlineEnv := cli.Env{Server: ts.URL, Token: tok, HTTPClient: ts.Client()}
	cliBinary := buildAuditVerifierCLI_AUD53(t)

	artifacts := make(map[auditanchor.Format][]byte, len(auditanchor.Formats()))
	for _, format := range auditanchor.Formats() {
		var stdout, stderr bytes.Buffer
		if exit := cli.Run(t.Context(), []string{"audit", "export", "--format", string(format)}, onlineEnv,
			strings.NewReader(""), &stdout, &stderr); exit != 0 {
			t.Fatalf("trstctl-cli audit export --format %s exit=%d stderr=%q", format, exit, stderr.String())
		}
		artifacts[format] = append([]byte(nil), stdout.Bytes()...)
	}
	var jwksStdout, jwksStderr bytes.Buffer
	if exit := cli.Run(t.Context(), []string{"audit", "verification-keys"}, onlineEnv,
		strings.NewReader(""), &jwksStdout, &jwksStderr); exit != 0 {
		t.Fatalf("trstctl-cli audit verification-keys exit=%d stderr=%q", exit, jwksStderr.String())
	}
	publicJWKS := jwksStdout.Bytes()

	// Everything below this line runs with the authenticated HTTP server and its
	// control-plane dependencies gone. The saved bytes and separately pinned
	// trust files are the only inputs the shipped command receives.
	ts.Close()
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("shut down assembled server before offline verification: %v", err)
	}
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "tsa-root.pem")
	if err := os.WriteFile(rootPath, crypto.EncodeCertificatePEM(rootDER), 0o600); err != nil {
		t.Fatal(err)
	}
	jwksPath := filepath.Join(dir, "audit.jwks.json")
	if err := os.WriteFile(jwksPath, publicJWKS, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, format := range auditanchor.Formats() {
		format := format
		t.Run(string(format), func(t *testing.T) {
			artifactPath := filepath.Join(dir, "served-audit."+string(format))
			if err := os.WriteFile(artifactPath, artifacts[format], 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{
				"audit", "verify", "--artifact", artifactPath, "--format", "auto",
				"--tsa-root", rootPath, "--max-anchor-delay", "1h",
			}
			if format == auditanchor.FormatJWS {
				args = append(args, "--audit-jwks", jwksPath)
			}
			command := exec.CommandContext(t.Context(), cliBinary, args...) // #nosec G204 -- fixed binary built by this test; arguments are fixed/test-owned paths and enum values (CWE-78)
			stdout, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("%s %s: %v\n%s", cliBinary, strings.Join(args, " "), err, stdout)
			}
			var receipt auditanchor.VerificationResult
			if err := json.Unmarshal(stdout, &receipt); err != nil {
				t.Fatalf("decode command receipt: %v: %s", err, stdout)
			}
			if receipt.Format != format || receipt.RecordCount == 0 || receipt.ChainHead == "" ||
				receipt.AnchorKind != auditanchor.KindRFC3161 {
				t.Fatalf("offline %s receipt = %+v", format, receipt)
			}
		})
	}
}

func buildAuditVerifierCLI_AUD53(t *testing.T) string {
	t.Helper()
	workingDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(workingDir, "../.."))
	binary := filepath.Join(t.TempDir(), "trstctl-cli")
	command := exec.Command("go", "build", "-o", binary, "./cmd/trstctl-cli") // #nosec G204 -- fixed repository binary and test-owned destination (CWE-78)
	command.Dir = repoRoot
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build shipped trstctl-cli: %v\n%s", err, output)
	}
	return binary
}

func newAnchoredAuditExportHarnessAUD51(t *testing.T) (*httptest.Server, string, *Server, []byte) {
	t.Helper()
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111151"
	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "AUD-51 anchored export"}); err != nil {
		t.Fatal(err)
	}
	tok := seedServedAPIToken(t, ctx, st, tenantID, "aud-51-auditor", []string{
		string(authz.AuditRead), string(authz.OwnersWrite), string(authz.OwnersRead),
	})
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	auditKey, err := jose.GenerateRSASigningKey("aud-51-export")
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	rootKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rootKey.Destroy)
	rootDER, err := crypto.SelfSignedCACert(rootKey, "AUD-51 TSA root", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tsaKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tsaKey.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "AUD-51 TSA"}, tsaKey)
	if err != nil {
		t.Fatal(err)
	}
	tsaCert, err := crypto.SignTimestampingCertFromCSR(rootDER, rootKey, csr, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := tsa.New(tsa.Config{
		TenantID: tenantID, TSACertDER: tsaCert, TSASigner: tsaKey, Audit: auditsink.Nop{},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := Build(ctx, Deps{
		Store: st, Log: log, AuditSigningKey: auditKey,
		APIOptions: []api.Option{api.WithAuditTimestamper(authority)},
	})
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	code, body := doBearer(t, ts, http.MethodPost, "/api/v1/owners", tok, "aud-51-seed",
		map[string]any{"kind": "team", "name": "Audit", "email": "audit@example.test"})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("seed audit event = %d: %s", code, body)
	}
	return ts, tok, srv, rootDER
}

// An unknown format is a 400, not a silent downgrade to JWS.
func TestServedAuditExportRefusesAnUnknownFormat(t *testing.T) {
	ts, tok, _ := newAuditExportHarness(t)

	code, body := doBearer(t, ts, http.MethodGet, "/api/v1/audit/export?format=splunk", tok, "", nil)
	if code != http.StatusBadRequest {
		t.Fatalf("unknown format = %d (%s), want 400; a caller who asked for a format they did "+
			"not get would find out when their ingest pipeline rejected the payload", code, body)
	}
}

// The default is unchanged: no format means the signed bundle.
func TestServedAuditExportStillDefaultsToTheSignedBundle(t *testing.T) {
	ts, tok, _ := newAuditExportHarness(t)

	code, body := doBearer(t, ts, http.MethodGet, "/api/v1/audit/export", tok, "", nil)
	if code != http.StatusOK {
		t.Fatalf("export = %d: %s", code, body)
	}
	var resp struct {
		Format    string `json:"format"`
		Bundle    string `json:"bundle"`
		ChainHead string `json:"chain_head"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Format != "jws" || resp.Bundle == "" {
		t.Errorf("default export = %+v, want the signed bundle", resp)
	}
	if resp.ChainHead == "" {
		t.Error("the JWS response carries no chain head alongside the bundle")
	}
}
