// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/testutil/openssltest"
	"trstctl.com/trstctl/internal/tsa"
)

// TestServedTSAOpenSSLTimestampOverHTTP is the INTEROP-005 wire-in proof:
// server.Build mounts /tsa, OpenSSL creates the TimeStampReq, the served control
// plane POSTs back a TimeStampResp, and OpenSSL verifies it against the served
// issuing CA. This fails on a tree where internal/tsa is only a library.
func TestServedTSAOpenSSLTimestampOverHTTP(t *testing.T) {
	ossl := requireOpenSSLTSServer(t)
	dir := t.TempDir()
	h := newServedHarness(t, config.Protocols{
		TSA:         config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		TSACertFile: filepath.Join(dir, "tsa.crt"),
	})
	if !hasServedProtocol(h.srv.ServedProtocols(), "tsa") {
		t.Fatalf("served protocols = %v, want tsa mounted", h.srv.ServedProtocols())
	}

	dataPath := filepath.Join(dir, "served-artifact.bin")
	reqPath := filepath.Join(dir, "served-request.tsq")
	respPath := filepath.Join(dir, "served-response.tsr")
	caPath := filepath.Join(dir, "served-ca.pem")
	verifyLogPath := filepath.Join(dir, "served-openssl-ts-verify.log")
	if err := os.WriteFile(dataPath, []byte("served timestamp data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, h.caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command(ossl, "ts", "-query", "-sha256", "-data", dataPath, "-out", reqPath).CombinedOutput() // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	if err != nil {
		t.Fatalf("openssl ts -query failed: %v\n%s", err, out)
	}
	reqDER, err := os.ReadFile(reqPath) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	httpResp, err := http.Post(h.ts.URL+"/tsa", tsa.ContentTypeQuery, bytes.NewReader(reqDER))
	if err != nil {
		t.Fatalf("POST /tsa: %v", err)
	}
	defer func() { _ = httpResp.Body.Close() }()
	respDER, err := io.ReadAll(httpResp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /tsa status = %d, want 200; body %x", httpResp.StatusCode, respDER)
	}
	if err := os.WriteFile(respPath, respDER, 0o600); err != nil {
		t.Fatal(err)
	}

	out, err = exec.Command(ossl, "ts", "-verify", "-queryfile", reqPath, "-in", respPath, "-CAfile", caPath).CombinedOutput() // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	if err != nil {
		_ = os.WriteFile(verifyLogPath, out, 0o600)
		t.Fatalf("openssl ts -verify rejected served /tsa response: %v\n%s", err, out)
	}
	if err := os.WriteFile(verifyLogPath, out, 0o600); err != nil {
		t.Fatal(err)
	}

	// The console preview reads the exact assembled runtime after OpenSSL proves
	// the wire path. It must not issue a second timestamp or require timestamp
	// request/certificate material from the browser.
	issuedBefore := countServedTSAEvents(t, h)
	readToken := seedAPITokenWithScopes(t, h.store, servedTestTenant, []string{"certs:read"})
	qualifyReq, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/protocols/tsa/qualification", nil)
	qualifyReq.Header.Set("Authorization", "Bearer "+readToken)
	qualifyResp, err := h.ts.Client().Do(qualifyReq)
	if err != nil {
		t.Fatalf("TSA qualification: %v", err)
	}
	qualifyBody, _ := readAllClose(qualifyResp)
	if qualifyResp.StatusCode != http.StatusOK {
		t.Fatalf("TSA qualification status %d: %s", qualifyResp.StatusCode, qualifyBody)
	}
	var qualification api.TSAQualification
	if err := json.Unmarshal(qualifyBody, &qualification); err != nil {
		t.Fatalf("decode TSA qualification: %v body=%s", err, qualifyBody)
	}
	if !qualification.Ready || !qualification.EffectFree || qualification.Endpoint != "/tsa" {
		t.Fatalf("TSA qualification=%+v, want ready effect-free exact live posture", qualification)
	}
	if issuedAfter := countServedTSAEvents(t, h); issuedAfter != issuedBefore {
		t.Fatalf("effect-free TSA qualification changed issuance count from %d to %d", issuedBefore, issuedAfter)
	}
	archiveServedTSATranscripts(t, dataPath, reqPath, respPath, caPath, verifyLogPath)
}

func TestServedTSAQualificationMatchesEvalActivationGate(t *testing.T) {
	dir := t.TempDir()
	h := newServedHarness(t, config.Protocols{
		TSA:         config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
		TSACertFile: filepath.Join(dir, "tsa.crt"),
	})
	h.srv.protocols.activation = newProtocolActivationGate(false)

	readToken := seedAPITokenWithScopes(t, h.store, servedTestTenant, []string{"certs:read"})
	qualify := func() api.TSAQualification {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/protocols/tsa/qualification", nil)
		req.Header.Set("Authorization", "Bearer "+readToken)
		resp, err := h.ts.Client().Do(req)
		if err != nil {
			t.Fatalf("TSA qualification: %v", err)
		}
		body, _ := readAllClose(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("TSA qualification status %d: %s", resp.StatusCode, body)
		}
		var got api.TSAQualification
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("decode TSA qualification: %v body=%s", err, body)
		}
		return got
	}

	blocked := qualify()
	if blocked.Ready {
		t.Fatalf("closed eval gate reported ready: %+v", blocked)
	}
	if len(blocked.Blockers) != 1 || !bytes.Contains([]byte(blocked.Blockers[0]), []byte("Protocol profile active")) {
		t.Fatalf("closed eval gate blockers=%v, want exact activation blocker", blocked.Blockers)
	}

	h.srv.protocols.activation.Activate()
	ready := qualify()
	if !ready.Ready {
		t.Fatalf("open eval gate reported blocked: %+v", ready)
	}
}

func countServedTSAEvents(t *testing.T, h *servedHarness) int {
	t.Helper()
	count := 0
	if err := h.log.Replay(t.Context(), 0, func(event events.Event) error {
		if event.TenantID == servedTestTenant && event.Type == "tsa.timestamp.issued" {
			count++
		}
		return nil
	}); err != nil {
		t.Fatalf("replay TSA events: %v", err)
	}
	return count
}

func requireOpenSSLTSServer(t *testing.T) string {
	t.Helper()
	// openssltest.RequireTSA honors TRSTCTL_REQUIRE_OPENSSL_TSA=1, so CI can make
	// this served stock-client proof mandatory instead of skipped when OpenSSL lacks ts.
	return openssltest.RequireTSA(t)
}

func hasServedProtocol(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}
	return false
}

func archiveServedTSATranscripts(t *testing.T, paths ...string) {
	t.Helper()
	dir := os.Getenv("TRSTCTL_INTEROP_TRANSCRIPT_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 G703 -- fixture tree in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276)
		t.Fatalf("create transcript dir: %v", err)
	}
	for _, src := range paths {
		in, err := os.Open(src) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
		if err != nil {
			t.Fatalf("open transcript %s: %v", src, err)
		}
		dst := filepath.Join(dir, filepath.Base(src))
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644) // #nosec G302 G304 G703 -- test reads its own fixture/tempdir path (CWE-22, CWE-276)
		if err != nil {
			_ = in.Close()
			t.Fatalf("create transcript %s: %v", dst, err)
		}
		if _, err := io.Copy(out, in); err != nil {
			_ = in.Close()
			_ = out.Close()
			t.Fatalf("copy transcript %s: %v", dst, err)
		}
		if err := in.Close(); err != nil {
			_ = out.Close()
			t.Fatalf("close transcript source %s: %v", src, err)
		}
		if err := out.Close(); err != nil {
			t.Fatalf("close transcript %s: %v", dst, err)
		}
	}
}
