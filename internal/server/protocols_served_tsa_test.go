package server

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/config"
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

	out, err := exec.Command(ossl, "ts", "-query", "-sha256", "-data", dataPath, "-out", reqPath).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl ts -query failed: %v\n%s", err, out)
	}
	reqDER, err := os.ReadFile(reqPath)
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

	out, err = exec.Command(ossl, "ts", "-verify", "-queryfile", reqPath, "-in", respPath, "-CAfile", caPath).CombinedOutput()
	if err != nil {
		_ = os.WriteFile(verifyLogPath, out, 0o600)
		t.Fatalf("openssl ts -verify rejected served /tsa response: %v\n%s", err, out)
	}
	if err := os.WriteFile(verifyLogPath, out, 0o600); err != nil {
		t.Fatal(err)
	}
	archiveServedTSATranscripts(t, dataPath, reqPath, respPath, caPath, verifyLogPath)
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
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create transcript dir: %v", err)
	}
	for _, src := range paths {
		in, err := os.Open(src)
		if err != nil {
			t.Fatalf("open transcript %s: %v", src, err)
		}
		dst := filepath.Join(dir, filepath.Base(src))
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
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
