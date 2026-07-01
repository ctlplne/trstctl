package tsa_test

import (
	"bytes"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/testutil/openssltest"
	"trstctl.com/trstctl/internal/tsa"
)

// TestTimeStampHTTPPostOpenSSLTSVerify is the INTEROP-005 served-stock-client
// acceptance: OpenSSL creates a real RFC 3161 TimeStampReq, trstctl serves it over
// HTTP as application/timestamp-query, and OpenSSL verifies the returned
// TimeStampResp. Pre-fix, only the inner library token existed and no HTTP
// TimeStampResp path existed, so this flow could not pass.
func TestTimeStampHTTPPostOpenSSLTSVerify(t *testing.T) {
	ossl := requireOpenSSLTS(t)
	a, rootDER, tsaCertDER := newRSATSAWithRoot(t)
	ts := httptest.NewServer(a.Handler())
	t.Cleanup(ts.Close)

	dir := t.TempDir()
	dataPath := filepath.Join(dir, "artifact.bin")
	reqPath := filepath.Join(dir, "request.tsq")
	respPath := filepath.Join(dir, "response.tsr")
	rootPath := filepath.Join(dir, "root.pem")
	tsaPath := filepath.Join(dir, "tsa.pem")
	verifyLogPath := filepath.Join(dir, "openssl-ts-verify.log")
	if err := os.WriteFile(dataPath, []byte("artifact bytes that need a trusted signing time"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeCertPEMForTest(rootPath, rootDER); err != nil {
		t.Fatal(err)
	}
	if err := writeCertPEMForTest(tsaPath, tsaCertDER); err != nil {
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
	httpResp, err := http.Post(ts.URL, tsa.ContentTypeQuery, bytes.NewReader(reqDER))
	if err != nil {
		t.Fatalf("HTTP POST TimeStampReq: %v", err)
	}
	defer func() { _ = httpResp.Body.Close() }()
	respDER, err := io.ReadAll(httpResp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("timestamp HTTP status = %d, want 200; body %x", httpResp.StatusCode, respDER)
	}
	if got := httpResp.Header.Get("Content-Type"); got != tsa.ContentTypeReply {
		t.Fatalf("timestamp content type = %q, want %q", got, tsa.ContentTypeReply)
	}
	if err := os.WriteFile(respPath, respDER, 0o600); err != nil {
		t.Fatal(err)
	}

	out, err = exec.Command(ossl, "ts", "-verify", "-queryfile", reqPath, "-in", respPath, "-CAfile", rootPath, "-untrusted", tsaPath).CombinedOutput()
	if err != nil {
		_ = os.WriteFile(verifyLogPath, out, 0o600)
		t.Fatalf("openssl ts -verify rejected served timestamp response: %v\n%s", err, out)
	}
	if err := os.WriteFile(verifyLogPath, out, 0o600); err != nil {
		t.Fatal(err)
	}
	archiveTSAConformanceTranscripts(t, dataPath, reqPath, respPath, rootPath, tsaPath, verifyLogPath)
}

func requireOpenSSLTS(t *testing.T) string {
	t.Helper()
	// openssltest.RequireTSA honors TRSTCTL_REQUIRE_OPENSSL_TSA=1, so CI can make
	// this stock-client proof mandatory instead of skipped when OpenSSL lacks ts.
	return openssltest.RequireTSA(t)
}

func writeCertPEMForTest(path string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
}

func archiveTSAConformanceTranscripts(t *testing.T, paths ...string) {
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
