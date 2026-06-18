package est_test

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestESTDifferentialVsOpenSSL is a REAL, non-skipped external-reference
// differential for the EST server (INTEROP-007): it drives the server's /cacerts
// and /simpleenroll endpoints and feeds the wire output to the OpenSSL `pkcs7`
// command — an independent RFC 7030 / PKCS#7 implementation, not our own
// crypto.CertsFromPKCS7 parser — asserting OpenSSL reads the same certificates.
//
// This replaces the previous stub, which only LookPath-ed an env var and then
// t.Log-ed without exercising any reference client (so it passed without proving
// interop). OpenSSL is present in CI and most dev environments; the test SKIPs
// honestly only when openssl is genuinely unavailable, never passing vacuously.
func TestESTDifferentialVsOpenSSL(t *testing.T) {
	ossl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not on PATH; the EST PKCS#7 differential runs on the CI backstop")
	}
	srv, ca := newServer(t, nil, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// (1) /cacerts: fetch the certs-only PKCS#7, hand it to `openssl pkcs7
	// -print_certs`, and confirm OpenSSL parses it and emits the CA certificate.
	caP7DER := fetchPKCS7(t, ts.URL+"/.well-known/est/cacerts", http.MethodGet, nil)
	caPEM := opensslPrintCerts(t, ossl, caP7DER)
	if !bytes.Contains(caPEM, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("openssl did not parse a certificate from /cacerts PKCS#7:\n%s", caPEM)
	}
	// The CA cert OpenSSL extracted must equal the server's CA (round-trip through
	// the external parser is lossless).
	wantPEM := pemCert(t, ca.certDER)
	if !bytes.Contains(normalizePEM(caPEM), normalizePEM(wantPEM)) {
		t.Errorf("openssl-extracted /cacerts cert does not match the server CA\nGOT:\n%s\nWANT:\n%s", caPEM, wantPEM)
	}

	// (2) /simpleenroll: enroll a device CSR and confirm OpenSSL parses the issued
	// leaf out of the returned certs-only PKCS#7.
	enrollBody := []byte(base64.StdEncoding.EncodeToString(deviceCSR(t)))
	leafP7DER := fetchPKCS7(t, ts.URL+"/.well-known/est/simpleenroll", http.MethodPost, enrollBody)
	leafPEM := opensslPrintCerts(t, ossl, leafP7DER)
	if !bytes.Contains(leafPEM, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("openssl did not parse the enrolled leaf from /simpleenroll PKCS#7:\n%s", leafPEM)
	}
	// OpenSSL must agree the leaf was issued by the CA: verify the chain.
	opensslVerifyChain(t, ossl, leafPEM, wantPEM)
}

// TestESTDifferentialVsLibest drives the libest reference client (RFC 7030) when
// EST_LIBEST points at an estclient binary. Unlike the previous stub, when the
// binary IS present it runs a real /cacerts fetch against a live server and
// asserts estclient succeeds — it can no longer pass without exercising the
// client. For local `make test`, libest can still skip when the binary is absent.
// CI sets TRSTCTL_REQUIRE_LIBEST=1 in the dedicated INTEROP-102 job, so absence of
// the pinned estclient is a failure there rather than a vacuous skip.
func TestESTDifferentialVsLibest(t *testing.T) {
	bin := os.Getenv("EST_LIBEST")
	if bin == "" {
		if os.Getenv("TRSTCTL_REQUIRE_LIBEST") == "1" {
			t.Fatal("TRSTCTL_REQUIRE_LIBEST=1 but EST_LIBEST is not set; CI must provide the pinned libest estclient")
		}
		t.Skip("EST_LIBEST not set; libest is an opt-in extra reference (the OpenSSL differential above is the real, non-skipped cross-check that runs in make test/CI)")
	}
	if _, err := exec.LookPath(bin); err != nil {
		t.Fatalf("EST_LIBEST=%q not executable: %v", bin, err)
	}
	ossl, err := exec.LookPath("openssl")
	if err != nil {
		t.Fatal("openssl not on PATH; required to validate the libest PKCS#7 output")
	}
	srv, ca := newServer(t, nil, nil)
	ts := httptest.NewTLSServer(srv.Handler())
	defer ts.Close()

	// Write the HTTPS server certificate so estclient can establish TLS trust, then drive
	// a real /cacerts fetch. estclient must exit 0 and write a PKCS#7 response.
	dir := t.TempDir()
	tlsTrustFile := filepath.Join(dir, "tls-ca.pem")
	if err := os.WriteFile(tlsTrustFile, pemCert(t, ts.TLS.Certificates[0].Certificate[0]), 0o600); err != nil {
		t.Fatal(err)
	}
	host, port := splitHostPort(t, ts.URL)
	outDir := filepath.Join(dir, "out")
	if err := os.Mkdir(outDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-g", "-s", host, "-p", port, "-o", outDir) // -g: get cacerts
	cmd.Env = append(os.Environ(), "EST_OPENSSL_CACERT="+tlsTrustFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("libest estclient -g (get cacerts) failed against the EST server: %v\n%s", err, out)
	}
	gotB64, err := os.ReadFile(filepath.Join(outDir, "cacert-0-0.pkcs7"))
	if err != nil {
		t.Fatalf("libest estclient did not write cacert-0-0.pkcs7: %v\n%s", err, out)
	}
	got, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(gotB64)))
	if err != nil {
		t.Fatalf("libest estclient wrote non-base64 PKCS#7: %v\n%s", err, gotB64)
	}
	gotPEM := opensslPrintCerts(t, ossl, got)
	if !bytes.Contains(gotPEM, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("libest estclient wrote a PKCS#7 response OpenSSL could not print:\n%s", got)
	}
	if !bytes.Contains(normalizePEM(gotPEM), normalizePEM(pemCert(t, ca.certDER))) {
		t.Fatalf("libest estclient fetched /cacerts, but it did not contain the EST CA\nGOT:\n%s", gotPEM)
	}
}

// --- helpers ----------------------------------------------------------------

func fetchPKCS7(t *testing.T, url, method string, body []byte) []byte {
	t.Helper()
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequest(method, url, bytes.NewReader(body))
		if req != nil {
			req.Header.Set("Content-Type", "application/pkcs10")
		}
	} else {
		req, err = http.NewRequest(method, url, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s %s -> %d", method, url, resp.StatusCode)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(buf.Bytes())))
	if err != nil {
		t.Fatalf("response body not base64 PKCS#7: %v", err)
	}
	return der
}

// opensslPrintCerts feeds a DER certs-only PKCS#7 to `openssl pkcs7 -print_certs`
// and returns the PEM certificates OpenSSL extracts.
func opensslPrintCerts(t *testing.T, ossl string, p7DER []byte) []byte {
	t.Helper()
	dir := t.TempDir()
	in := filepath.Join(dir, "in.p7b")
	if err := os.WriteFile(in, p7DER, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(ossl, "pkcs7", "-inform", "DER", "-in", in, "-print_certs").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl pkcs7 -print_certs rejected our EST PKCS#7 (not RFC 7030 certs-only): %v\n%s", err, out)
	}
	return out
}

// opensslVerifyChain confirms OpenSSL accepts leafPEM as issued by caPEM.
func opensslVerifyChain(t *testing.T, ossl string, leafPEM, caPEM []byte) {
	t.Helper()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	leafFile := filepath.Join(dir, "leaf.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// Keep only the first leaf certificate block for the verify input.
	if err := os.WriteFile(leafFile, firstPEMBlock(leafPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	// -partial_chain lets a directly-issued leaf verify against the CA as a trust
	// anchor even though the CA is not marked as a self-signed root chain here.
	out, err := exec.Command(ossl, "verify", "-CAfile", caFile, "-partial_chain", leafFile).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl verify rejected the EST-enrolled leaf against the CA: %v\n%s", err, out)
	}
}

func pemCert(t *testing.T, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func normalizePEM(b []byte) []byte {
	return bytes.ReplaceAll(bytes.TrimSpace(b), []byte("\r\n"), []byte("\n"))
}

func firstPEMBlock(b []byte) []byte {
	const end = "-----END CERTIFICATE-----"
	i := bytes.Index(b, []byte(end))
	if i < 0 {
		return b
	}
	return b[:i+len(end)+1]
}

func splitHostPort(t *testing.T, rawURL string) (host, port string) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse test server URL %q: %v", rawURL, err)
	}
	host, port, err = net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("cannot split host:port from %q: %v", rawURL, err)
	}
	return host, port
}
