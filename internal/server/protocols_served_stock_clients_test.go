package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// TestServedACMECertbotManualDNSIssueRenewRevoke is the INTEROP-001 served-path
// stock-client proof: certbot drives the assembled control-plane handler (server.Build)
// through DNS-01 issue, renew, and revoke. CI sets TRSTCTL_REQUIRE_CERTBOT=1, so the
// test cannot silently skip in the required conformance job.
func TestServedACMECertbotManualDNSIssueRenewRevoke(t *testing.T) {
	certbot, err := exec.LookPath("certbot")
	if err != nil {
		if os.Getenv("TRSTCTL_REQUIRE_CERTBOT") == "1" {
			t.Fatalf("TRSTCTL_REQUIRE_CERTBOT is set but certbot is not on PATH: %v", err)
		}
		t.Skip("certbot not on PATH; set TRSTCTL_REQUIRE_CERTBOT=1 in CI to make the stock ACME client mandatory")
	}

	dir := t.TempDir()
	certName := "trstctl-served-acme-certbot"
	domain := "certbot.served.test"
	recordsPath := filepath.Join(dir, "certbot-dns-records.tsv")
	hookLogPath := filepath.Join(dir, "certbot-hooks.log")
	hooksDir := filepath.Join(dir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	authHook := filepath.Join(hooksDir, "auth.sh")
	cleanupHook := filepath.Join(hooksDir, "cleanup.sh")
	servedWriteExecutable(t, authHook, servedCertbotAuthHookScript())
	servedWriteExecutable(t, cleanupHook, servedCertbotCleanupHookScript())

	validators := acmesrv.Validators{
		DNS01: acmesrv.DNS01Validator{Resolver: servedCertbotDNSResolver{recordsPath: recordsPath}},
	}
	h := newServedHarness(t,
		config.Protocols{ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		func(d *Deps) { d.ACMEValidators = &validators },
	)
	if !protoContains(h.srv.ServedProtocols(), "acme") {
		t.Fatal("ACME is not reported as served")
	}

	// certbot insists on HTTPS for non-local ACME directories. This TLS server wraps
	// the same assembled handler as h.ts, so the protocol path is still server.Build.
	ts := httptest.NewTLSServer(h.srv.Handler())
	t.Cleanup(ts.Close)
	caFile := filepath.Join(dir, "served-acme-https-ca.pem")
	servedWriteTLSCertPEM(t, caFile, ts)

	configDir := filepath.Join(dir, "config")
	workDir := filepath.Join(dir, "work")
	logsDir := filepath.Join(dir, "logs")
	for _, p := range []string{configDir, workDir, logsDir} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	issueLogPath := filepath.Join(dir, "certbot-issue.log")
	renewLogPath := filepath.Join(dir, "certbot-renew.log")
	revokeLogPath := filepath.Join(dir, "certbot-revoke.log")
	letsEncryptLogPath := filepath.Join(logsDir, "letsencrypt.log")
	liveDir := filepath.Join(configDir, "live", certName)
	certPath := filepath.Join(liveDir, "cert.pem")
	fullchainPath := filepath.Join(liveDir, "fullchain.pem")
	renewalPath := filepath.Join(configDir, "renewal", certName+".conf")
	t.Cleanup(func() {
		servedArchiveExistingConformanceTranscripts(t, "served-acme-certbot", caFile, recordsPath,
			hookLogPath, issueLogPath, renewLogPath, revokeLogPath, letsEncryptLogPath,
			certPath, fullchainPath, renewalPath)
	})

	env := append(os.Environ(),
		"REQUESTS_CA_BUNDLE="+caFile,
		"SSL_CERT_FILE="+caFile,
		"TRSTCTL_CERTBOT_RECORDS="+recordsPath,
		"TRSTCTL_CERTBOT_HOOK_LOG="+hookLogPath,
	)
	commonArgs := []string{
		"--server", ts.URL + "/directory",
		"--config-dir", configDir,
		"--work-dir", workDir,
		"--logs-dir", logsDir,
		"--non-interactive",
	}

	servedRunExternalClient(t, certbot, append([]string{
		"certonly",
		"--manual",
		"--preferred-challenges", "dns",
		"--manual-auth-hook", authHook,
		"--manual-cleanup-hook", cleanupHook,
		"--agree-tos",
		"--email", "acme-stock-client@example.com",
		"--no-eff-email",
		"--cert-name", certName,
		"-d", domain,
	}, commonArgs...), env, issueLogPath)
	servedAssertCertbotIssuedDomain(t, certPath, domain)

	servedRunExternalClient(t, certbot, append([]string{
		"renew",
		"--force-renewal",
		"--cert-name", certName,
		"--preferred-challenges", "dns",
		"--manual-auth-hook", authHook,
		"--manual-cleanup-hook", cleanupHook,
		"--no-random-sleep-on-renew",
	}, commonArgs...), env, renewLogPath)
	servedAssertCertbotIssuedDomain(t, certPath, domain)

	leafDER := servedReadPEMCert(t, certPath)
	if err := crypto.VerifyLeafSignedByCA(leafDER, caCertDER(t, h.caPEM)); err != nil {
		t.Fatalf("certbot-issued served ACME cert does not verify against served CA: %v", err)
	}
	if !h.hasEvent(t, "certificate.recorded") {
		t.Error("no certificate.recorded event after certbot issuance")
	}

	servedRunExternalClient(t, certbot, append([]string{
		"revoke",
		"--cert-path", certPath,
		"--reason", "keycompromise",
		"--no-delete-after-revoke",
	}, commonArgs...), env, revokeLogPath)
	if st := servedOCSPStatus(t, h.srv, h.tenant, leafDER, h.caPEM); st != "revoked" {
		t.Fatalf("certbot ACME revoke did not feed served OCSP: status = %q, want revoked", st)
	}

	servedArchiveConformanceTranscripts(t, "served-acme-certbot", caFile, recordsPath,
		hookLogPath, issueLogPath, renewLogPath, revokeLogPath, certPath, fullchainPath, renewalPath)
}

// TestServedESTLibestSimpleEnroll proves the required libest estclient job reaches
// the mounted EST route, not the package-level EST server. It performs a real
// simpleenroll with a Bearer API token and verifies the issued cert against the served
// signer-backed CA.
func TestServedESTLibestSimpleEnroll(t *testing.T) {
	bin := os.Getenv("EST_LIBEST")
	if bin == "" {
		if os.Getenv("TRSTCTL_REQUIRE_LIBEST") == "1" || os.Getenv("TRSTCTL_REQUIRE_ESTCLIENT") == "1" {
			t.Fatal("EST_LIBEST is not set; CI must provide the pinned libest estclient")
		}
		t.Skip("EST_LIBEST not set; set TRSTCTL_REQUIRE_LIBEST=1 in CI to make libest mandatory")
	}
	if _, err := exec.LookPath(bin); err != nil {
		t.Fatalf("EST_LIBEST=%q is not executable: %v", bin, err)
	}

	h := newServedHarness(t, config.Protocols{
		EST: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
	})
	if !protoContains(h.srv.ServedProtocols(), "est") {
		t.Fatal("EST is not reported as served")
	}
	token := seedAPIToken(t, h.store, servedTestTenant)

	ts := httptest.NewTLSServer(h.srv.Handler())
	t.Cleanup(ts.Close)
	dir := t.TempDir()
	caFile := filepath.Join(dir, "served-est-https-ca.pem")
	servedWriteTLSCertPEM(t, caFile, ts)
	host, port := servedSplitHostPort(t, ts.URL)
	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		t.Fatal(err)
	}
	logOut := filepath.Join(dir, "libest-simpleenroll.log")

	cmd := exec.Command(bin,
		"-e",
		"-s", host,
		"-p", port,
		"-o", outDir,
		"--auth-token", token,
		"--common-name", "libest-served-device",
		"-v",
	)
	cmd.Env = append(os.Environ(), "EST_OPENSSL_CACERT="+caFile)
	out, err := cmd.CombinedOutput()
	if werr := os.WriteFile(logOut, out, 0o600); werr != nil {
		t.Fatalf("write libest log: %v", werr)
	}
	if err != nil {
		t.Fatalf("libest estclient simpleenroll failed against served EST endpoint: %v\n%s", err, out)
	}
	p7Path := filepath.Join(outDir, "cert-0-0.pkcs7")
	gotB64, err := os.ReadFile(p7Path)
	if err != nil {
		t.Fatalf("libest estclient did not write %s: %v\n%s", p7Path, err, out)
	}
	p7, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(gotB64)))
	if err != nil {
		t.Fatalf("libest simpleenroll output is not base64 PKCS#7: %v\n%s", err, gotB64)
	}
	certs, err := crypto.CertsFromPKCS7(p7)
	if err != nil || len(certs) == 0 {
		t.Fatalf("libest simpleenroll output carries no certificate: %v", err)
	}
	if err := crypto.VerifyLeafSignedByCA(certs[0], caCertDER(t, h.caPEM)); err != nil {
		t.Fatalf("libest-issued served EST cert does not verify against served CA: %v", err)
	}
	if !h.hasEvent(t, "certificate.recorded") {
		t.Error("no certificate.recorded event after libest simpleenroll")
	}
	servedArchiveConformanceTranscripts(t, "served-est-libest", caFile, p7Path, logOut)
}

// TestServedSCEPSSCEPClientEnrollment proves stock sscep drives /scep on the
// assembled control-plane handler, with PKIOperation request/response transcripts
// captured from the served path.
func TestServedSCEPSSCEPClientEnrollment(t *testing.T) {
	sscep, err := exec.LookPath("sscep")
	if err != nil {
		if os.Getenv("TRSTCTL_REQUIRE_SSCEP") == "1" {
			t.Fatalf("TRSTCTL_REQUIRE_SSCEP is set but sscep is not on PATH: %v", err)
		}
		t.Skip("sscep not on PATH; set TRSTCTL_REQUIRE_SSCEP=1 in CI to make the external SCEP client mandatory")
	}

	h := newServedHarness(t, config.Protocols{
		SCEP: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
	})
	if !protoContains(h.srv.ServedProtocols(), "scep") {
		t.Fatal("SCEP is not reported as served")
	}
	recorder := newServedSCEPTranscriptRecorder(t.TempDir(), h.srv.Handler())
	ts := httptest.NewServer(recorder)
	t.Cleanup(ts.Close)

	_, clientKey, csrDER := newSCEPClient(t, "sscep-served-device")
	dir := t.TempDir()
	caFile := filepath.Join(dir, "sscep-ca.crt")
	clientKeyFile := servedWritePEMFile(t, dir, "sscep-client.key", "PRIVATE KEY", clientKey)
	csrFile := servedWritePEMFile(t, dir, "sscep-client.csr", "CERTIFICATE REQUEST", csrDER)
	issuedFile := filepath.Join(dir, "sscep-issued.crt")
	selfSignedFile := filepath.Join(dir, "sscep-selfsigned.crt")
	getCALog := filepath.Join(dir, "sscep-getca.log")
	enrollLog := filepath.Join(dir, "sscep-enroll.log")
	scepURL := ts.URL + "/scep/pkiclient.exe"

	getCA := exec.Command(sscep, "getca",
		"-u", scepURL,
		"-c", caFile,
		"-F", "sha256",
		"-v",
	)
	getCAOut, err := getCA.CombinedOutput()
	if werr := os.WriteFile(getCALog, getCAOut, 0o600); werr != nil {
		t.Fatalf("write sscep getca log: %v", werr)
	}
	if err != nil {
		t.Fatalf("sscep getca failed against served SCEP endpoint: %v\n%s", err, getCAOut)
	}
	if stat, err := os.Stat(caFile); err != nil {
		t.Fatalf("sscep getca did not write CA file: %v\n%s", err, getCAOut)
	} else if stat.Size() == 0 {
		t.Fatalf("sscep getca wrote an empty CA file\n%s", getCAOut)
	}

	enroll := exec.Command(sscep, "enroll",
		"-u", scepURL,
		"-c", caFile,
		"-k", clientKeyFile,
		"-r", csrFile,
		"-l", issuedFile,
		"-L", selfSignedFile,
		"-E", "aes256",
		"-S", "sha256",
		"-t", "1",
		"-n", "1",
		"-v",
	)
	enrollOut, err := enroll.CombinedOutput()
	if werr := os.WriteFile(enrollLog, enrollOut, 0o600); werr != nil {
		t.Fatalf("write sscep enroll log: %v", werr)
	}
	if err != nil {
		t.Fatalf("sscep enroll failed against served SCEP endpoint: %v\n%s", err, enrollOut)
	}
	issuedDER := servedReadCertificateFile(t, issuedFile)
	if err := crypto.VerifyLeafSignedByCA(issuedDER, caCertDER(t, h.caPEM)); err != nil {
		t.Fatalf("sscep-issued served SCEP cert does not verify against served CA: %v", err)
	}
	if !h.hasEvent(t, "certificate.recorded") {
		t.Error("no certificate.recorded event after sscep enrollment")
	}

	pkiReq, pkiResp := recorder.pkioOperationFiles(t)
	servedArchiveConformanceTranscripts(t, "served-scep-sscep", caFile, issuedFile, selfSignedFile, getCALog, enrollLog, pkiReq, pkiResp)
}

// TestServedCMPOpenSSLClientP10CREnrollment proves stock OpenSSL cmp enrolls against
// the mounted /cmp endpoint on the assembled control-plane handler.
func TestServedCMPOpenSSLClientP10CREnrollment(t *testing.T) {
	ossl, err := exec.LookPath("openssl")
	if err != nil {
		if os.Getenv("TRSTCTL_REQUIRE_OPENSSL_CMP") == "1" {
			t.Fatalf("TRSTCTL_REQUIRE_OPENSSL_CMP is set but openssl is not on PATH: %v", err)
		}
		t.Skip("openssl not on PATH; set TRSTCTL_REQUIRE_OPENSSL_CMP=1 in CI to make the external CMP client mandatory")
	}

	h := newServedHarness(t, config.Protocols{
		CMP: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant},
	})
	if !protoContains(h.srv.ServedProtocols(), "cmp") {
		t.Fatal("CMP is not reported as served")
	}

	clientCert, clientKey, csrDER := newSCEPClient(t, "openssl-cmp-served-device")
	dir := t.TempDir()
	caFile := filepath.Join(dir, "served-cmp-ca.pem")
	if err := os.WriteFile(caFile, h.caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	raFile := servedWritePEMFile(t, dir, "served-cmp-ra.pem", "CERTIFICATE", h.srv.protoRACertDER)
	clientCertFile := servedWritePEMFile(t, dir, "client.pem", "CERTIFICATE", clientCert)
	clientKeyFile := servedWritePEMFile(t, dir, "client.key", "PRIVATE KEY", clientKey)
	csrFile := servedWritePEMFile(t, dir, "client.csr", "CERTIFICATE REQUEST", csrDER)
	reqOut := filepath.Join(dir, "openssl-cmp-p10cr-request.der")
	rspOut := filepath.Join(dir, "openssl-cmp-p10cr-response.der")
	certOut := filepath.Join(dir, "openssl-cmp-issued.pem")
	logOut := filepath.Join(dir, "openssl-cmp.log")

	cmd := exec.Command(ossl, "cmp",
		"-config", "",
		"-cmd", "p10cr",
		"-server", h.ts.URL,
		"-path", "/cmp",
		"-csr", csrFile,
		"-cert", clientCertFile,
		"-key", clientKeyFile,
		"-extracerts", clientCertFile,
		"-srvcert", raFile,
		"-ignore_keyusage",
		"-disable_confirm",
		"-certout", certOut,
		"-reqout", reqOut,
		"-rspout", rspOut,
		"-batch",
		"-verbosity", "7",
	)
	out, err := cmd.CombinedOutput()
	if werr := os.WriteFile(logOut, out, 0o600); werr != nil {
		t.Fatalf("write openssl cmp log: %v", werr)
	}
	if err != nil {
		t.Fatalf("openssl cmp p10cr enrollment failed against served CMP endpoint: %v\n%s", err, out)
	}
	for _, p := range []string{reqOut, rspOut, certOut} {
		if stat, err := os.Stat(p); err != nil {
			t.Fatalf("openssl cmp did not write %s: %v\n%s", p, err, out)
		} else if stat.Size() == 0 {
			t.Fatalf("openssl cmp wrote empty %s\n%s", p, out)
		}
	}
	issuedDER := servedReadPEMCert(t, certOut)
	if err := crypto.VerifyLeafSignedByCA(issuedDER, caCertDER(t, h.caPEM)); err != nil {
		t.Fatalf("openssl-cmp-issued served CMP cert does not verify against served CA: %v", err)
	}
	if !h.hasEvent(t, "certificate.recorded") {
		t.Error("no certificate.recorded event after OpenSSL CMP enrollment")
	}
	servedArchiveConformanceTranscripts(t, "served-cmp-openssl-p10cr", caFile, raFile, reqOut, rspOut, certOut, logOut)
}

type servedCertbotDNSResolver struct {
	recordsPath string
}

func (r servedCertbotDNSResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	wantName := strings.TrimSuffix(name, ".")
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		if vals := r.lookupTXTOnce(wantName); len(vals) > 0 {
			return vals, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, fmt.Errorf("no certbot DNS-01 TXT record for %s", wantName)
		case <-tick.C:
		}
	}
}

func (r servedCertbotDNSResolver) lookupTXTOnce(wantName string) []string {
	b, err := os.ReadFile(r.recordsPath)
	if err != nil {
		return nil
	}
	var vals []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 || parts[0] != wantName {
			continue
		}
		vals = append(vals, parts[1])
	}
	return vals
}

func servedCertbotAuthHookScript() string {
	return `#!/bin/sh
set -eu
: "${TRSTCTL_CERTBOT_RECORDS:?missing records path}"
: "${TRSTCTL_CERTBOT_HOOK_LOG:?missing hook log path}"
name="_acme-challenge.${CERTBOT_DOMAIN}"
printf '%s\t%s\n' "$name" "$CERTBOT_VALIDATION" >> "$TRSTCTL_CERTBOT_RECORDS"
printf 'auth %s %s\n' "$name" "$CERTBOT_VALIDATION" >> "$TRSTCTL_CERTBOT_HOOK_LOG"
`
}

func servedCertbotCleanupHookScript() string {
	return `#!/bin/sh
set -eu
: "${TRSTCTL_CERTBOT_HOOK_LOG:?missing hook log path}"
printf 'cleanup _acme-challenge.%s\n' "$CERTBOT_DOMAIN" >> "$TRSTCTL_CERTBOT_HOOK_LOG"
`
}

func servedWriteExecutable(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write executable %s: %v", path, err)
	}
}

func servedWriteTLSCertPEM(t *testing.T, path string, ts *httptest.Server) {
	t.Helper()
	if len(ts.TLS.Certificates) == 0 || len(ts.TLS.Certificates[0].Certificate) == 0 {
		t.Fatal("httptest TLS server has no certificate")
	}
	der := ts.TLS.Certificates[0].Certificate[0]
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write TLS cert PEM: %v", err)
	}
}

func servedRunExternalClient(t *testing.T, bin string, args, env []string, logPath string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if werr := os.WriteFile(logPath, out, 0o600); werr != nil {
		t.Fatalf("write external client log: %v", werr)
	}
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", bin, strings.Join(args, " "), err, out)
	}
}

func servedAssertCertbotIssuedDomain(t *testing.T, certPath, domain string) {
	t.Helper()
	info, err := certinfo.Inspect(servedReadPEMCert(t, certPath))
	if err != nil {
		t.Fatalf("inspect certbot certificate: %v", err)
	}
	if !protoContains(info.DNSNames, domain) {
		t.Fatalf("certbot certificate DNSNames=%v, missing %q", info.DNSNames, domain)
	}
}

func servedReadPEMCert(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cert %s: %v", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("%s is not a certificate PEM", path)
	}
	return block.Bytes
}

func servedReadCertificateFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if block, _ := pem.Decode(raw); block != nil && block.Type == "CERTIFICATE" {
		return block.Bytes
	}
	return raw
}

func servedWritePEMFile(t *testing.T, dir, name, typ string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func servedSplitHostPort(t *testing.T, rawURL string) (host, port string) {
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

type servedSCEPTranscriptRecorder struct {
	mu      sync.Mutex
	dir     string
	handler http.Handler
	pkiReq  string
	pkiResp string
}

func newServedSCEPTranscriptRecorder(dir string, handler http.Handler) *servedSCEPTranscriptRecorder {
	return &servedSCEPTranscriptRecorder{dir: dir, handler: handler}
}

func (r *servedSCEPTranscriptRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var requestDER []byte
	if req.URL.Query().Get("operation") == "PKIOperation" {
		if req.Method == http.MethodPost {
			requestDER, _ = io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(requestDER))
		} else if msg := req.URL.Query().Get("message"); msg != "" {
			requestDER, _ = base64.StdEncoding.DecodeString(msg)
		}
	}
	rw := &servedRecordingResponseWriter{ResponseWriter: w}
	r.handler.ServeHTTP(rw, req)
	if req.URL.Query().Get("operation") != "PKIOperation" || len(requestDER) == 0 || len(rw.body.Bytes()) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	reqPath := filepath.Join(r.dir, "sscep-pkioperation-request.der")
	respPath := filepath.Join(r.dir, "sscep-pkioperation-response.der")
	if err := os.WriteFile(reqPath, requestDER, 0o600); err == nil {
		r.pkiReq = reqPath
	}
	if err := os.WriteFile(respPath, rw.body.Bytes(), 0o600); err == nil {
		r.pkiResp = respPath
	}
}

func (r *servedSCEPTranscriptRecorder) pkioOperationFiles(t *testing.T) (string, string) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range []string{r.pkiReq, r.pkiResp} {
		if p == "" {
			t.Fatalf("sscep enrollment did not produce a captured PKIOperation transcript")
		}
		if stat, err := os.Stat(p); err != nil {
			t.Fatalf("captured PKIOperation transcript %s is missing: %v", p, err)
		} else if stat.Size() == 0 {
			t.Fatalf("captured PKIOperation transcript %s is empty", p)
		}
	}
	return r.pkiReq, r.pkiResp
}

type servedRecordingResponseWriter struct {
	http.ResponseWriter
	body bytes.Buffer
}

func (w *servedRecordingResponseWriter) Write(p []byte) (int, error) {
	_, _ = w.body.Write(p)
	return w.ResponseWriter.Write(p)
}

func servedArchiveConformanceTranscripts(t *testing.T, prefix string, paths ...string) {
	t.Helper()
	dstDir := os.Getenv("TRSTCTL_INTEROP_TRANSCRIPT_DIR")
	if dstDir == "" {
		return
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatalf("create transcript archive dir: %v", err)
	}
	for _, src := range paths {
		servedArchiveOneTranscript(t, dstDir, prefix, src)
	}
}

func servedArchiveExistingConformanceTranscripts(t *testing.T, prefix string, paths ...string) {
	t.Helper()
	dstDir := os.Getenv("TRSTCTL_INTEROP_TRANSCRIPT_DIR")
	if dstDir == "" {
		return
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatalf("create transcript archive dir: %v", err)
	}
	for _, src := range paths {
		if src == "" {
			continue
		}
		if stat, err := os.Stat(src); err != nil || stat.Size() == 0 {
			continue
		}
		servedArchiveOneTranscript(t, dstDir, prefix, src)
	}
}

func servedArchiveOneTranscript(t *testing.T, dstDir, prefix, src string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("open transcript %s: %v", src, err)
	}
	defer func() { _ = in.Close() }()
	dst := filepath.Join(dstDir, prefix+"-"+filepath.Base(src))
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("create archived transcript %s: %v", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		t.Fatalf("copy transcript %s: %v", src, err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close archived transcript %s: %v", dst, err)
	}
}
