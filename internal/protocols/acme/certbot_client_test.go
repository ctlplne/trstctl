// SPDX-License-Identifier: MPL-2.0

package acme_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// TestACMECertbotManualDNSIssueRenewRevoke is the INTEROP-004 stock-client guard.
// A real certbot binary drives issue, renew, and revoke against the served ACME
// handler. The manual DNS hook writes the TXT value certbot asks for, and the
// production DNS-01 validator reads that value through its normal resolver seam.
func TestACMECertbotManualDNSIssueRenewRevoke(t *testing.T) {
	certbot, err := exec.LookPath("certbot")
	if err != nil {
		if os.Getenv("TRSTCTL_REQUIRE_CERTBOT") == "1" {
			t.Fatalf("TRSTCTL_REQUIRE_CERTBOT is set but certbot is not on PATH: %v", err)
		}
		t.Skip("certbot not on PATH; set TRSTCTL_REQUIRE_CERTBOT=1 in CI to make the stock ACME client mandatory")
	}

	builtin, err := ca.NewBuiltin("trstctl ACME certbot conformance CA")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certName := "trstctl-acme-certbot"
	domain := "certbot.acme.test"
	recordsPath := filepath.Join(dir, "certbot-dns-records.tsv")
	hookLogPath := filepath.Join(dir, "certbot-hooks.log")
	hooksDir := filepath.Join(dir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	authHook := filepath.Join(hooksDir, "auth.sh")
	cleanupHook := filepath.Join(hooksDir, "cleanup.sh")
	writeCertbotHook(t, authHook, certbotAuthHookScript())
	writeCertbotHook(t, cleanupHook, certbotCleanupHookScript())

	resolver := certbotDNSResolver{recordsPath: recordsPath}
	srv := acmesrv.New(builtin, acmesrv.Validators{
		DNS01: acmesrv.DNS01Validator{Resolver: resolver},
	})
	ts := httptest.NewTLSServer(srv)
	t.Cleanup(ts.Close)
	caFile := filepath.Join(dir, "acme-server-ca.pem")
	writeTLSCertPEM(t, caFile, ts)

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
		archiveExistingConformanceTranscripts(t, "acme-certbot", caFile, recordsPath,
			hookLogPath,
			issueLogPath,
			renewLogPath,
			revokeLogPath,
			letsEncryptLogPath,
			certPath,
			fullchainPath,
			renewalPath,
		)
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

	runExternalClient(t, certbot, append([]string{
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
	assertCertbotIssuedDomain(t, certPath, domain)

	runExternalClient(t, certbot, append([]string{
		"renew",
		"--force-renewal",
		"--cert-name", certName,
		"--preferred-challenges", "dns",
		"--manual-auth-hook", authHook,
		"--manual-cleanup-hook", cleanupHook,
		"--no-random-sleep-on-renew",
	}, commonArgs...), env, renewLogPath)
	assertCertbotIssuedDomain(t, certPath, domain)

	runExternalClient(t, certbot, append([]string{
		"revoke",
		"--cert-path", certPath,
		"--reason", "keycompromise",
		"--no-delete-after-revoke",
	}, commonArgs...), env, revokeLogPath)

	archiveConformanceTranscripts(t, "acme-certbot", caFile, recordsPath,
		hookLogPath,
		issueLogPath,
		renewLogPath,
		revokeLogPath,
		certPath,
		fullchainPath,
		renewalPath,
	)
}

type certbotDNSResolver struct {
	recordsPath string
}

func (r certbotDNSResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	wantName := strings.TrimSuffix(name, ".")
	deadline := time.Now().Add(10 * time.Second)
	for {
		records, err := readCertbotDNSRecords(r.recordsPath, wantName)
		if err != nil {
			return nil, err
		}
		if len(records) > 0 {
			return records, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("no certbot DNS-01 TXT record for %s", wantName)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func readCertbotDNSRecords(path, wantName string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var records []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		if strings.TrimSuffix(name, ".") == wantName {
			records = append(records, value)
		}
	}
	return records, nil
}

func certbotAuthHookScript() string {
	return `#!/usr/bin/env sh
set -eu
: "${CERTBOT_IDENTIFIER:=${CERTBOT_DOMAIN:?}}"
: "${TRSTCTL_CERTBOT_RECORDS:?}"
: "${TRSTCTL_CERTBOT_HOOK_LOG:?}"
record="_acme-challenge.${CERTBOT_IDENTIFIER}"
printf '%s	%s\n' "${record}" "${CERTBOT_VALIDATION}" >> "${TRSTCTL_CERTBOT_RECORDS}"
printf 'auth identifier=%s token=%s remaining=%s\n' "${CERTBOT_IDENTIFIER}" "${CERTBOT_TOKEN:-}" "${CERTBOT_REMAINING_CHALLENGES:-}" >> "${TRSTCTL_CERTBOT_HOOK_LOG}"
`
}

func certbotCleanupHookScript() string {
	return `#!/usr/bin/env sh
set -eu
: "${CERTBOT_IDENTIFIER:=${CERTBOT_DOMAIN:?}}"
: "${TRSTCTL_CERTBOT_HOOK_LOG:?}"
printf 'cleanup identifier=%s auth_output=%s\n' "${CERTBOT_IDENTIFIER}" "${CERTBOT_AUTH_OUTPUT:-}" >> "${TRSTCTL_CERTBOT_HOOK_LOG}"
`
}

func writeCertbotHook(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write certbot hook %s: %v", path, err)
	}
}

func writeTLSCertPEM(t *testing.T, path string, ts *httptest.Server) {
	t.Helper()
	block := &pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write ACME test server CA: %v", err)
	}
}

func runExternalClient(t *testing.T, bin string, args, env []string, logPath string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if writeErr := os.WriteFile(logPath, out, 0o600); writeErr != nil {
		t.Fatalf("write %s: %v", logPath, writeErr)
	}
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", bin, strings.Join(args, " "), err, out)
	}
}

func assertCertbotIssuedDomain(t *testing.T, certPath, domain string) {
	t.Helper()
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read certbot cert %s: %v", certPath, err)
	}
	info, err := certinfo.Inspect(pemBytes)
	if err != nil {
		t.Fatalf("inspect certbot certificate: %v", err)
	}
	for _, name := range info.DNSNames {
		if name == domain {
			return
		}
	}
	t.Fatalf("certbot certificate DNSNames=%v, missing %q", info.DNSNames, domain)
}

func archiveConformanceTranscripts(t *testing.T, prefix string, paths ...string) {
	t.Helper()
	dstDir := os.Getenv("TRSTCTL_INTEROP_TRANSCRIPT_DIR")
	if dstDir == "" {
		return
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatalf("create transcript archive dir: %v", err)
	}
	for _, src := range paths {
		if err := copyConformanceTranscript(dstDir, prefix, src); err != nil {
			t.Fatalf("archive transcript %s: %v", src, err)
		}
	}
}

func archiveExistingConformanceTranscripts(t *testing.T, prefix string, paths ...string) {
	t.Helper()
	dstDir := os.Getenv("TRSTCTL_INTEROP_TRANSCRIPT_DIR")
	if dstDir == "" {
		return
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Logf("create partial transcript archive dir: %v", err)
		return
	}
	for _, src := range paths {
		if err := copyConformanceTranscript(dstDir, prefix, src); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Logf("archive partial transcript %s: %v", src, err)
		}
	}
}

func copyConformanceTranscript(dstDir, prefix, src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	dst := filepath.Join(dstDir, prefix+"-"+filepath.Base(src))
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		_ = in.Close()
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = in.Close()
		_ = out.Close()
		return err
	}
	if err := in.Close(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func TestArchiveACMEConformanceTranscriptsWritesPublicFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRSTCTL_INTEROP_TRANSCRIPT_DIR", dir)
	src := filepath.Join(t.TempDir(), "certbot.log")
	if err := os.WriteFile(src, []byte("transcript"), 0o600); err != nil {
		t.Fatal(err)
	}
	archiveConformanceTranscripts(t, "unit", src)
	got, err := os.ReadFile(filepath.Join(dir, "unit-certbot.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("transcript")) {
		t.Fatalf("archived transcript = %q", got)
	}
}

func TestArchiveExistingACMEConformanceTranscriptsKeepsPartialLogs(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TRSTCTL_INTEROP_TRANSCRIPT_DIR", dir)
	src := filepath.Join(t.TempDir(), "certbot-issue.log")
	if err := os.WriteFile(src, []byte("partial failure log"), 0o600); err != nil {
		t.Fatal(err)
	}

	archiveExistingConformanceTranscripts(t, "unit", src, filepath.Join(t.TempDir(), "missing.log"))

	got, err := os.ReadFile(filepath.Join(dir, "unit-certbot-issue.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("partial failure log")) {
		t.Fatalf("archived partial transcript = %q", got)
	}
}
