// SPDX-License-Identifier: MPL-2.0

package shellca_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/shellca"
	"trstctl.com/trstctl/internal/crypto"
	boundaryca "trstctl.com/trstctl/internal/crypto/ca"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestSignCommandProducesCertificateFromCSR(t *testing.T) {
	tempRoot := t.TempDir()
	t.Setenv("TMPDIR", tempRoot)
	authority := []byte("descriptor-only-authority")
	p := shellca.New(shellca.Config{
		Name:    "shellca",
		Command: os.Args[0],
		Args:    []string{"-test.run=TestShellCASignHelperProcess", "--"},
		Env:     []string{"SHELLCA_HELPER=1"},
		SecretFDs: []shellca.SecretFD{{
			Name: "SHELLCA_TOKEN", Value: authority,
		}},
		Timeout: 5 * time.Second,
	})
	var _ ca.CA = p

	cert, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "tenant-a",
		CSR:      shellCSR(t, "svc.shellca.test", []string{"svc.shellca.test"}),
		DNSNames: []string{"svc.shellca.test"},
		TTL:      24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(cert.CertificatePEM) == 0 || cert.Serial == "" || cert.Issuer != "shellca" {
		t.Fatalf("issued cert = %+v", cert)
	}
	info, err := certinfo.Inspect(cert.CertificatePEM)
	if err != nil {
		t.Fatalf("inspect issued cert: %v", err)
	}
	if !containsDNS(info.DNSNames, "svc.shellca.test") {
		t.Fatalf("issued cert DNSNames = %v, want svc.shellca.test", info.DNSNames)
	}
	if !bytes.Equal(authority, make([]byte, len(authority))) {
		t.Fatalf("consumed secret descriptor bytes were not zeroed: %x", authority)
	}
	entries, err := os.ReadDir(tempRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("shell CA left filesystem-backed temp material: %v", entries)
	}
}

func TestSignerEchoCannotEscapeFailure(t *testing.T) {
	authority := []byte("shellca-receiver-echo-secret")
	p := shellca.New(shellca.Config{
		Name:    "shellca",
		Command: os.Args[0],
		Args:    []string{"-test.run=TestShellCASignHelperProcess", "--"},
		Env:     []string{"SHELLCA_HELPER=echo-fail"},
		SecretFDs: []shellca.SecretFD{{
			Name: "SHELLCA_TOKEN", Value: authority,
		}},
		Timeout: 5 * time.Second,
	})
	_, err := p.Issue(context.Background(), ca.IssueRequest{
		TenantID: "tenant-a",
		CSR:      shellCSR(t, "echo.shellca.test", []string{"echo.shellca.test"}),
		DNSNames: []string{"echo.shellca.test"},
		TTL:      time.Hour,
	})
	if err == nil {
		t.Fatal("Issue succeeded after signer echo-and-fail")
	}
	if strings.Contains(err.Error(), "shellca-receiver-echo-secret") {
		t.Fatalf("Issue error leaked signer output: %v", err)
	}
	if !bytes.Equal(authority, make([]byte, len(authority))) {
		t.Fatalf("failed signer left secret descriptor bytes in memory: %x", authority)
	}
}

func TestValidatorRejectsInjectionLadenCommandAndArgs(t *testing.T) {
	cases := []shellca.Config{
		{Command: "/usr/local/bin/openssl;rm"},
		{Command: "/bin/sh"},
		{Command: "/usr/local/bin/signer", Args: []string{"$(id)"}},
		{Command: "/usr/local/bin/signer", Args: []string{"safe|unsafe"}},
		{Command: "/usr/local/bin/signer", Args: []string{"line\nbreak"}},
	}
	for _, tc := range cases {
		if err := shellca.ValidateConfig(tc); err == nil {
			t.Fatalf("ValidateConfig(%+v) succeeded; want rejection", tc)
		}
	}
}

func TestShellCASignHelperProcess(t *testing.T) {
	mode := os.Getenv("SHELLCA_HELPER")
	if mode != "1" && mode != "echo-fail" {
		return
	}
	if os.Getenv("SHELLCA_TOKEN") != "" {
		_, _ = fmt.Fprintln(os.Stderr, "shellca helper: secret leaked into string environment")
		os.Exit(2)
	}
	descriptor := os.Getenv("SHELLCA_TOKEN_FD")
	if descriptor == "" {
		_, _ = fmt.Fprintln(os.Stderr, "shellca helper: secret descriptor is missing")
		os.Exit(2)
	}
	fd, err := strconv.Atoi(descriptor)
	if err != nil || fd < 3 {
		_, _ = fmt.Fprintln(os.Stderr, "shellca helper: secret descriptor is invalid")
		os.Exit(2)
	}
	secretFile := os.NewFile(uintptr(fd), "shellca-token")
	secretValue, err := io.ReadAll(io.LimitReader(secretFile, 1024))
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "shellca helper: read secret descriptor")
		os.Exit(2)
	}
	if mode == "echo-fail" {
		// Write far more than both stdout and stderr pipe capacities. The parent
		// must drain both streams concurrently without retaining or reporting any
		// echoed authority bytes.
		for i := 0; i < 8192; i++ {
			_, _ = os.Stdout.Write(secretValue)
			_, _ = os.Stderr.Write(secretValue)
		}
		secret.Wipe(secretValue)
		os.Exit(19)
	}
	if !bytes.Equal(secretValue, []byte("descriptor-only-authority")) {
		_, _ = fmt.Fprintln(os.Stderr, "shellca helper: secret descriptor did not carry exact authority bytes")
		os.Exit(2)
	}
	csrPath, certPath, ok := helperPaths(os.Args)
	if !ok {
		_, _ = fmt.Fprintln(os.Stderr, "shellca helper: missing csr/cert args")
		os.Exit(2)
	}
	csrPEM, err := os.ReadFile(csrPath) // #nosec G304 G703 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "shellca helper: read csr: %v\n", err)
		os.Exit(2)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		_, _ = fmt.Fprintln(os.Stderr, "shellca helper: csr is not PEM")
		os.Exit(2)
	}
	auth, err := boundaryca.NewAuthority("shellca helper root")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "shellca helper: authority: %v\n", err)
		os.Exit(2)
	}
	defer auth.Destroy()
	issued, err := auth.IssueFromCSR(block.Bytes, 24*time.Hour)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "shellca helper: issue: %v\n", err)
		os.Exit(2)
	}
	if err := os.WriteFile(certPath, issued.CertificatePEM, 0o600); err != nil { // #nosec G703 -- test path inside its own tempdir/checkout (CWE-22)
		_, _ = fmt.Fprintf(os.Stderr, "shellca helper: write cert: %v\n", err)
		os.Exit(2)
	}
	os.Exit(0)
}

func helperPaths(args []string) (csrPath, certPath string, ok bool) {
	for i, arg := range args {
		if arg == "--" && len(args) > i+2 {
			return args[i+1], args[i+2], true
		}
	}
	return "", "", false
}

func shellCSR(t *testing.T, cn string, dns []string) []byte {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn, DNSNames: dns}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func containsDNS(names []string, want string) bool {
	for _, n := range names {
		if strings.EqualFold(n, want) {
			return true
		}
	}
	return false
}
