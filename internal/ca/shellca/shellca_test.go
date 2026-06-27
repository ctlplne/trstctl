package shellca_test

import (
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/shellca"
	"trstctl.com/trstctl/internal/crypto"
	boundaryca "trstctl.com/trstctl/internal/crypto/ca"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

func TestSignCommandProducesCertificateFromCSR(t *testing.T) {
	p := shellca.New(shellca.Config{
		Name:    "shellca",
		Command: os.Args[0],
		Args:    []string{"-test.run=TestShellCASignHelperProcess", "--"},
		Env:     []string{"SHELLCA_HELPER=1"},
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
	if os.Getenv("SHELLCA_HELPER") != "1" {
		return
	}
	csrPath, certPath, ok := helperPaths(os.Args)
	if !ok {
		_, _ = fmt.Fprintln(os.Stderr, "shellca helper: missing csr/cert args")
		os.Exit(2)
	}
	csrPEM, err := os.ReadFile(csrPath)
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
	if err := os.WriteFile(certPath, issued.CertificatePEM, 0o600); err != nil {
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
