package agent_test

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent"
	"trstctl.com/trstctl/internal/agent/enroll"
)

// TestAgentBootstrapsOverHTTP exercises the binary's enrollment transport: the
// agent bootstraps through the HTTP enrollment endpoint (enroll.Handler) rather
// than an in-process enroller, and ends up with an issued certificate. Bootstrap is
// token-authenticated, so it does not need a client certificate.
func TestAgentBootstrapsOverHTTP(t *testing.T) {
	authority, err := enroll.NewAuthority("cp", enroll.NewMemoryTokenStore())
	if err != nil {
		t.Fatal(err)
	}
	token, err := authority.IssueBootstrapToken(context.Background(), "11111111-1111-1111-1111-111111111111", "")
	if err != nil {
		t.Fatal(err)
	}
	hsrv := httptest.NewServer(enroll.Handler(authority))
	t.Cleanup(hsrv.Close)

	dir := t.TempDir()
	a := agent.New(agent.Config{
		CommonName: "agent-http", BootstrapToken: token,
		KeyPath: filepath.Join(dir, "a.key"), CertPath: filepath.Join(dir, "a.crt"),
		ServerName: "localhost", ServerCAPEM: authority.CABundlePEM(), RefreshBefore: time.Hour,
	}, agent.NewHTTPEnroller(hsrv.URL, nil))

	if err := a.Bootstrap(context.Background()); err != nil {
		t.Fatalf("Bootstrap over HTTP: %v", err)
	}
	if a.CertificateSerial() == "" {
		t.Error("agent has no certificate after HTTP bootstrap")
	}

	// Renewal over PLAIN HTTP (no client-certificate verification) must now FAIL
	// CLOSED: the renewal handler requires a verified client certificate from the
	// TLS layer (WIRE-006), so serving enroll.Handler without mTLS is not an
	// unauthenticated cert-minting endpoint. This httptest server is plain HTTP, so
	// r.TLS.VerifiedChains is empty and the handler rejects the renewal — exactly the
	// latent open-mint the hardening closes. (Renewal succeeding under a verified
	// client cert is covered by enroll's TestEnrollRenewalRequiresVerifiedClientCert.)
	if err := a.Rotate(context.Background()); err == nil {
		t.Fatal("rotation over plain HTTP succeeded; renewal must require a verified client certificate (WIRE-006)")
	}
}
