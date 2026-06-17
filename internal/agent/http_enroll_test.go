package agent_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent"
	"trstctl.com/trstctl/internal/agent/enroll"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

func TestAgentBootstrapRejectsPlainHTTP(t *testing.T) {
	a, closeServer := newHTTPBootstrapAgent(t)
	defer closeServer()

	err := a.Bootstrap(context.Background())
	if err == nil {
		t.Fatal("bootstrap over plaintext HTTP succeeded")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Fatalf("bootstrap error = %v, want HTTPS rejection", err)
	}
}

func TestAgentBootstrapAllowsExplicitLoopbackDevHTTP(t *testing.T) {
	authority, token := newBootstrapAuthority(t)
	hsrv := httptest.NewServer(enroll.Handler(authority))
	t.Cleanup(hsrv.Close)

	a := newBootstrapAgent(t, token, authority.CABundlePEM(), agent.NewHTTPEnroller(hsrv.URL, nil, agent.WithLoopbackDevHTTP()))
	if err := a.Bootstrap(context.Background()); err != nil {
		t.Fatalf("Bootstrap over explicit loopback-dev HTTP: %v", err)
	}
	if a.CertificateSerial() == "" {
		t.Error("agent has no certificate after explicit loopback-dev bootstrap")
	}
}

func TestAgentBootstrapPinsCABundle(t *testing.T) {
	authority, token := newBootstrapAuthority(t)
	enrollURL, trustPEM := newHTTPSEnrollServer(t, enroll.Handler(authority))

	a := newBootstrapAgent(t, token, authority.CABundlePEM(), agent.NewHTTPEnroller(enrollURL, pinnedClientFromPEM(t, trustPEM)))
	if err := a.Bootstrap(context.Background()); err != nil {
		t.Fatalf("Bootstrap over pinned HTTPS: %v", err)
	}
	if a.CertificateSerial() == "" {
		t.Error("agent has no certificate after pinned HTTPS bootstrap")
	}
}

func TestAgentBootstrapRejectsWrongCA(t *testing.T) {
	authority, token := newBootstrapAuthority(t)
	enrollURL, _ := newHTTPSEnrollServer(t, enroll.Handler(authority))
	wrongCA, err := mtls.SelfSignedServerCert([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	a := newBootstrapAgent(t, token, authority.CABundlePEM(), agent.NewHTTPEnroller(enrollURL, pinnedClientFromPEM(t, wrongCA.TrustPEM)))
	if err := a.Bootstrap(context.Background()); err == nil {
		t.Fatal("bootstrap succeeded with a client pinned to the wrong CA")
	}
}

func newHTTPBootstrapAgent(t *testing.T) (*agent.Agent, func()) {
	t.Helper()
	authority, token := newBootstrapAuthority(t)
	hsrv := httptest.NewServer(enroll.Handler(authority))
	return newBootstrapAgent(t, token, authority.CABundlePEM(), agent.NewHTTPEnroller(hsrv.URL, hsrv.Client())), hsrv.Close
}

func newBootstrapAuthority(t *testing.T) (*enroll.Authority, string) {
	t.Helper()
	authority, err := enroll.NewAuthority("cp", enroll.NewMemoryTokenStore())
	if err != nil {
		t.Fatal(err)
	}
	token, err := authority.IssueBootstrapToken(context.Background(), "11111111-1111-1111-1111-111111111111", "")
	if err != nil {
		t.Fatal(err)
	}
	return authority, token
}

func newBootstrapAgent(t *testing.T, token string, caPEM []byte, enroller agent.Enroller) *agent.Agent {
	t.Helper()
	dir := t.TempDir()
	return agent.New(agent.Config{
		CommonName: "agent-http", BootstrapToken: token,
		KeyPath: filepath.Join(dir, "a.key"), CertPath: filepath.Join(dir, "a.crt"),
		ServerName: "localhost", ServerCAPEM: caPEM, RefreshBefore: time.Hour,
	}, enroller)
}

func newHTTPSEnrollServer(t *testing.T, handler http.Handler) (string, []byte) {
	t.Helper()
	cert, err := mtls.SelfSignedServerCert([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler}
	errc := make(chan error, 1)
	go func() {
		errc <- cert.ServeHTTPS(srv, ln)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		if err := <-errc; err != nil && err != http.ErrServerClosed {
			t.Fatalf("https enrollment server: %v", err)
		}
	})
	return "https://" + ln.Addr().String(), cert.TrustPEM
}

func pinnedClientFromPEM(t *testing.T, caPEM []byte) *http.Client {
	t.Helper()
	tr, err := mtls.HTTPTransport(caPEM)
	if err != nil {
		t.Fatalf("build pinned test client: %v", err)
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}
