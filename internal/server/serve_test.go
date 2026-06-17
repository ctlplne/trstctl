package server

import (
	"bytes"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

func newHandler() *http.Server {
	return &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })}
}

// TestServeControlPlaneInternalRefusesPlaintext: the default (internal TLS) mode
// serves over TLS, so a plaintext request to the socket fails — the control plane
// refuses cleartext by default (B4).
func TestServeControlPlaneInternalRefusesPlaintext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newHandler()
	go func() { _ = serveControlPlane(srv, ln, config.TLS{Mode: config.TLSInternal}, &bytes.Buffer{}) }()
	t.Cleanup(func() { _ = srv.Close() })

	// Poll until the TLS server is up enough to refuse a plaintext request (Go
	// answers a bare 400 to HTTP-over-TLS). Getting the handler's 200 over
	// plaintext is the failure; never getting any response means the server never
	// started.
	plain := &http.Client{Timeout: 2 * time.Second}
	responded := false
	for i := 0; i < 100; i++ {
		resp, err := plain.Get("http://" + ln.Addr().String() + "/healthz")
		if err != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		status := resp.StatusCode
		_ = resp.Body.Close()
		responded = true
		if status == http.StatusOK {
			t.Errorf("internal-TLS server served the handler (200) over a plaintext request; cleartext must be refused")
		}
		break
	}
	if !responded {
		t.Fatal("internal-TLS server never responded (even to refuse plaintext); it may not have started")
	}
}

// TestServeControlPlaneDisabledAllowsPlaintext: plaintext is available
// only as an explicit, loudly-warned opt-in for local development.
func TestServeControlPlaneDisabledAllowsPlaintext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newHandler()
	var warn bytes.Buffer
	go func() { _ = serveControlPlane(srv, ln, config.TLS{Mode: config.TLSDisabled}, &warn) }()
	t.Cleanup(func() { _ = srv.Close() })

	client := &http.Client{Timeout: 2 * time.Second}
	var resp *http.Response
	for i := 0; i < 50; i++ {
		resp, err = client.Get("http://" + ln.Addr().String() + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("disabled mode should serve plaintext: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("plaintext GET = %d, want 200", resp.StatusCode)
	}
	if w := warn.String(); !strings.Contains(strings.ToUpper(w), "PLAINTEXT") {
		t.Errorf("disabled mode must log a loud plaintext warning, got: %q", w)
	}
}

// TestServeControlPlaneFileModeRejectsBadCert: a file mode pointing at a missing
// certificate fails fast rather than silently falling back to plaintext.
func TestServeControlPlaneFileModeRejectsBadCert(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	err = serveControlPlane(newHandler(), ln, config.TLS{Mode: config.TLSFile, CertFile: "/no/such/cert.pem", KeyFile: "/no/such/key.pem"}, &bytes.Buffer{})
	if err == nil {
		t.Error("file mode with a missing certificate must return an error")
	}
}
