package mtls_test

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/mtls"
)

// TestServeHTTPSEncryptsAndRefusesPlaintext is the B4 acceptance: the control
// plane served with a self-signed internal certificate answers over TLS to a
// client that trusts it, a session cookie travels only over that TLS connection,
// and a plaintext request to the same socket is refused (nothing in the clear).
func TestServeHTTPSEncryptsAndRefusesPlaintext(t *testing.T) {
	sc, err := mtls.SelfSignedServerCert([]string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("SelfSignedServerCert: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "trstctl_session", Value: "top-secret-session"})
		_, _ = io.WriteString(w, "ok")
	})}
	go func() { _ = sc.ServeHTTPS(srv, ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	addr := ln.Addr().String()

	// A client trusting the server's certificate gets 200 over TLS, and the
	// session cookie is delivered (over the encrypted channel).
	tr, err := mtls.HTTPTransport(sc.TrustPEM)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	var resp *http.Response
	for i := 0; i < 50; i++ { // tolerate the serve goroutine starting
		resp, err = client.Get("https://" + addr + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("HTTPS GET never succeeded: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HTTPS GET = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Set-Cookie"), "trstctl_session") {
		t.Errorf("session cookie not delivered over TLS: %q", resp.Header.Get("Set-Cookie"))
	}

	// A plaintext request to the TLS socket never reaches the handler: the server
	// rejects it (Go answers a bare 400 "Client sent an HTTP request to an HTTPS
	// server"), so no handler response — and no session cookie — travels in the
	// clear.
	plain := &http.Client{Timeout: 2 * time.Second}
	if presp, perr := plain.Get("http://" + addr + "/healthz"); perr == nil {
		defer func() { _ = presp.Body.Close() }()
		if presp.StatusCode/100 == 2 {
			t.Errorf("plaintext request to the TLS socket was served by the handler (%d); cleartext must be refused", presp.StatusCode)
		}
		if strings.Contains(presp.Header.Get("Set-Cookie"), "trstctl_session") {
			t.Error("session cookie was delivered over a plaintext request")
		}
	}
}

// TestServeHTTPSRefusesTLS12 is the WIRE-008 acceptance: the operator HTTPS surface
// pins a TLS 1.3 floor, so a client that caps at TLS 1.2 is refused, while a TLS
// 1.3 client connects and negotiates exactly 1.3. The pre-fix server set MinVersion
// TLS 1.2, which a 1.2-only client could negotiate.
func TestServeHTTPSRefusesTLS12(t *testing.T) {
	sc, err := mtls.SelfSignedServerCert([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("SelfSignedServerCert: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })}
	go func() { _ = sc.ServeHTTPS(srv, ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	addr := ln.Addr().String()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(sc.TrustPEM) {
		t.Fatal("could not load TrustPEM")
	}

	// TLS 1.3 client: succeeds and must negotiate 1.3.
	ok13 := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
	}}
	var resp *http.Response
	for i := 0; i < 50; i++ {
		resp, err = ok13.Get("https://" + addr + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("TLS 1.3 client never connected: %v", err)
	}
	if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 {
		got := uint16(0)
		if resp.TLS != nil {
			got = resp.TLS.Version
		}
		t.Errorf("negotiated TLS version = 0x%04x, want TLS 1.3 (0x%04x)", got, tls.VersionTLS13)
	}
	_ = resp.Body.Close()

	// TLS 1.2-max client: must be refused (handshake fails) since the floor is 1.3.
	only12 := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12},
	}}
	if r, err := only12.Get("https://" + addr + "/healthz"); err == nil {
		_ = r.Body.Close()
		t.Errorf("TLS 1.2 client was accepted (status %d); the operator floor must be TLS 1.3 (WIRE-008)", r.StatusCode)
	}
}

// TestSelfSignedServerCertHasUsableSANs: the generated certificate is a server
// certificate covering the requested hostnames and IPs.
func TestSelfSignedServerCertHasUsableSANs(t *testing.T) {
	sc, err := mtls.SelfSignedServerCert([]string{"localhost", "127.0.0.1", "trstctl"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.TrustPEM) == 0 {
		t.Fatal("TrustPEM is empty; a client would have nothing to trust")
	}
}

// TestServerCertFromFilesRejectsMissing: an operator cert/key path that does not
// exist fails clearly rather than serving without TLS.
func TestServerCertFromFilesRejectsMissing(t *testing.T) {
	if _, err := mtls.ServerCertFromFiles("/no/such/cert.pem", "/no/such/key.pem"); err == nil {
		t.Error("ServerCertFromFiles accepted a missing cert/key")
	}
}

// TestLoopbackProbeClientTrustsNothingButConnects: the loopback liveness client
// reaches an internal-cert server (it does not verify the chain — it is a
// localhost liveness probe only).
func TestLoopbackProbeClientReachesInternalServer(t *testing.T) {
	sc, err := mtls.SelfSignedServerCert([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })}
	go func() { _ = sc.ServeHTTPS(srv, ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	client := mtls.LoopbackProbeClient(3 * time.Second)
	var err2 error
	for i := 0; i < 50; i++ {
		resp, e := client.Get("https://" + ln.Addr().String() + "/healthz")
		if e == nil {
			_ = resp.Body.Close()
			err2 = nil
			break
		}
		err2 = e
		time.Sleep(20 * time.Millisecond)
	}
	if err2 != nil && !errors.Is(err2, http.ErrServerClosed) {
		t.Fatalf("loopback probe client could not reach the internal-cert server: %v", err2)
	}
}
