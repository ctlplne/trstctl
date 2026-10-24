// SPDX-License-Identifier: BUSL-1.1

package mtls_test

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/mtls"
)

// B13-8, found proving A116 with stock OpenSSL on the lab: the served HTTPS
// listener refused a client that offered only the hybrid post-quantum group
// X25519MLKEM768, although the documentation says the served listeners prefer
// it. The group was dropped from CurvePreferences when post-quantum code left
// the core in July and was not restored when it came back. A hybrid-only client
// now negotiates it, and a classical-only client is still served.
func TestServeHTTPSNegotiatesTheHybridPostQuantumGroup(t *testing.T) {
	sc, err := mtls.SelfSignedServerCert([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("SelfSignedServerCert: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })} // #nosec G112 -- local test listener owned and torn down by the test (CWE-400)
	go func() { _ = sc.ServeHTTPS(srv, ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(sc.TrustPEM) {
		t.Fatal("could not load TrustPEM")
	}
	for _, tc := range []struct {
		name  string
		offer tls.CurveID
	}{{"hybrid-only client", tls.X25519MLKEM768}, {"classical-only client", tls.X25519}} {
		client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: pool, MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tc.offer},
		}}}
		var resp *http.Response
		for i := 0; i < 50; i++ {
			if resp, err = client.Get("https://" + ln.Addr().String() + "/healthz"); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("%s: handshake failed: %v", tc.name, err)
		}
		_ = resp.Body.Close()
		if resp.TLS == nil || resp.TLS.CurveID != tc.offer {
			t.Fatalf("%s negotiated %v, want %v", tc.name, resp.TLS.CurveID, tc.offer)
		}
	}
}

// The core served TLS paths, the agent channel included, put the hybrid group
// first so two trstctl peers agree on it without being told to.
func TestCurvePreferencesPutTheHybridGroupFirst(t *testing.T) {
	curves := mtls.CurvePreferences()
	if len(curves) == 0 || curves[0] != tls.X25519MLKEM768 {
		t.Fatalf("CurvePreferences = %v, want X25519MLKEM768 first", curves)
	}
}
