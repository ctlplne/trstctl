// SPDX-License-Identifier: BUSL-1.1

package mtls

import (
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"
)

// The served floor is TLS 1.3. A device fleet whose stock EST client caps at
// TLS 1.2 (cisco libest) needs an explicit opt-in, and that opt-in must never
// admit a non-AEAD suite (DP2-036).
func TestServedTLSFloorIsThirteenUnlessAnOperatorOptsDownToAEADOnlyTwelve(t *testing.T) {
	serve := func(t *testing.T, allowTLS12 bool) string {
		t.Helper()
		sc, err := LoadOrCreateSelfSignedServerCert(t.TempDir()+"/state.pem", []string{"localhost"}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		sc.AllowTLS12 = allowTLS12
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), ReadHeaderTimeout: time.Second}
		go func() { _ = sc.ServeHTTPS(srv, ln) }()
		t.Cleanup(func() { _ = srv.Close() })
		return ln.Addr().String()
	}
	dial := func(addr string, maxVersion uint16) (tls.ConnectionState, error) {
		conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, MaxVersion: maxVersion}) // #nosec G402 -- loopback test dial against the test's own self-signed server (CWE-295)
		if err != nil {
			return tls.ConnectionState{}, err
		}
		defer func() { _ = conn.Close() }()
		return conn.ConnectionState(), nil
	}

	strict := serve(t, false)
	if _, err := dial(strict, tls.VersionTLS12); err == nil {
		t.Fatal("the default floor accepted a TLS 1.2-only client")
	}
	if state, err := dial(strict, tls.VersionTLS13); err != nil || state.Version != tls.VersionTLS13 {
		t.Fatalf("default floor: TLS 1.3 dial err=%v version=%x", err, state.Version)
	}

	lowered := serve(t, true)
	state, err := dial(lowered, tls.VersionTLS12)
	if err != nil {
		t.Fatalf("opt-in floor refused a TLS 1.2 client: %v", err)
	}
	if state.Version != tls.VersionTLS12 {
		t.Fatalf("negotiated %x, want TLS 1.2", state.Version)
	}
	aead := false
	for _, id := range tls12AEADSuites() {
		if state.CipherSuite == id {
			aead = true
		}
	}
	if !aead {
		t.Fatalf("TLS 1.2 negotiated non-AEAD suite %x", state.CipherSuite)
	}
	if state, err := dial(lowered, tls.VersionTLS13); err != nil || state.Version != tls.VersionTLS13 {
		t.Fatalf("opt-in floor must still prefer TLS 1.3 for capable clients: err=%v version=%x", err, state.Version)
	}
}
