// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// The container health check verifies the listener it probes: in internal mode
// it pins the certificate published in the trust file, in file mode the
// configured certificate file, and a different or missing certificate fails the
// probe instead of being skipped.
func TestHealthProbePinsTheServedCertificate(t *testing.T) {
	served, err := mtls.SelfSignedServerCert([]string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { // #nosec G112 -- local test listener owned and torn down by the test (CWE-400)
		if r.URL.Path == healthProbePath {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})}
	go func() { _ = served.ServeHTTPS(srv, ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	dir := t.TempDir()
	trust := filepath.Join(dir, "internal-server.crt")
	if err := os.WriteFile(trust, served.TrustPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	other, err := mtls.SelfSignedServerCert([]string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	otherTrust := filepath.Join(dir, "other.crt")
	if err := os.WriteFile(otherTrust, other.TrustPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := func(mode, file string) *config.Config {
		c := &config.Config{}
		c.Server.Addr = ln.Addr().String()
		c.Server.TLS.Mode = mode
		if mode == config.TLSInternal {
			c.Server.TLS.InternalTrustFile = file
		} else {
			c.Server.TLS.CertFile = file
		}
		return c
	}
	var ready error
	for i := 0; i < 50; i++ {
		if ready = healthProbe(cfg(config.TLSInternal, trust)); ready == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if ready != nil {
		t.Fatalf("internal mode: the probe could not verify its own listener: %v", ready)
	}
	if err := healthProbe(cfg(config.TLSFile, trust)); err != nil {
		t.Fatalf("file mode: %v", err)
	}
	if err := healthProbe(cfg(config.TLSInternal, otherTrust)); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("a probe pinned to another certificate = %v, want a verification failure", err)
	}
	if err := healthProbe(cfg(config.TLSInternal, filepath.Join(dir, "missing.crt"))); err == nil {
		t.Fatal("a probe without the served certificate succeeded")
	}
}
