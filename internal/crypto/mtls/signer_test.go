package mtls_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/mtls"
)

// isAEAD reports whether suite is one of the TLS 1.3 AEAD cipher suites. All TLS
// 1.3 suites are AEAD by protocol; this list is the explicit allowlist used to
// assert the negotiated suite is one of them.
func isAEAD(suite uint16) bool {
	switch suite {
	case tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256:
		return true
	default:
		return false
	}
}

// loadPoolForTest builds a cert pool from a CA PEM file (test helper; this is a
// _test file, so crypto/x509 use here does not breach the AN-3 boundary).
func loadPoolForTest(t *testing.T, caFile string) *x509.CertPool {
	t.Helper()
	pem := readFileForTest(t, caFile)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatalf("no certs in %s", caFile)
	}
	return pool
}

// readFileForTest reads a file or fails the test.
func readFileForTest(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// dialTLS opens a raw TLS connection to addr presenting clientCert and trusting
// the given roots, with the supplied min/max version, and returns the negotiated
// connection state (or the handshake error). It is the low-level probe the signer
// channel tests use to assert TLS 1.3 / AEAD without going through gRPC.
func dialTLS(addr string, cfg *tls.Config, timeout time.Duration) (tls.ConnectionState, error) {
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Handshake(); err != nil {
		return tls.ConnectionState{}, err
	}
	return conn.ConnectionState(), nil
}

// serveSignerTLS binds a loopback TCP listener with the signer's mTLS server
// credentials and accepts handshakes until ctx is done. It returns the address and
// a channel reporting each accepted connection's SERVER-side handshake result
// (nil on success, the rejection error otherwise) — so a test can assert the
// signer side accepted/refused a peer regardless of when the client observes it
// (TLS 1.3 surfaces a client-cert rejection to the client only on a later read).
func serveSignerTLS(t *testing.T, ctx context.Context, cfg mtls.SignerPeerConfig) (string, <-chan error) {
	t.Helper()
	creds, err := mtls.SignerServerCredentials(cfg)
	if err != nil {
		t.Fatalf("SignerServerCredentials: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	results := make(chan error, 8)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				// ServerHandshake performs the mutual-auth + pin verification the
				// signer credential enforces; report its outcome.
				wrapped, _, herr := creds.ServerHandshake(raw)
				select {
				case results <- herr:
				default:
				}
				if herr != nil {
					_ = raw.Close()
					return
				}
				_ = wrapped.Close()
			}(c)
		}
	}()
	return ln.Addr().String(), results
}

// clientTLSConfigFor builds a raw client tls.Config from provisioned control-plane
// material: present its cert, trust the signer's CA, pin nothing here (the pin is
// the signer-side check) — used to probe the negotiated TLS version/cipher.
func clientTLSConfigFor(t *testing.T, cp mtls.SignerPeerConfig, serverName string, maxVersion uint16) *tls.Config {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(cp.CertFile, cp.KeyFile)
	if err != nil {
		t.Fatalf("load client cert: %v", err)
	}
	pool := loadPoolForTest(t, cp.PeerCAFile)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   maxVersion,
		// gRPC's server credentials enforce ALPN ("h2"); advertise it so the probe
		// reaches the mutual-auth/pin check rather than failing on ALPN.
		NextProtos: []string{"h2"},
	}
	return cfg
}

// TestSignerMTLSNegotiatesTLS13AEAD is the SIGNER-005 (c) acceptance: the signer's
// cross-node channel negotiates TLS 1.3 and an AEAD cipher with a correct mutual
// peer, and REFUSES a client capped at TLS 1.2 (no downgrade). This proves the
// transport floor the design (§5.2) requires.
func TestSignerMTLSNegotiatesTLS13AEAD(t *testing.T) {
	const serverName = "trstctl-signer.svc"
	dir := t.TempDir()
	mat, err := mtls.GenerateSignerPeerMaterial(dir, serverName, time.Hour)
	if err != nil {
		t.Fatalf("GenerateSignerPeerMaterial: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr, _ := serveSignerTLS(t, ctx, mat.Signer)

	// A correct peer capped at 1.3 negotiates 1.3 + an AEAD suite.
	state, err := dialTLS(addr, clientTLSConfigFor(t, mat.ControlPlane, serverName, tls.VersionTLS13), 5*time.Second)
	if err != nil {
		t.Fatalf("correct mutual handshake failed: %v", err)
	}
	if state.Version != tls.VersionTLS13 {
		t.Errorf("negotiated TLS version = 0x%04x, want TLS 1.3 (0x%04x)", state.Version, tls.VersionTLS13)
	}
	if !isAEAD(state.CipherSuite) {
		t.Errorf("negotiated cipher 0x%04x is not AEAD", state.CipherSuite)
	}

	// A client that will not speak above TLS 1.2 must be refused (the server pins a
	// 1.3 floor); there is no downgrade.
	if _, err := dialTLS(addr, clientTLSConfigFor(t, mat.ControlPlane, serverName, tls.VersionTLS12), 5*time.Second); err == nil {
		t.Error("a TLS 1.2-capped client was accepted; the signer channel must enforce a TLS 1.3 floor")
	}
}

// TestSignerMTLSRejectsUntrustedClientAtHandshake is the SIGNER-005 (b) acceptance
// at the raw-TLS layer: a client from a different CA (untrusted, unpinned) fails
// the signer's ServerHandshake — the mutual-auth + pin check rejects it before any
// application byte flows.
func TestSignerMTLSRejectsUntrustedClientAtHandshake(t *testing.T) {
	const serverName = "trstctl-signer.svc"
	signerDir := t.TempDir()
	good, err := mtls.GenerateSignerPeerMaterial(signerDir, serverName, time.Hour)
	if err != nil {
		t.Fatalf("GenerateSignerPeerMaterial (signer): %v", err)
	}
	attackerDir := t.TempDir()
	attacker, err := mtls.GenerateSignerPeerMaterial(attackerDir, serverName, time.Hour)
	if err != nil {
		t.Fatalf("GenerateSignerPeerMaterial (attacker): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr, results := serveSignerTLS(t, ctx, good.Signer)

	// Correct peer: the SERVER handshake succeeds.
	if _, err := dialTLS(addr, clientTLSConfigFor(t, good.ControlPlane, serverName, tls.VersionTLS13), 5*time.Second); err != nil {
		t.Fatalf("correct peer rejected by client: %v", err)
	}
	if serverErr := nextResult(t, results); serverErr != nil {
		t.Fatalf("signer rejected the correct peer: %v", serverErr)
	}

	// Attacker peer (its own CA, unpinned key) trusting the real signer: the
	// SERVER must reject the client cert. (TLS 1.3 may let the client's Dial
	// return before it learns of the rejection, so we assert on the server side.)
	rogue := clientTLSConfigFor(t, attacker.ControlPlane, serverName, tls.VersionTLS13)
	rogue.RootCAs = loadPoolForTest(t, good.ControlPlane.PeerCAFile) // trust real signer so only the client side is "wrong"
	_, _ = dialTLS(addr, rogue, 5*time.Second)
	if serverErr := nextResult(t, results); serverErr == nil {
		t.Error("the signer accepted an untrusted/unpinned client certificate at the handshake")
	}
}

// nextResult waits for the next server-side handshake outcome from serveSignerTLS.
func nextResult(t *testing.T, results <-chan error) error {
	t.Helper()
	select {
	case err := <-results:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the signer's server-side handshake result")
		return nil
	}
}

// TestParsePin validates the operator-facing pin parsing: a 64-char hex SHA-256
// round-trips, and malformed/short pins are rejected.
func TestParsePin(t *testing.T) {
	dir := t.TempDir()
	mat, err := mtls.GenerateSignerPeerMaterial(dir, "s", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mtls.ParsePin(mat.Signer.PeerPinHex); err != nil {
		t.Errorf("a generated pin should parse: %v", err)
	}
	for _, bad := range []string{"", "zz", strings.Repeat("a", 63), strings.Repeat("a", 66)} {
		if _, err := mtls.ParsePin(bad); err == nil {
			t.Errorf("ParsePin(%q) accepted an invalid pin", bad)
		}
	}
}

// TestPinPEMMatchesConfiguredPin: the pin PinPEM computes for the signer's own
// certificate equals the pin the control-plane config was given to expect — so an
// operator who runs PinPEM on the signer cert gets exactly the value to configure.
func TestPinPEMMatchesConfiguredPin(t *testing.T) {
	dir := t.TempDir()
	mat, err := mtls.GenerateSignerPeerMaterial(dir, "s", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signerCertPEM := readFileForTest(t, mat.Signer.CertFile)
	pin, err := mtls.PinPEM(signerCertPEM)
	if err != nil {
		t.Fatalf("PinPEM: %v", err)
	}
	if pin != mat.ControlPlane.PeerPinHex {
		t.Errorf("PinPEM(signer cert) = %s, but the control plane was told to pin %s", pin, mat.ControlPlane.PeerPinHex)
	}
}
