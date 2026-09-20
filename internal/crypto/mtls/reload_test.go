// SPDX-License-Identifier: BUSL-1.1

package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeSelfSignedPair(t *testing.T, dir, serial string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serialInt, ok := new(big.Int).SetString(serial, 10)
	if !ok {
		t.Fatalf("bad serial %q", serial)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serialInt,
		Subject:      pkix.Name{CommonName: "tls-reload-" + serial},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "server.crt")
	keyFile = filepath.Join(dir, "server.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func fetchServedSerial(t *testing.T, addr string) string {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) // #nosec G402 -- reload probe of the test's own loopback listener; reads only the served serial, carries no data (CWE-295)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no served certificate")
	}
	return state.PeerCertificates[0].SerialNumber.String()
}

// TestTLSReloadRotatedFileCertificateServedWithoutRestart is the
// OPS-TLS-RELOAD-001 acceptance: in file mode the server must pick up a
// rotated certificate/key pair via tls.Config.GetCertificate without a
// process restart, and a broken half-rotation must keep serving the previous
// good pair rather than dropping TLS.
func TestTLSReloadRotatedFileCertificateServedWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeSelfSignedPair(t, dir, "1001")

	sc, err := ServerCertFromFiles(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	sc.SetReloadCheckInterval(10 * time.Millisecond)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })} // #nosec G112 -- loopback test listener torn down by the test (CWE-400)
	done := make(chan error, 1)
	go func() { done <- sc.ServeHTTPS(srv, ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
	})

	if got := fetchServedSerial(t, ln.Addr().String()); got != "1001" {
		t.Fatalf("initial serial = %s, want 1001", got)
	}

	// Rotate: a new pair lands at the same paths (typical cert-manager /
	// certbot deploy hook). The server must serve it without restart.
	time.Sleep(20 * time.Millisecond) // ensure a distinct mtime tick window
	writeSelfSignedPair(t, dir, "2002")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got := fetchServedSerial(t, ln.Addr().String()); got == "2002" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("rotated certificate was not served within 5s (no restart)")
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Broken half-rotation: corrupt key with a fresh mtime. The reloader must
	// keep serving the last good pair, not break the listener.
	if err := os.WriteFile(keyFile, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if got := fetchServedSerial(t, ln.Addr().String()); got != "2002" {
		t.Fatalf("after broken rotation serial = %s, want previous good 2002", got)
	}
}
