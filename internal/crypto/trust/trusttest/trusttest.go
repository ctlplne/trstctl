// SPDX-License-Identifier: BUSL-1.1

// Package trusttest gives packages outside the crypto boundary (netsec, the
// egress guard, their tests) a throwaway HTTPS server whose chain they can
// distrust, without naming crypto/x509 or crypto/tls themselves (AN-3).
package trusttest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/certtest"
	"trstctl.com/trstctl/internal/crypto/trust"
)

// Server is a loopback HTTPS server under a private root with one intermediate.
type Server struct {
	URL      string
	RootsPEM []byte
	// IntermediateList is a distrust list (shipped file shape) naming the
	// intermediate's key: installing it must make every handshake fail.
	IntermediateList []byte
	// RootList names the root by key and certificate.
	RootList []byte
}

// PostgresPasswordPeer is a fake PostgreSQL server. It asks for cleartext
// authentication after TLS or a plaintext fallback and reports which transport
// carried a PasswordMessage.
// The message body is deliberately discarded, never copied into test output.
type PostgresPasswordPeer struct {
	Addr              string
	RootsPEM          []byte
	DistrustList      []byte
	PasswordTransport <-chan string
}

// attempts is the maximum number of connections to observe. Two attempts
// exercise pgx's sslmode=prefer TLS-then-plaintext fallback.
func NewPostgresPasswordPeer(t *testing.T, attempts int) *PostgresPasswordPeer {
	t.Helper()
	if attempts < 1 || attempts > 2 {
		t.Fatal("trusttest: PostgreSQL peer needs one or two attempts")
	}
	caPEM, certPEM, keyPEM, err := certtest.PrivateCAServer("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		t.Fatal("trusttest: missing PostgreSQL fixture CA")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	seen := make(chan string, 1)
	go func() {
		var transport string
		defer func() { seen <- transport }()
		for i := 0; i < attempts; i++ {
			_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if got := postgresPasswordAttempt(conn, pair); got != "" {
				transport = got
			}
		}
	}()
	return &PostgresPasswordPeer{Addr: listener.Addr().String(), RootsPEM: caPEM,
		DistrustList: list(t, "operator-distrusted PostgreSQL root", trust.KindRoot, root, true), PasswordTransport: seen}
}

func postgresPasswordAttempt(conn net.Conn, pair tls.Certificate) string {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	first := make([]byte, 8)
	if _, err := io.ReadFull(conn, first); err != nil {
		return ""
	}
	wire := conn
	var alreadyRead int
	transport := "plaintext"
	if bytes.Equal(first, []byte{0, 0, 0, 8, 4, 210, 22, 47}) {
		if _, err := conn.Write([]byte{'S'}); err != nil {
			return ""
		}
		secure := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
		if err := secure.Handshake(); err != nil {
			return ""
		}
		wire = secure
		transport = "tls"
	} else {
		alreadyRead = 8 // plaintext startup packet on pgx fallback
	}
	length := make([]byte, 4)
	if alreadyRead == 0 {
		if _, err := io.ReadFull(wire, length); err != nil {
			return ""
		}
		alreadyRead = 4
	} else {
		copy(length, first[:4])
	}
	n := int(length[0])<<24 | int(length[1])<<16 | int(length[2])<<8 | int(length[3])
	if n < 8 || n > 8192 {
		return ""
	}
	if _, err := io.CopyN(io.Discard, wire, int64(n-alreadyRead)); err != nil {
		return ""
	}
	if _, err := wire.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}); err != nil {
		return ""
	}
	kind := make([]byte, 1)
	_, err := io.ReadFull(wire, kind)
	if err == nil && kind[0] == 'p' {
		return transport
	}
	return ""
}

func key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func list(t *testing.T, name, kind string, c *x509.Certificate, withCert bool) []byte {
	t.Helper()
	e := map[string]any{"name": name, "kind": kind, "spki_sha256": trust.SPKISHA256(c), "reason": "test incident", "sources": []string{"trusttest"}, "since": "2026-10-23"}
	if withCert {
		e["cert_sha256"] = trust.CertSHA256(c)
	}
	body, err := json.Marshal(map[string]any{"schema": 1, "updated": "2026-10-23", "entries": []any{e}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// New starts the server and stops it when the test ends.
func New(t *testing.T) *Server {
	t.Helper()
	now := time.Now()
	rootKey, interKey, leafKey := key(t), key(t), key(t)
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "trusttest root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	interTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "trusttest intermediate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	inter, _ := x509.ParseCertificate(interDER)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, inter, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, interDER}, PrivateKey: leafKey}}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &Server{
		URL:              srv.URL,
		RootsPEM:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
		IntermediateList: list(t, "trusttest intermediate key", trust.KindIntermediate, inter, false),
		RootList:         list(t, "trusttest root", trust.KindRoot, root, true),
	}
}

// NewFallbackRootTLSListener creates a disposable TLS listener whose root is
// trusted through Go's process-local fallback roots and simultaneously placed
// on the operator distrust list. Call only in an isolated test process: Go's
// fallback roots can be set once and affect all TLS clients in that process.
// The listener speaks no application protocol; the caller observes what a
// client sends after its handshake.
func NewFallbackRootTLSListener(t *testing.T) net.Listener {
	t.Helper()
	t.Setenv("GODEBUG", "x509usefallbackroots=1")
	caPEM, certPEM, keyPEM, err := certtest.PrivateCAServer("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		t.Fatal("trusttest: fixture CA PEM has no certificate")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	x509.SetFallbackRoots(roots)
	leafBlock, _ := pem.Decode(certPEM)
	if leafBlock == nil {
		t.Fatal("trusttest: fixture leaf PEM has no certificate")
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "127.0.0.1"}); err != nil {
		t.Fatalf("trusttest: test CA is not a fallback system root: %v", err)
	}
	Install(t, list(t, "operator-distrusted test root", trust.KindRoot, root, true))
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

// TrustRoots makes transport verify servers against pemRoots (in place).
func TrustRoots(t *testing.T, transport *http.Transport, pemRoots []byte) {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemRoots) {
		t.Fatal("trusttest: no roots in PEM")
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	transport.TLSClientConfig.RootCAs = pool
}

// Install sets the operator distrust list for the rest of the test.
func Install(t *testing.T, listJSON []byte) {
	t.Helper()
	l, err := trust.Parse(listJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.SetOperator(l); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = trust.SetOperator(nil) })
}
