// SPDX-License-Identifier: BUSL-1.1

// Package trusttest gives packages outside the crypto boundary (netsec, the
// egress guard, their tests) a throwaway HTTPS server whose chain they can
// distrust, without naming crypto/x509 or crypto/tls themselves (AN-3).
package trusttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
