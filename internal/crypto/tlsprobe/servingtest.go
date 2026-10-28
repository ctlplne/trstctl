// SPDX-License-Identifier: BUSL-1.1

package tlsprobe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"time"
)

// A real TLS listener for verification tests (epic D2).
//
// The verification engine's whole claim is that only a handshake can tell a
// deployed certificate from a served one, so its tests must handshake something
// real — a fake that returns a certificate on request would test the comparison
// and skip the part that matters. AN-3 keeps crypto/tls inside this boundary,
// so the listener is built here and callers outside get an address, exactly as
// NewACMEALPNTestServer already does for TLS-ALPN-01.

// ServingTestServer is a loopback TLS listener presenting a known certificate.
type ServingTestServer struct {
	// Addr is host:port to dial.
	Addr string
	// LeafPEM is the certificate the listener presents, so a test can build the
	// expectation from the same bytes the server serves.
	LeafPEM []byte
	// Close stops the listener.
	Close func()
}

// NewServingTestServer starts a loopback TLS listener presenting a fresh
// self-signed certificate for the given DNS names.
//
// Two calls with identical names produce DIFFERENT certificates — a fresh key
// and serial each time — which is the property the tests need: "the same names,
// a different certificate" is precisely the shape of a renewal that never
// landed on the listener.
func NewServingTestServer(dnsNames ...string) (*ServingTestServer, error) {
	return newServingTestServer(dnsNames, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}

// NewServingTestServerWithValidity is NewServingTestServer with an explicit
// validity window, for exercising the expired and not-yet-valid classes against
// a real handshake rather than a synthesized Info.
func NewServingTestServerWithValidity(notBefore, notAfter time.Time, dnsNames ...string) (*ServingTestServer, error) {
	return newServingTestServer(dnsNames, notBefore, notAfter)
}

func newServingTestServer(dnsNames []string, notBefore, notAfter time.Time) (*ServingTestServer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	cn := "trstctl-verify-test"
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              dnsNames,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				tc := tls.Server(c, cfg)
				_ = tc.Handshake()
				_ = tc.Close()
			}(conn)
		}
	}()
	return &ServingTestServer{
		Addr:    ln.Addr().String(),
		LeafPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Close:   func() { _ = ln.Close() },
	}, nil
}

// NewServingTestServerUnder starts a loopback TLS listener presenting a fresh
// leaf issued by a fresh CA whose subject key identifier is issuerKeyID (so
// the leaf's authority key identifier names it), followed by the given chain
// certificates as served issuers. It lets tests outside the crypto boundary
// scan a listener whose leaf is "under" a real CA, such as one of the eMudhra
// intermediates, without that CA's key (Part 4).
func NewServingTestServerUnder(issuerKeyID []byte, chainDER [][]byte, dnsNames ...string) (*ServingTestServer, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "trstctl-verify-test-issuer"}, SubjectKeyId: issuerKeyID,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	cn := "trstctl-verify-test"
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn}, DNSNames: dnsNames,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	served := append([][]byte{der}, chainDER...)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: served, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				tc := tls.Server(c, cfg)
				_ = tc.Handshake()
				_ = tc.Close()
			}(conn)
		}
	}()
	return &ServingTestServer{
		Addr:    ln.Addr().String(),
		LeafPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Close:   func() { _ = ln.Close() },
	}, nil
}

// NewServingTestServerChain starts a loopback TLS listener presenting chainDER
// (leaf first) with the leaf's private key in PEM, so a test outside the
// crypto boundary can serve a certificate it issued through this package
// together with its issuer — for example a leaf that names CRL and OCSP
// endpoints, which a scan keeps to probe (A211).
func NewServingTestServerChain(chainDER [][]byte, keyPEM []byte) (*ServingTestServer, error) {
	if len(chainDER) == 0 {
		return nil, errors.New("tlsprobe: a serving chain needs a leaf")
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chainDER[0]}), keyPEM)
	if err != nil {
		return nil, err
	}
	pair.Certificate = chainDER
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				tc := tls.Server(c, cfg)
				_ = tc.Handshake()
				_ = tc.Close()
			}(conn)
		}
	}()
	return &ServingTestServer{
		Addr:    ln.Addr().String(),
		LeafPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chainDER[0]}),
		Close:   func() { _ = ln.Close() },
	}, nil
}
