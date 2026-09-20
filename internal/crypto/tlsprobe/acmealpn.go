// SPDX-License-Identifier: BUSL-1.1

package tlsprobe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"time"
)

// ACMETLSALPNProto is the ALPN protocol a TLS-ALPN-01 validator negotiates
// (RFC 8737 §3).
const ACMETLSALPNProto = "acme-tls/1"

// idPeACMEIdentifier is the OID of the acmeIdentifier certificate extension
// (id-pe-acmeIdentifier, RFC 8737 §3): 1.3.6.1.5.5.7.1.31.
var idPeACMEIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

// acmeIdentifierFromCert returns the 32-byte digest carried in the cert's
// id-pe-acmeIdentifier extension, or nil if the extension is absent or malformed.
func acmeIdentifierFromCert(cert *x509.Certificate) []byte {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(idPeACMEIdentifier) {
			continue
		}
		var digest []byte
		if rest, err := asn1.Unmarshal(ext.Value, &digest); err != nil || len(rest) != 0 {
			return nil
		}
		return digest
	}
	return nil
}

// NewACMEALPNTestServer starts a TLS-ALPN-01 responder on a loopback port: on an
// "acme-tls/1" handshake it presents a self-signed certificate carrying the
// id-pe-acmeIdentifier extension set to digest (RFC 8737). It exists so the
// ACME TLS-ALPN-01 validator can be tested end-to-end against a real handshake
// without callers importing crypto/* (AN-3). The returned close function stops it.
func NewACMEALPNTestServer(digest []byte) (addr string, closeFn func(), err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", nil, err
	}
	extVal, err := asn1.Marshal(digest)
	if err != nil {
		return "", nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "acme-tls-alpn-01"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"acme.invalid"},
		ExtraExtensions: []pkix.Extension{
			{Id: idPeACMEIdentifier, Critical: true, Value: extVal},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", nil, err
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{ACMETLSALPNProto}}
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
	return ln.Addr().String(), func() { _ = ln.Close() }, nil
}
