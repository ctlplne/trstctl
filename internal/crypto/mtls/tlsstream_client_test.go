// SPDX-License-Identifier: BUSL-1.1

package mtls_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/mtls"
)

type p5l2Issuer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newP5L2Issuer(t *testing.T, name string) p5l2Issuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return p5l2Issuer{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// leaf returns a certificate and key PEM for name with the given usage.
func (ca p5l2Issuer) leaf(t *testing.T, name string, usage x509.ExtKeyUsage) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// P5-L2: a receiver that requires mutual TLS verifies the client certificate
// the dial presents. Over TLS 1.3 the client finishes its handshake before the
// receiver checks it, so the dial waits for the receiver's verdict: a client
// with no certificate, or one another CA issued, is refused at the dial, not
// counted as a session that went through.
func TestDialPresentsTheClientCertificateAndSeesARefusalP5L2(t *testing.T) {
	ca, other := newP5L2Issuer(t, "P5-L2 receiver CA"), newP5L2Issuer(t, "P5-L2 other CA")
	serverCert, serverKey := ca.leaf(t, "localhost", x509.ExtKeyUsageServerAuth)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if err := os.WriteFile(certFile, serverCert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, serverKey, 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := mtls.ServerCertFromFiles(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := server.ListenerRequiringClientCert(raw, ca.pem)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if _, err := server.ListenerRequiringClientCert(raw, []byte("not a CA")); err == nil {
		t.Fatal("a listener with no client CA was built")
	}
	var mu sync.Mutex
	var verified []string
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				if name, err := mtls.VerifiedClientCommonName(conn); err == nil {
					mu.Lock()
					verified = append(verified, name)
					mu.Unlock()
					_, _ = conn.Read(make([]byte, 64))
				}
			}()
		}
	}()
	addr := raw.Addr().String()
	dial := func(bundle []byte) error {
		conn, err := mtls.DialVerifiedTCPWithClientCert(context.Background(), addr, "localhost", ca.pem, bundle, nil)
		if err == nil {
			_, err = conn.Write([]byte("x"))
			_ = conn.Close()
		}
		return err
	}

	clientCert, clientKey := ca.leaf(t, "feed-client.p5l2.test", x509.ExtKeyUsageClientAuth)
	if err := dial(append(append([]byte(nil), clientCert...), clientKey...)); err != nil {
		t.Fatalf("the receiver's own CA's client certificate was refused: %v", err)
	}
	if err := dial(nil); err == nil || !strings.Contains(err.Error(), "refused the session") {
		t.Fatalf("no client certificate: %v, want the receiver's refusal", err)
	}
	otherCert, otherKey := other.leaf(t, "feed-client.p5l2.test", x509.ExtKeyUsageClientAuth)
	if err := dial(append(append([]byte(nil), otherCert...), otherKey...)); err == nil || !strings.Contains(err.Error(), "refused the session") {
		t.Fatalf("another CA's client certificate: %v, want the receiver's refusal", err)
	}
	if err := dial(clientCert); err == nil || !strings.Contains(err.Error(), "client certificate bundle") {
		t.Fatalf("a bundle with no key: %v", err)
	}
	// The receiver records the verified client on its own goroutine.
	for deadline := time.Now().Add(2 * time.Second); ; {
		mu.Lock()
		got := append([]string(nil), verified...)
		mu.Unlock()
		if len(got) == 1 && got[0] == "feed-client.p5l2.test" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the receiver verified %v, want the one feed client", got)
		}
		runtime.Gosched()
	}
}
