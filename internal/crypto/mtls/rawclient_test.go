// SPDX-License-Identifier: BUSL-1.1

package mtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMutualTLSClientConnFromFilesRawTLS13NoALPN(t *testing.T) {
	files := writeMutualTLSFiles(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	tlsListener, err := MutualTLSServerListenerFromFiles(ln, files.serverCert, files.serverKey, files.ca)
	if err != nil {
		t.Fatalf("MutualTLSServerListenerFromFiles: %v", err)
	}

	serverErr := make(chan error, 1)
	go func() {
		conn, acceptErr := tlsListener.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer func() { _ = conn.Close() }()
		if _, peerErr := PeerCertificateDER(conn); peerErr != nil {
			serverErr <- peerErr
			return
		}
		_, writeErr := conn.Write([]byte("kmip"))
		serverErr <- writeErr
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := MutualTLSClientConnFromFiles(
		ctx, raw, files.clientCert, files.clientKey, files.ca, "kmip.test",
	)
	if err != nil {
		t.Fatalf("MutualTLSClientConnFromFiles: %v", err)
	}
	defer func() { _ = conn.Close() }()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		t.Fatalf("connection type = %T, want *tls.Conn", conn)
	}
	state := tlsConn.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		t.Fatalf("TLS version = 0x%04x, want TLS 1.3", state.Version)
	}
	if state.NegotiatedProtocol != "" {
		t.Fatalf("negotiated ALPN = %q, want empty for raw KMIP", state.NegotiatedProtocol)
	}
	if len(state.VerifiedChains) == 0 {
		t.Fatal("server certificate did not produce a verified chain")
	}
	payload, err := io.ReadAll(io.LimitReader(conn, 4))
	if err != nil {
		t.Fatalf("read raw payload: %v", err)
	}
	if string(payload) != "kmip" {
		t.Fatalf("payload = %q, want kmip", payload)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}

// A124: a KMIP server capped at TLS 1.2 is refused by default and reached
// with an AEAD suite once the operator opts that server down to TLS 1.2.
func TestMutualTLSClientConnFromFilesReachesATLS12ServerOnlyWhenAllowed(t *testing.T) {
	files := writeMutualTLSFiles(t)
	serverCert, err := tls.LoadX509KeyPair(files.serverCert, files.serverKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCAs, err := loadCAPool(files.ca)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert}, // #nosec G402 -- the test server models a KMIP server whose TLS stops at 1.2 (CWE-327)
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}()
		}
	}()
	dial := func(opts ...RawClientOption) (net.Conn, error) {
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return MutualTLSClientConnFromFiles(ctx, raw, files.clientCert, files.clientKey, files.ca, "kmip.test", opts...)
	}
	if conn, err := dial(); err == nil {
		_ = conn.Close()
		t.Fatal("the default TLS 1.3 floor reached a TLS 1.2-only server")
	}
	conn, err := dial(AllowTLS12())
	if err != nil {
		t.Fatalf("an opted-down client could not reach a TLS 1.2 server: %v", err)
	}
	defer func() { _ = conn.Close() }()
	state := conn.(*tls.Conn).ConnectionState()
	aead := false
	for _, id := range tls12AEADSuites() {
		aead = aead || state.CipherSuite == id
	}
	if state.Version != tls.VersionTLS12 || !aead {
		t.Fatalf("negotiated version %x suite %x, want TLS 1.2 with an AEAD suite", state.Version, state.CipherSuite)
	}
}

func TestMutualTLSClientConnFromFilesRejectsWrongServerName(t *testing.T) {
	files := writeMutualTLSFiles(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	tlsListener, err := MutualTLSServerListenerFromFiles(ln, files.serverCert, files.serverKey, files.ca)
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := tlsListener.Accept()
		if acceptErr == nil {
			defer func() { _ = conn.Close() }()
			_, _ = PeerCertificateDER(conn)
		}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = MutualTLSClientConnFromFiles(
		ctx, raw, files.clientCert, files.clientKey, files.ca, "wrong.test",
	)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("wrong server name error = %v, want certificate verification failure", err)
	}
	select {
	case <-serverDone:
	case <-time.After(3 * time.Second):
		t.Fatal("server handshake did not finish")
	}
}

func TestMutualTLSClientConnFromFilesClosesRawOnConfigurationError(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	_, err := MutualTLSClientConnFromFiles(context.Background(), client, "missing", "missing", "missing", "")
	if err == nil || !strings.Contains(err.Error(), "server name is required") {
		t.Fatalf("error = %v, want required server name", err)
	}
	if _, err := client.Write([]byte("x")); err == nil {
		t.Fatal("raw connection remained writable after configuration failure")
	}
}

type mutualTLSFiles struct {
	ca         string
	serverCert string
	serverKey  string
	clientCert string
	clientKey  string
}

func writeMutualTLSFiles(t *testing.T) mutualTLSFiles {
	t.Helper()
	ca, err := NewCA("raw-mtls-test-ca")
	if err != nil {
		t.Fatal(err)
	}
	server, err := ca.IssueServerCertificate([]string{"kmip.test"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	client, err := ca.IssueClientCertificate("kmip-client", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	files := mutualTLSFiles{
		ca:         filepath.Join(dir, "ca.pem"),
		serverCert: filepath.Join(dir, "server.pem"),
		serverKey:  filepath.Join(dir, "server-key.pem"),
		clientCert: filepath.Join(dir, "client.pem"),
		clientKey:  filepath.Join(dir, "client-key.pem"),
	}
	writeFile(t, files.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.der}))
	writeTLSCertificateFiles(t, server, files.serverCert, files.serverKey)
	writeTLSCertificateFiles(t, client, files.clientCert, files.clientKey)
	return files
}

func writeTLSCertificateFiles(t *testing.T, cert tls.Certificate, certFile, keyFile string) {
	t.Helper()
	var certPEM []byte
	for _, der := range cert.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	key, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("private key type = %T, want ECDSA", cert.PrivateKey)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, certFile, certPEM)
	writeFile(t, keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

func writeFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}
