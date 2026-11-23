// SPDX-License-Identifier: BUSL-1.1
package ldapbind

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"syscall"
	"testing"
	"time"
)

// unverifiedDirectory is an LDAPS listener with a self-signed certificate for a
// name the client never asked for: an on-path attacker, or a server the source
// author chose. It records whether the bind request carried the password.
func unverifiedDirectory(t *testing.T, password []byte) (string, <-chan bool, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "attacker.example"},
		DNSNames: []string{"attacker.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	got := make(chan bool, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			got <- false
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		request, err := readLDAPFrame(conn, 64<<10)
		if err != nil {
			got <- false
			return
		}
		got <- bytes.Contains(request, password)
		_ = writeAll(conn, []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
	}()
	return listener.Addr().String(), got, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestR1S3DirectoryBindNeverReachesAnUnverifiedPeer: Dial "never transmits a
// password before StartTLS/LDAPS succeeds"; a TLS handshake whose peer was not
// verified must not count as success for a credentialed bind.
func TestR1S3DirectoryBindNeverReachesAnUnverifiedPeer(t *testing.T) {
	control := func(string, string, syscall.RawConn) error { return nil }
	password := []byte("owned-disposable-r1s3-bind-canary")

	// Control: with verification on, the self-signed peer is refused before any bind.
	addr, got, _ := unverifiedDirectory(t, password)
	if conn, err := Dial(t.Context(), "ldaps://"+addr, "CN=Reader,DC=example", password, false, control); err == nil {
		_ = conn.Close()
		t.Fatal("verified mode bound to a self-signed directory")
	}
	assertNoUnverifiedBind(t, got)

	// The tenant-settable insecure_skip_verify path (AD CS source → relay → Dial).
	addr, got, _ = unverifiedDirectory(t, password)
	conn, err := Dial(t.Context(), "ldaps://"+addr, "CN=Reader,DC=example", password, true, control)
	if err == nil {
		_ = conn.Close()
	}
	assertNoUnverifiedBind(t, got)
}

func TestCR134PinnedDirectoryOnlyBindsWithExactCAAndName(t *testing.T) {
	control := func(string, string, syscall.RawConn) error { return nil }
	password := []byte("owned-disposable-pinned-directory-canary")
	addr, got, caPEM := unverifiedDirectory(t, password)
	conn, err := DialVerifiedDirectory(t.Context(), "ldaps://"+addr, "CN=Reader,DC=example", password, caPEM, "attacker.example", control)
	if err != nil {
		t.Fatalf("explicitly pinned directory refused: %v", err)
	}
	_ = conn.Close()
	if !<-got {
		t.Fatal("verified pinned directory never received its authorized bind")
	}
	addr, got, caPEM = unverifiedDirectory(t, password)
	if conn, err := DialVerifiedDirectory(t.Context(), "ldaps://"+addr, "CN=Reader,DC=example", password, caPEM, "other.example", control); err == nil {
		_ = conn.Close()
		t.Fatal("CA pin without expected server-name match was accepted")
	}
	assertNoUnverifiedBind(t, got)
}

func assertNoUnverifiedBind(t *testing.T, got <-chan bool) {
	t.Helper()
	select {
	case sent := <-got:
		if sent {
			t.Fatal("the bind password reached a directory whose certificate was never verified")
		}
	case <-time.After(time.Second):
		// A fail-closed dial refuses insecureLab before opening a connection.
	}
}
