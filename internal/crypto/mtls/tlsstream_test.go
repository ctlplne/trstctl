// SPDX-License-Identifier: BUSL-1.1

package mtls

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

// ServerConn upgrades a connection that already spoke plaintext (an SMTP
// greeting, then STARTTLS) to TLS 1.3 with the server certificate (P15).
func TestServerConnUpgradesAfterPlaintextP15(t *testing.T) {
	sc, err := SelfSignedServerCert([]string{"intake.p15.test"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("220 ready\r\n"))
		secured := sc.ServerConn(conn)
		defer func() { _ = secured.Close() }()
		line, err := bufio.NewReader(secured).ReadString('\n')
		if err == nil {
			_, _ = secured.Write([]byte("echo " + line))
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	greeting, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || greeting != "220 ready\r\n" {
		t.Fatalf("greeting %q %v", greeting, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(sc.TrustPEM) {
		t.Fatal("trust PEM")
	}
	client := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: "intake.p15.test", MinVersion: tls.VersionTLS12})
	defer func() { _ = client.Close() }()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if v := client.ConnectionState().Version; v != tls.VersionTLS13 {
		t.Fatalf("negotiated TLS version %x, want 1.3", v)
	}
	if _, err := client.Write([]byte("hello\r\n")); err != nil {
		t.Fatal(err)
	}
	echo, err := bufio.NewReader(client).ReadString('\n')
	if err != nil || echo != "echo hello\r\n" {
		t.Fatalf("echo %q %v", echo, err)
	}
}
