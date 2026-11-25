// SPDX-License-Identifier: BUSL-1.1

package mysqlsignin

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/certtest"
)

// The first upstream packet after MySQL's greeting must be an SSLRequest.
// A server without TLS must receive no user name or password-derived proof.
func TestCR039MySQLRefusesUnauthenticatedUpstreamBeforeCredentialProof(t *testing.T) {
	server := serverHandshake()
	server.Capabilities &^= ClientSSL
	conn := &observedMySQLConn{}
	target := &Target{Address: "db.example.test:3306", User: "fixture-user", Password: []byte("fixture-password")}
	client := &ClientResponse{Capabilities: required, Charset: 45}
	_, _, err := SignIn(conn, server, target, client, Options{})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "tls") || len(conn.writes) != 0 {
		t.Fatalf("insecure server received credential proof: writes=%d err=%v", len(conn.writes), err)
	}
}

type observedMySQLConn struct {
	net.Conn
	writes [][]byte
}

func (c *observedMySQLConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (*observedMySQLConn) Read([]byte) (int, error) { return 0, io.EOF }

type recordedMySQLWire struct {
	net.Conn
	writes [][]byte
}

func (c *recordedMySQLWire) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return c.Conn.Write(p)
}

func TestCR039MySQLFullAuthenticationStaysInsideVerifiedTLS(t *testing.T) {
	caPEM, certPEM, keyPEM, err := certtest.PrivateCAServer("db.private.test")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	clientRaw, serverRaw := net.Pipe()
	t.Cleanup(func() { _ = clientRaw.Close(); _ = serverRaw.Close() })
	deadline := time.Now().Add(5 * time.Second)
	_ = clientRaw.SetDeadline(deadline)
	_ = serverRaw.SetDeadline(deadline)
	wire := &recordedMySQLWire{Conn: clientRaw}
	password := []byte("fixture-password-on-tls-only")
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- func() error {
			_, request, err := ReadPacket(serverRaw)
			if err != nil {
				return err
			}
			if len(request) != 32 || binary.LittleEndian.Uint32(request[:4])&ClientSSL == 0 {
				return fmt.Errorf("first upstream packet was not an SSLRequest: length=%d", len(request))
			}
			secure := tls.Server(serverRaw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			if err := secure.Handshake(); err != nil {
				return err
			}
			seq, auth, err := ReadPacket(secure)
			if err != nil || seq != 2 || !bytes.Contains(auth, []byte("fixture-user")) {
				return fmt.Errorf("TLS auth response seq=%d user_present=%t err=%v", seq, bytes.Contains(auth, []byte("fixture-user")), err)
			}
			if err := WritePacket(secure, 3, []byte{0x01, 0x04}); err != nil {
				return err
			}
			seq, full, err := ReadPacket(secure)
			if err != nil || seq != 4 || !bytes.Equal(full, append(append([]byte(nil), password...), 0)) {
				return fmt.Errorf("full auth did not complete inside TLS: seq=%d err=%v", seq, err)
			}
			return WritePacket(secure, 5, []byte{0x00, 0x00, 0x00})
		}()
	}()
	target := &Target{Address: "db.private.test:3306", User: "fixture-user", Password: password, Database: "orders"}
	client := &ClientResponse{Capabilities: required, Charset: 45}
	upstream, ok, err := SignIn(wire, serverHandshake(), target, client, Options{RootCAPEM: caPEM, ServerName: "db.private.test"})
	if err != nil {
		t.Fatalf("verified TLS sign-in: %v", err)
	}
	if _, isTLS := upstream.(*tls.Conn); !isTLS || len(ok) == 0 || ok[0] != 0 {
		t.Fatalf("sign-in returned upstream=%T ok=%x", upstream, ok)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bytes.Join(wire.writes, nil), password) {
		t.Fatal("upstream wire exposed the session password outside TLS")
	}
}

func TestCR039MySQLRejectsWrongCertificateNameBeforeAuthentication(t *testing.T) {
	caPEM, certPEM, keyPEM, err := certtest.PrivateCAServer("db.private.test")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	deadline := time.Now().Add(5 * time.Second)
	authSeen := make(chan bool, 1)
	go func() {
		serverRaw, acceptErr := listener.Accept()
		if acceptErr != nil {
			authSeen <- false
			return
		}
		defer func() { _ = serverRaw.Close() }()
		_ = serverRaw.SetDeadline(deadline)
		_, request, err := ReadPacket(serverRaw)
		if err != nil || len(request) != 32 || binary.LittleEndian.Uint32(request[:4])&ClientSSL == 0 {
			authSeen <- true
			return
		}
		secure := tls.Server(serverRaw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		if secure.Handshake() != nil {
			authSeen <- false
			return
		}
		_, _, err = ReadPacket(secure)
		authSeen <- err == nil
	}()
	clientRaw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientRaw.Close() })
	_ = clientRaw.SetDeadline(deadline)
	target := &Target{Address: "db.private.test:3306", User: "fixture-user", Password: []byte("fixture-password")}
	_, _, err = SignIn(clientRaw, serverHandshake(), target, &ClientResponse{Capabilities: required, Charset: 45},
		Options{RootCAPEM: caPEM, ServerName: "wrong.private.test"})
	_ = clientRaw.Close() // release the fake server's TLS handshake after rejection
	var nameError x509.HostnameError
	if !errors.As(err, &nameError) || <-authSeen {
		t.Fatalf("wrong certificate name reached credential exchange: err=%v", err)
	}
}
