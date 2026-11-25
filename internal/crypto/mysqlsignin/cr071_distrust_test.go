// SPDX-License-Identifier: BUSL-1.1

package mysqlsignin

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/certtest"
	"trstctl.com/trstctl/internal/crypto/trust"
)

func TestCR071MySQLSignInRefusesDistrustedCABeforeAuthentication(t *testing.T) {
	caPEM, certPEM, keyPEM, err := certtest.PrivateCAServer("db.private.test")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		t.Fatal("fixture CA PEM has no certificate")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"schema": 1, "updated": "2026-11-26", "entries": []trust.Entry{{
		Name: "CR-071 MySQL CA", Kind: trust.KindRoot, SPKISHA256: trust.SPKISHA256(root),
		Reason: "test incident", Sources: []string{"test"}, Since: "2026-11-26",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	list, err := trust.Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.SetOperator(list); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = trust.SetOperator(nil) })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	seen := make(chan bool, 1)
	go func() {
		serverRaw, acceptErr := listener.Accept()
		if acceptErr != nil {
			seen <- false
			return
		}
		defer func() { _ = serverRaw.Close() }()
		_ = serverRaw.SetDeadline(time.Now().Add(3 * time.Second))
		_, request, readErr := ReadPacket(serverRaw)
		if readErr != nil || len(request) != 32 || binary.LittleEndian.Uint32(request[:4])&ClientSSL == 0 {
			seen <- false
			return
		}
		secure := tls.Server(serverRaw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		if secure.Handshake() != nil {
			seen <- false
			return
		}
		_, _, readErr = ReadPacket(secure)
		seen <- readErr == nil
	}()
	clientRaw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientRaw.Close() })
	_ = clientRaw.SetDeadline(time.Now().Add(3 * time.Second))
	target := &Target{Address: "db.private.test:3306", User: "fixture-user", Password: []byte("p")}
	_, _, err = SignIn(clientRaw, serverHandshake(), target, &ClientResponse{Capabilities: required, Charset: 45},
		Options{RootCAPEM: caPEM, ServerName: "db.private.test"})
	_ = clientRaw.Close()
	var distrusted *trust.DistrustError
	if !errors.As(err, &distrusted) || <-seen {
		t.Fatalf("MySQL accepted the distrusted CA or sent its authentication packet: %v", err)
	}
}
