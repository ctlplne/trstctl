// SPDX-License-Identifier: BUSL-1.1

package mongosignin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/certtest"
	"trstctl.com/trstctl/internal/crypto/trust"
)

func TestCR071MongoSignInRefusesDistrustedCABeforeSCRAM(t *testing.T) {
	caPEM, certPEM, keyPEM, err := certtest.PrivateCAServer("mongo.private.test")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.(*tls.Conn).Handshake()
	}()
	block, _ := pem.Decode(caPEM)
	if block == nil {
		t.Fatal("fixture CA PEM has no certificate")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"schema": 1, "updated": "2026-11-26", "entries": []trust.Entry{{
		Name: "CR-071 MongoDB CA", Kind: trust.KindRoot, SPKISHA256: trust.SPKISHA256(root),
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
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, err := connect(ctx, (&net.Dialer{}).DialContext, listener.Addr().String(), &Target{
		TLS: true, rootPEM: caPEM, serverName: "mongo.private.test",
	})
	if conn != nil {
		_ = conn.Close()
	}
	var distrusted *trust.DistrustError
	if !errors.As(err, &distrusted) {
		t.Fatalf("MongoDB accepted an operator-distrusted CA before SCRAM: %v", err)
	}
}
