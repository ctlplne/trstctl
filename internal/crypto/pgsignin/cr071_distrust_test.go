// SPDX-License-Identifier: BUSL-1.1

package pgsignin

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

func TestCR071PostgresSignInNeverSendsPasswordThroughDistrustedCA(t *testing.T) {
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
		Name: "CR-071 PostgreSQL CA", Kind: trust.KindRoot, SPKISHA256: trust.SPKISHA256(root),
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
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	password := make(chan []byte, 1)
	addr := fakePostgres(t, 3, 'S', password, serverTLS)
	host, port, _ := net.SplitHostPort(addr)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	session, err := SignIn(ctx, []byte("host="+host+" port="+port+" user=u password=p dbname=d sslmode=verify-full"),
		Options{RootCAPEM: caPEM, ServerName: "db.private.test"})
	if session != nil && session.Conn != nil {
		_ = session.Conn.Close()
	}
	var distrusted *trust.DistrustError
	if !errors.As(err, &distrusted) {
		t.Fatalf("PostgreSQL accepted an operator-distrusted CA and reached password auth: %v", err)
	}
	select {
	case <-password:
		t.Fatal("PostgreSQL sent a password after distrust")
	default:
	}
}
