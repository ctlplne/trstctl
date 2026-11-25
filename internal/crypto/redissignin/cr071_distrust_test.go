// SPDX-License-Identifier: BUSL-1.1

package redissignin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/certtest"
	"trstctl.com/trstctl/internal/crypto/trust"
)

func TestCR071RedisSignInNeverSendsAUTHThroughDistrustedCA(t *testing.T) {
	caPEM, certPEM, keyPEM, err := certtest.PrivateCAServer("cache.private.test")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		t.Fatal("fixture CA PEM has no certificate")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"schema": 1, "updated": "2026-11-26", "entries": []trust.Entry{{
		Name: "CR-071 Redis CA", Kind: trust.KindRoot, SPKISHA256: trust.SPKISHA256(root),
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
	addr, seen := fakeRedis(t, "u", "fixture-password", false, serverTLS)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, err := SignIn(ctx, []byte("rediss://u:fixture-password@"+addr+"/0"),
		Options{RootCAPEM: caPEM, ServerName: "cache.private.test"})
	if conn != nil {
		_ = conn.Close()
	}
	var distrusted *trust.DistrustError
	if !errors.As(err, &distrusted) {
		t.Fatalf("Redis accepted an operator-distrusted CA and reached AUTH: %v", err)
	}
	select {
	case command := <-seen:
		t.Fatalf("Redis sent a credential command after distrust: %q", command[0])
	default:
	}
}
