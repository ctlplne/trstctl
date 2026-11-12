// SPDX-License-Identifier: BUSL-1.1

package mongosignin

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/certtest"
)

func TestParseURIReadsTheProviderCredential(t *testing.T) {
	target, err := ParseURI([]byte("mongodb://trstctl_ab12:p%40ss%3Aw0rd@db1.internal,db2.internal:27018/orders?replicaSet=rs0&tls=true&authSource=orders"))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Wipe()
	if target.User != "trstctl_ab12" || string(target.Password) != "p@ss:w0rd" || target.AuthSource != "orders" || !target.TLS ||
		len(target.Hosts) != 2 || target.Hosts[0] != "db1.internal:27017" || target.Hosts[1] != "db2.internal:27018" {
		t.Fatalf("target = %+v", target)
	}
	plain, err := ParseURI([]byte("mongodb://u:p@127.0.0.1:27017"))
	if err != nil || plain.AuthSource != "admin" || plain.TLS {
		t.Fatalf("plain = %+v %v", plain, err)
	}
	for _, bad := range []string{"mongodb+srv://u:p@h/db", "postgres://u:p@h/db", "mongodb://h/db", "mongodb://u:@h/db",
		"mongodb://u:p@h:0/db", "mongodb://u:p@h/db?authMechanism=SCRAM-SHA-1", "mongodb://u:%zz@h/db",
		"mongodb://u:p@h/db?AuthSourCe"} { // found by FuzzParseURI: an empty authSource
		if _, err := ParseURI([]byte(bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestBSONRoundTrip(t *testing.T) {
	doc := Encode([]E{{"saslStart", int32(1)}, {"payload", []byte("n,,n=u,r=x")}, {"conversationId", int64(7)},
		{"done", true}, {"ok", float64(1)}, {"errmsg", "no"}, {"options", []E{{"skipEmptyExchange", true}}}, {"list", A{{"0", "a"}}}})
	elems, err := Elements(doc)
	if err != nil || len(elems) != 8 {
		t.Fatalf("elements = %d %v", len(elems), err)
	}
	if n, ok := elems[2].Number(); !ok || n != 7 || !elems[3].Bool() {
		t.Fatalf("number/bool = %v %v", n, elems[3].Bool())
	}
	if p, ok := elems[1].Binary(); !ok || !bytes.Equal(p, []byte("n,,n=u,r=x")) {
		t.Fatalf("binary = %q", p)
	}
	if s, ok := elems[5].Text(); !ok || s != "no" {
		t.Fatalf("text = %q", s)
	}
	if e, ok := Lookup(elems[6].Value, "skipEmptyExchange"); !ok || !e.Bool() {
		t.Fatal("nested lookup failed")
	}
	if elems[7].Type != TypeArray {
		t.Fatalf("array type = %#x", elems[7].Type)
	}
	if _, err := Elements(doc[:len(doc)-1]); err == nil {
		t.Fatal("a truncated document was read")
	}
}

// TestConnectVerifiesThePrivateCATheSessionCarriesA256L1 is A256-L1: a
// tls=true target behind a private CA verifies against the CA the session
// carries, ahead of a tlsCAFile that names a path on the control plane's
// host; without it the handshake does not verify.
func TestConnectVerifiesThePrivateCATheSessionCarriesA256L1(t *testing.T) {
	caPEM, certPEM, keyPEM, err := certtest.PrivateCAServer("mongo.private.test")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
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
				_ = conn.(*tls.Conn).Handshake()
				_, _ = conn.Read(make([]byte, 1))
			}()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dial := (&net.Dialer{}).DialContext
	carried := &Target{TLS: true, TLSCAFile: "/nonexistent/on/this/host/ca.pem", rootPEM: caPEM, serverName: "mongo.private.test"}
	conn, err := connect(ctx, dial, ln.Addr().String(), carried)
	if err != nil {
		t.Fatalf("the carried CA: %v", err)
	}
	_ = conn.Close()
	if _, err := connect(ctx, dial, ln.Addr().String(), &Target{TLS: true}); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("a private CA without the carried CA = %v, want unverified", err)
	}
	if _, err := connect(ctx, dial, ln.Addr().String(), &Target{TLS: true, rootPEM: []byte("x"), serverName: "mongo.private.test"}); err == nil || !strings.Contains(err.Error(), "holds no certificate") {
		t.Fatalf("a carried CA with no certificate = %v", err)
	}
}
