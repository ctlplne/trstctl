// SPDX-License-Identifier: BUSL-1.1

package mtls_test

import (
	"context"
	"encoding/pem"
	"net"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/mtls"
)

func TestDialVerifiedTCPPinsCAAndServerIdentity(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	addr := strings.TrimPrefix(server.URL, "https://")
	conn, err := mtls.DialVerifiedTCP(context.Background(), addr, "example.com", ca)
	if err != nil {
		t.Fatalf("correct pinned CA/name rejected: %v", err)
	}
	_ = conn.Close()
	if conn, err := mtls.DialVerifiedTCP(context.Background(), addr, "wrong.example", ca); err == nil {
		_ = conn.Close()
		t.Fatal("wrong Redis server identity accepted")
	}
	if conn, err := mtls.DialVerifiedTCP(context.Background(), addr, "example.com", nil); err == nil {
		_ = conn.Close()
		t.Fatal("private Redis CA accepted from system roots")
	}
	if conn, err := mtls.DialVerifiedTCP(context.Background(), addr, "example.com", []byte("not a CA")); err == nil {
		_ = conn.Close()
		t.Fatal("invalid Redis CA accepted")
	}
}

func TestVerifiedClientConnectionRejectsWrongPeerBeforeApplicationBytes(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	address := strings.TrimPrefix(server.URL, "https://")
	for _, tc := range []struct {
		name    string
		ca      []byte
		allowed bool
	}{{"example.com", ca, true}, {"wrong.example", ca, false}, {"example.com", nil, false}, {"example.com", []byte("not a CA"), false}, {"", ca, false}} {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		secured, err := mtls.VerifyClientConnection(context.Background(), conn, tc.name, tc.ca)
		if secured != nil {
			_ = secured.Close()
		}
		if (err == nil) != tc.allowed {
			t.Fatalf("TLS identity %q accepted=%v, want %v", tc.name, err == nil, tc.allowed)
		}
	}
}
