// SPDX-License-Identifier: BUSL-1.1

package tlsprobe

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A PostgreSQL-style listener: it refuses a bare ClientHello (the startup
// packet is malformed) and only upgrades to TLS after the SSLRequest exchange.
func startPostgresStyleListener(t *testing.T, offerTLS bool) string {
	t.Helper()
	upstream := httptest.NewUnstartedServer(nil)
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	tlsCfg := upstream.TLS.Clone()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var startup [8]byte
				if _, err := io.ReadFull(conn, startup[:]); err != nil {
					return
				}
				// A ClientHello starts with 0x16 0x03; the SSLRequest starts with
				// the length 8 and the request code. Anything else is a protocol error.
				if startup[3] != 8 || startup[4] != 0x04 || startup[5] != 0xd2 || startup[6] != 0x16 || startup[7] != 0x2f {
					_, _ = conn.Write([]byte("E"))
					return
				}
				if !offerTLS {
					_, _ = conn.Write([]byte("N"))
					return
				}
				if _, err := conn.Write([]byte("S")); err != nil {
					return
				}
				srv := tls.Server(conn, tlsCfg)
				if err := srv.Handshake(); err != nil {
					return
				}
				// Non-invasive probe: the client sends no application data.
				buf := make([]byte, 1)
				_, _ = srv.Read(buf)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func TestPostgresSSLRequestNegotiatesTLSWhereABareClientHelloFails(t *testing.T) {
	addr := startPostgresStyleListener(t, true)
	ctx := context.Background()

	if _, err := Probe(ctx, addr, WithTimeout(3*time.Second)); err == nil {
		t.Fatal("bare ClientHello against a PostgreSQL-style listener unexpectedly succeeded")
	}
	res, err := Probe(ctx, addr, WithTimeout(3*time.Second), WithPreHandshake(PostgresSSLRequest))
	if err != nil {
		t.Fatalf("probe with SSLRequest negotiation: %v", err)
	}
	if len(res.PeerCertificates) == 0 {
		t.Fatal("negotiated probe returned no certificate")
	}
}

func TestPostgresSSLRequestReportsAListenerThatDeclinesTLS(t *testing.T) {
	addr := startPostgresStyleListener(t, false)
	_, err := Probe(context.Background(), addr, WithTimeout(3*time.Second), WithPreHandshake(PostgresSSLRequest))
	if err == nil || !strings.Contains(err.Error(), "does not offer TLS") {
		t.Fatalf("declined TLS error = %v, want the server's refusal named", err)
	}
}
