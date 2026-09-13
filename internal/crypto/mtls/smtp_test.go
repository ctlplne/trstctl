// SPDX-License-Identifier: MPL-2.0

package mtls_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/mtls"
)

func TestSMTPRelayTLSChecksNameAndAuthority(t *testing.T) {
	ca, err := mtls.NewCA("SMTP relay test authority")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.IssueServerCertificate([]string{"smtp.example.test"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, hostname string
		trusted, want  bool
	}{
		{"trusted exact name", "smtp.example.test", true, true},
		{"wrong name", "wrong.example.test", true, false},
		{"untrusted authority", "smtp.example.test", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				defer cancel()
				peer := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
				_ = peer.HandshakeContext(ctx)
			}()
			cfg := mtls.SMTPClientTLSConfig(test.hostname)
			// The fixture supplies its independent trust anchor; production uses
			// system roots. No insecure-verification override is enabled.
			cfg.RootCAs = x509.NewCertPool()
			if test.trusted {
				cfg.RootCAs = ca.Pool()
			}
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", listener.Addr().String(), cfg)
			if err == nil {
				_ = conn.Close()
			}
			if (err == nil) != test.want {
				t.Fatalf("relay handshake passed=%v want=%v err=%v", err == nil, test.want, err)
			}
			<-done
		})
	}
}
