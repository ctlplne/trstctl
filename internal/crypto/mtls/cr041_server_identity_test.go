// SPDX-License-Identifier: BUSL-1.1

package mtls

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	boundary "trstctl.com/trstctl/internal/crypto"
)

func TestCR041AgentRejectsGatewayCertificateForControlPlaneName(t *testing.T) {
	const host = "agent.trstctl.local"
	const controlPlaneURI = "spiffe://trstctl/system/agent-channel"
	key, caDER, caPEM := renewingTestAuthority(t)
	for _, tc := range []struct {
		name string
		uri  string
		want bool
	}{
		{"control plane", controlPlaneURI, true},
		{"tenant gateway", AgentSPIFFEID("tenant-a", "gateway-a"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, err := NewRenewingServerCertificate(caPEM, []string{host}, func(csr []byte) ([]byte, error) {
				return boundary.SignServerCertFromCSRWithURIs(caDER, key, csr, []string{host}, []string{tc.uri}, time.Hour)
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(cert.Close)
			listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
				MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, Certificates: []tls.Certificate{*cert.current.Load()},
			})
			if err != nil {
				t.Fatal(err)
			}
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				conn, acceptErr := listener.Accept()
				if acceptErr == nil {
					_ = conn.(*tls.Conn).Handshake()
					_ = conn.Close()
				}
			}()
			t.Cleanup(func() { _ = listener.Close(); <-serverDone })
			creds, err := AgentClientCredentials(nil, caPEM, host, nil)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = raw.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, _, err := creds.ClientHandshake(ctx, host, raw)
			if tc.want {
				if err != nil {
					t.Fatalf("control-plane certificate rejected: %v", err)
				}
				_ = conn.Close()
				return
			}
			if err == nil {
				_ = conn.Close()
				t.Fatal("agent accepted a tenant gateway certificate for its control-plane name")
			}
		})
	}
}
