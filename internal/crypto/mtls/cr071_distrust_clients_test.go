// SPDX-License-Identifier: BUSL-1.1

package mtls_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/trust"
)

func TestCR071OutboundTLSClientsRefuseAnOperatorDistrustedCA(t *testing.T) {
	ca, err := mtls.NewCA("CR-071 operator trust anchor")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.IssueAgentControlPlaneServerCertificate([]string{"localhost"}, time.Hour)
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
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				_ = conn.(*tls.Conn).Handshake()
				_ = conn.Close()
			}()
		}
	}()
	if err := trust.SetOperator(nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = trust.SetOperator(nil) })
	verified, err := mtls.VerifiedClientTLSConfig("localhost", ca.BundlePEM())
	if err != nil {
		t.Fatal(err)
	}
	directory, err := mtls.DirectoryClientTLSConfigPinned(ca.BundlePEM(), "localhost")
	if err != nil {
		t.Fatal(err)
	}
	smtp := mtls.SMTPClientTLSConfig("localhost")
	smtp.RootCAs = ca.Pool()
	gateway, err := mtls.GatewayClientTLSConfig(ca.BundlePEM(), "localhost", "spiffe://trstctl/system/agent-channel")
	if err != nil {
		t.Fatal(err)
	}
	agentTransport, err := mtls.AgentHTTPTransport(nil, ca.BundlePEM(), "localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	rootedTransport, err := mtls.HTTPTransportWithSystemRootsAndCA(ca.BundlePEM())
	if err != nil {
		t.Fatal(err)
	}
	rootedTransport.TLSClientConfig.ServerName = "localhost"
	privateTransport, err := mtls.HTTPTransportForServerName(ca.BundlePEM(), "localhost")
	if err != nil {
		t.Fatal(err)
	}
	configs := map[string]*tls.Config{
		"verified TCP": verified, "directory": directory, "SMTP": smtp,
		"gateway": gateway, "agent HTTP": agentTransport.TLSClientConfig,
		"HTTP with extra CA":   rootedTransport.TLSClientConfig,
		"HTTP with private CA": privateTransport.TLSClientConfig,
	}
	dial := func(config *tls.Config) error {
		conn, dialErr := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", listener.Addr().String(), config)
		if dialErr == nil {
			_ = conn.Close()
		}
		return dialErr
	}
	for name, config := range configs {
		if err := dial(config); err != nil {
			t.Fatalf("%s refused the otherwise trusted peer: %v", name, err)
		}
	}
	block, _ := pem.Decode(ca.BundlePEM())
	if block == nil {
		t.Fatal("CA bundle has no certificate")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(map[string]any{
		"schema": 1, "updated": "2026-11-26", "entries": []trust.Entry{{
			Name: "CR-071 distrusted CA", Kind: trust.KindRoot,
			SPKISHA256: trust.SPKISHA256(root), Reason: "test incident",
			Sources: []string{"test"}, Since: "2026-11-26",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	operator, err := trust.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.SetOperator(operator); err != nil {
		t.Fatal(err)
	}
	for name, config := range configs {
		var distrust *trust.DistrustError
		if err := dial(config); !errors.As(err, &distrust) {
			t.Errorf("%s accepted the operator-distrusted CA: %v", name, err)
		}
	}
}
