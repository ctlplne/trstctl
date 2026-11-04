// SPDX-License-Identifier: BUSL-1.1

package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
)

// GatewayListen opens an access gateway's TLS listener (A254) on addr,
// serving cert (renewed by its Run worker; signed by the agent CA for the
// gateway's bound host names and its agent SPIFFE ID). No client certificate
// is asked for: the session ticket inside the tunnel admits a client.
func GatewayListen(addr string, cert *RenewingServerCertificate) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	wrapped, err := GatewayWrapListener(ln, cert)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	return wrapped, nil
}

// GatewayWrapListener serves an access gateway's TLS on an open listener.
func GatewayWrapListener(ln net.Listener, cert *RenewingServerCertificate) (net.Listener, error) {
	if cert == nil {
		return nil, errors.New("mtls: gateway needs its serving certificate")
	}
	return tls.NewListener(ln, cert.GatewayTLSConfig()), nil
}

// GatewayClientTLSConfig verifies one access gateway (A254) with ordinary TLS
// verification — its serving certificate must chain to the tenant's agent CA
// for serverName — and then requires the gateway agent's exact SPIFFE ID among
// its URI SANs, so a client knows which agent it reached.
func GatewayClientTLSConfig(agentCAPEM []byte, serverName, spiffeID string) (*tls.Config, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(agentCAPEM) {
		return nil, errors.New("mtls: gateway agent CA PEM contains no certificates")
	}
	if serverName == "" || spiffeID == "" {
		return nil, errors.New("mtls: gateway host name and SPIFFE ID are required")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: serverName,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("mtls: gateway presented no certificate")
			}
			for _, uri := range cs.PeerCertificates[0].URIs {
				if uri != nil && uri.String() == spiffeID {
					return nil
				}
			}
			return fmt.Errorf("mtls: gateway certificate is not %s", spiffeID)
		},
	}, nil
}

// GatewayDial opens one TLS connection to an access gateway at addr
// (host:port), verified as GatewayClientTLSConfig describes for that host.
func GatewayDial(ctx context.Context, addr string, agentCAPEM []byte, spiffeID string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("mtls: gateway address: %w", err)
	}
	cfg, err := GatewayClientTLSConfig(agentCAPEM, host, spiffeID)
	if err != nil {
		return nil, err
	}
	d := &tls.Dialer{Config: cfg}
	return d.DialContext(ctx, "tcp", addr)
}
