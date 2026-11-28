// SPDX-License-Identifier: BUSL-1.1

package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"

	"trstctl.com/trstctl/internal/crypto/trust"
)

// HTTPTransport returns an http.Transport that trusts the CA certificate(s) in
// caPEM and nothing else. It lives in the crypto boundary so callers (for
// example the Kubernetes API client, which must trust the cluster CA) can build
// a trusting HTTP client without importing crypto/* themselves (AN-3).
func HTTPTransport(caPEM []byte) (*http.Transport, error) {
	return HTTPTransportForServerName(caPEM, "")
}

// ControlPlaneHTTPTransport accepts an operator's API certificate while
// requiring the control-plane role SAN for a leaf under the shared agent CA.
// A mixed bundle keeps each certificate in its assigned trust role.
func ControlPlaneHTTPTransport(caPEM []byte) (*http.Transport, error) {
	transport, err := HTTPTransport(caPEM)
	if err != nil {
		return nil, err
	}
	requireControlPlaneAgentRole(transport.TLSClientConfig)
	return transport, nil
}

// DirectoryHTTPTransport exposes the verified directory TLS configuration as
// a transport solely so netsec can adopt it onto an SSRF-scoped HTTP dialer.
func DirectoryHTTPTransport() *http.Transport {
	return &http.Transport{TLSClientConfig: DirectoryClientTLSConfig(false)}
}

// HTTPTransportForServerName is HTTPTransport with an explicit certificate
// identity override. This is needed when an operator reaches a private HTTPS
// service by IP or an internal alias while its certificate names a stable DNS
// identity. The override changes verification only; dialing still uses the URL
// host and remains subject to the caller's SSRF policy.
func HTTPTransportForServerName(caPEM []byte, serverName string) (*http.Transport, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("mtls: no CA certificates found in PEM")
	}
	return trust.HardenTransport(&http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		},
	}), nil
}

// MutualTLSHTTPTransportFromFiles returns an HTTP transport that presents the
// client certificate in certFile/keyFile and trusts only the CA certificate(s)
// in serverCAFile, for operator-configured HTTPS APIs that authenticate their
// caller by certificate (an EJBCA REST API, for example). TLS 1.3 is the floor
// unless an option lowers it; serverName, when set, overrides the identity the
// server certificate is verified against. HTTP/1.1 only: no HTTP/2 ALPN.
func MutualTLSHTTPTransportFromFiles(certFile, keyFile, serverCAFile, serverName string, opts ...RawClientOption) (*http.Transport, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: load client certificate: %w", err)
	}
	serverCAs, err := loadCAPool(serverCAFile)
	if err != nil {
		return nil, err
	}
	cfg := clientTLSConfig(StaticSource(cert), serverCAs, serverName, nil)
	cfg.NextProtos = nil
	for _, opt := range opts {
		opt(cfg)
	}
	return &http.Transport{TLSClientConfig: cfg}, nil
}

// HTTPTransportWithSystemRootsAndCA keeps the host's normal HTTPS trust and
// adds an operator-supplied private CA for appliance APIs. A relay must never
// disable certificate or hostname verification to reach an internal endpoint.
// The transport carries no agent client certificate.
func HTTPTransportWithSystemRootsAndCA(caPEM []byte) (*http.Transport, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("mtls: no CA certificates found in relay PEM")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return trust.HardenTransport(transport), nil
}

// AgentHTTPTransport returns an HTTP transport for the agent-facing HTTPS renewal
// listener. It verifies the server against serverCAPEM/serverName, pins TLS 1.3, and
// presents the current agent client certificate from src when one is supplied.
func AgentHTTPTransport(src ClientCertSource, serverCAPEM []byte, serverName string, pin *Pin) (*http.Transport, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(serverCAPEM) {
		return nil, errors.New("mtls: no CA certificates found in PEM")
	}
	config := clientTLSConfig(src, pool, serverName, pin)
	requireControlPlaneAgentRole(config)
	return &http.Transport{TLSClientConfig: config}, nil
}

func requireControlPlaneAgentRole(config *tls.Config) {
	prior := config.VerifyConnection
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if prior != nil {
			if err := prior(state); err != nil {
				return err
			}
		}
		if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
			return errors.New("mtls: control-plane HTTPS peer has no verified certificate chain")
		}
		for _, chain := range state.VerifiedChains {
			if len(chain) == 0 || !chain[len(chain)-1].IsCA ||
				chain[len(chain)-1].Subject.CommonName != AgentCACommonName {
				continue
			}
			for _, uri := range state.PeerCertificates[0].URIs {
				if uri.String() == AgentControlPlaneServerURI {
					return nil
				}
			}
			return errors.New("mtls: agent-CA HTTPS peer is not the control plane")
		}
		return nil
	}
}
