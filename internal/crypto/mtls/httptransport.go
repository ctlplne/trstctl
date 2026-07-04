package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
)

// HTTPTransport returns an http.Transport that trusts the CA certificate(s) in
// caPEM and nothing else. It lives in the crypto boundary so callers (for
// example the Kubernetes API client, which must trust the cluster CA) can build
// a trusting HTTP client without importing crypto/* themselves (AN-3).
func HTTPTransport(caPEM []byte) (*http.Transport, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("mtls: no CA certificates found in PEM")
	}
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		},
	}, nil
}

// AgentHTTPTransport returns an HTTP transport for the agent-facing HTTPS renewal
// listener. It verifies the server against serverCAPEM/serverName, pins TLS 1.3, and
// presents the current agent client certificate from src when one is supplied.
func AgentHTTPTransport(src ClientCertSource, serverCAPEM []byte, serverName string, pin *Pin) (*http.Transport, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(serverCAPEM) {
		return nil, errors.New("mtls: no CA certificates found in PEM")
	}
	return &http.Transport{
		TLSClientConfig: clientTLSConfig(src, pool, serverName, pin),
	}, nil
}
