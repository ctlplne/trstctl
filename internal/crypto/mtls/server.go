// SPDX-License-Identifier: MPL-2.0

package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
)

// ServerCert is a control-plane server's TLS material — its certificate and key,
// plus the PEM a client must trust to verify it. It is opaque to callers outside
// the crypto boundary, who use only ServeHTTPS and TrustPEM.
type ServerCert struct {
	cert tls.Certificate
	// reload is set for operator file-mode material: it hot-swaps a rotated
	// certificate/key pair via tls.Config.GetCertificate without a restart
	// (OPS-TLS-RELOAD-001). TrustPEM keeps the boot-time chain: file-mode
	// operators distribute trust out of band, so rotation does not mutate it.
	reload *reloadingServerCert
	// TrustPEM is the certificate a client adds to its root pool to verify this
	// server (for an internal cert, the self-signed certificate itself; for a
	// file cert, the provided chain).
	TrustPEM []byte
}

// SelfSignedServerCert generates a self-signed server (ServerAuth) certificate
// covering the given hostnames and IPs, valid for ttl. It is the control plane's
// default TLS material when no operator certificate is configured, so the server
// is never plaintext out of the box; clients trust ServerCert.TrustPEM (suitable
// for evaluation / internal deployments).
func SelfSignedServerCert(hosts []string, ttl time.Duration) (*ServerCert, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	var dnsNames []string
	var ipAddrs []net.IP
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			ipAddrs = append(ipAddrs, ip)
		} else {
			dnsNames = append(dnsNames, h)
		}
	}
	cn := "trstctl"
	if len(hosts) > 0 {
		cn = hosts[0]
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             boundarycrypto.IssuanceNotBefore(now),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
		BasicConstraintsValid: true,
	}
	// Self-signed: the certificate is its own issuer and trust anchor.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &ServerCert{
		cert:     tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf},
		TrustPEM: certPEM,
	}, nil
}

// ServerCertFromFiles loads an operator-provided server certificate chain and
// private key (PEM). It fails clearly when the files are missing or malformed,
// so a misconfiguration cannot silently fall back to plaintext.
func ServerCertFromFiles(certFile, keyFile string) (*ServerCert, error) {
	reload, err := newReloadingServerCert(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	chainPEM, err := os.ReadFile(certFile) // #nosec G304 -- operator-configured certificate/key path from deployment config (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("mtls: read server certificate: %w", err)
	}
	return &ServerCert{cert: *reload.current.Load(), reload: reload, TrustPEM: chainPEM}, nil
}

// MutualTLSServerListenerFromFiles wraps ln in a TLS 1.3 mutual-auth listener
// using operator-provided server material and a client CA. It keeps raw
// crypto/tls and crypto/x509 handling inside the AN-3 boundary while raw TCP
// protocols such as KMIP consume an ordinary net.Listener.
func MutualTLSServerListenerFromFiles(ln net.Listener, certFile, keyFile, clientCAFile string) (net.Listener, error) {
	reload, err := newReloadingServerCert(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	clientCAs, err := loadCAPool(clientCAFile)
	if err != nil {
		return nil, err
	}
	cfg := serverTLSConfig(*reload.current.Load(), clientCAs)
	cfg.Certificates = nil
	cfg.GetCertificate = reload.GetCertificate
	return tls.NewListener(ln, cfg), nil
}

// PeerCertificateDER returns the verified peer leaf certificate from a mutual-TLS
// connection. The TLS listener already performs chain validation; callers get only
// an opaque DER blob they can pass to their protocol authenticator.
func PeerCertificateDER(conn net.Conn) ([]byte, error) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("mtls: connection is %T, not TLS", conn)
	}
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("mtls: handshake: %w", err)
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil {
		return nil, fmt.Errorf("mtls: no verified peer certificate")
	}
	return append([]byte(nil), state.PeerCertificates[0].Raw...), nil
}

// CurvePreferences returns the key-agreement groups offered by MPL-core served
// TLS paths.
func CurvePreferences() []tls.CurveID {
	return []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}
}

// ServeHTTPS serves srv over ln using this server certificate. The control-plane /
// operator surface pins a TLS 1.3 floor — matching the agent transport's pinned
// TLS 1.3 (mtls.go) rather than the old TLS 1.2 default — so a credential control
// plane never negotiates a legacy version or a non-AEAD cipher (WIRE-008). TLS 1.3
// negotiates only AEAD suites by protocol, so an explicit CipherSuites allowlist
// is unnecessary at this floor.
// HSTS is emitted by the server's security-headers middleware over TLS (SEC-003),
// not here. It blocks like (*http.Server).ServeTLS and returns its error.
func (s *ServerCert) ServeHTTPS(srv *http.Server, ln net.Listener) error {
	srv.TLSConfig = &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: CurvePreferences(),
	}
	if s.reload != nil {
		// File mode: serve through the reload hook so a rotated pair is
		// picked up without a restart (OPS-TLS-RELOAD-001).
		srv.TLSConfig.GetCertificate = s.reload.GetCertificate
	} else {
		srv.TLSConfig.Certificates = []tls.Certificate{s.cert}
	}
	return srv.ServeTLS(ln, "", "")
}

// LoopbackProbeClient returns an HTTP client for a LOCALHOST LIVENESS PROBE only
// (the container health check execs the binary, which has no shell or curl). It
// does NOT verify the server certificate, because the control plane's internal
// certificate is ephemeral and self-signed and the probe only confirms the
// process is alive and ready on loopback — it carries no credential and reads no
// data. It must never be used for data-bearing requests.
func LoopbackProbeClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// Loopback liveness only — see the doc comment above.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, // #nosec G402 -- localhost liveness probe of this process's own ephemeral self-signed listener; no credential, no data (CWE-295)
		},
	}
}
