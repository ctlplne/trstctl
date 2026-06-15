// Package mtls implements the agent transport's mutual-TLS security, inside the
// AN-3 crypto boundary (it is a subpackage of internal/crypto, so it alone — with
// the rest of the boundary — may import crypto/tls and crypto/x509).
//
// It provides an in-process X.509 CA that issues the server certificate and
// short-lived (24h) agent client certificates, TLS 1.3 configs (AEAD-only,
// mutual auth, no plaintext), gRPC transport credentials, automatic client-
// certificate rotation, and server-certificate pinning. Callers outside the
// boundary consume only the opaque gRPC credentials.
//
// In production the CA signing key is custodied by the signer (AN-4); this
// in-process CA issues directly for the transport and stands in until that lands.
package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"
)

// ClientCertTTL is the validity period of an agent client certificate. Agents
// rotate well before it elapses (see RotatingSource).
const ClientCertTTL = 24 * time.Hour

// CA is an in-process X.509 certificate authority for the agent transport.
type CA struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

// NewCA creates a self-signed CA with the given common name.
func NewCA(commonName string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, der: der, key: key}, nil
}

// Pool returns a certificate pool trusting this CA — used as the server's
// client-CA pool and the agent's root pool.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// IssueServerCertificate issues a server (ServerAuth) certificate for the given
// DNS names, valid for ttl.
func (c *CA) IssueServerCertificate(dnsNames []string, ttl time.Duration) (tls.Certificate, error) {
	cn := ""
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	return c.issue(cn, dnsNames, ttl, x509.ExtKeyUsageServerAuth)
}

// IssueClientCertificate issues a client (ClientAuth) certificate for the given
// common name (the agent identity), valid for ttl.
func (c *CA) IssueClientCertificate(commonName string, ttl time.Duration) (tls.Certificate, error) {
	return c.issue(commonName, nil, ttl, x509.ExtKeyUsageClientAuth)
}

func (c *CA) issue(cn string, dnsNames []string, ttl time.Duration, eku x509.ExtKeyUsage) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
		DNSNames:              dnsNames,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, c.der}, PrivateKey: key, Leaf: leaf}, nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// ClientCertSource supplies the agent's current client certificate on each
// handshake, which is what enables transparent rotation.
type ClientCertSource interface {
	ClientCertificate() (*tls.Certificate, error)
}

type staticSource struct{ cert tls.Certificate }

// StaticSource returns a source that always presents cert.
func StaticSource(cert tls.Certificate) ClientCertSource { return &staticSource{cert: cert} }

func (s *staticSource) ClientCertificate() (*tls.Certificate, error) {
	c := s.cert
	return &c, nil
}

// RotatingSource presents a client certificate and reissues it before expiry, so
// an agent's credential never lapses mid-flight.
type RotatingSource struct {
	mu            sync.Mutex
	current       tls.Certificate
	issue         func() (tls.Certificate, error)
	refreshBefore time.Duration
}

// NewRotatingSource wraps an initial certificate; when its remaining validity
// drops to refreshBefore, the next ClientCertificate call reissues via issue.
func NewRotatingSource(initial tls.Certificate, issue func() (tls.Certificate, error), refreshBefore time.Duration) *RotatingSource {
	return &RotatingSource{current: initial, issue: issue, refreshBefore: refreshBefore}
}

// ClientCertificate returns the current certificate, rotating first if it is
// within refreshBefore of expiry.
func (r *RotatingSource) ClientCertificate() (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.needsRotation() {
		fresh, err := r.issue()
		if err != nil {
			return nil, err
		}
		r.current = fresh
	}
	c := r.current
	return &c, nil
}

func (r *RotatingSource) needsRotation() bool {
	leaf := r.current.Leaf
	if leaf == nil {
		if len(r.current.Certificate) == 0 {
			return true
		}
		parsed, err := x509.ParseCertificate(r.current.Certificate[0])
		if err != nil {
			return true
		}
		leaf = parsed
	}
	return time.Until(leaf.NotAfter) <= r.refreshBefore
}

// Pin is a SHA-256 of a server certificate's SubjectPublicKeyInfo. An agent pins
// the server it expects, so a swapped server key is refused even if it chains to
// a trusted CA.
type Pin [32]byte

// PinServer computes the pin for a server certificate.
func PinServer(cert tls.Certificate) Pin {
	leaf := cert.Leaf
	if leaf == nil {
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return Pin{}
		}
		leaf = parsed
	}
	return sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
}

func (p Pin) verify(rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return errors.New("mtls: server presented no certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("mtls: parse server certificate: %w", err)
	}
	if sha256.Sum256(leaf.RawSubjectPublicKeyInfo) != [32]byte(p) {
		return errors.New("mtls: server certificate does not match the pinned key")
	}
	return nil
}

func serverTLSConfig(serverCert tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	return serverTLSConfigPinned(serverCert, clientCAs, nil)
}

// serverTLSConfigPinned is serverTLSConfig that additionally pins the peer
// (client) certificate when clientPin is non-nil: after the normal CA-chain
// verification, the presented client leaf's SubjectPublicKeyInfo must match the
// pin or the handshake fails. This is the server-side half of mutual pinning used
// by the signer's cross-node mTLS listener (SIGNER-005): the signer pins the
// control plane's specific client key, not merely "any cert this CA signed", so a
// second, differently-keyed certificate from the same CA is still refused.
func serverTLSConfigPinned(serverCert tls.Certificate, clientCAs *x509.CertPool, clientPin *Pin) *tls.Config {
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
	if clientPin != nil {
		p := *clientPin
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return p.verify(rawCerts)
		}
	}
	return cfg
}

func clientTLSConfig(src ClientCertSource, serverCAs *x509.CertPool, serverName string, pin *Pin) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    serverCAs,
		ServerName: serverName,
	}
	if src != nil {
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return src.ClientCertificate()
		}
	}
	if pin != nil {
		p := *pin
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return p.verify(rawCerts)
		}
	}
	return cfg
}

// ServerCredentials returns gRPC transport credentials for the agent-facing
// server: TLS 1.3, mutual auth verifying client certs against clientCAs.
func ServerCredentials(serverCert tls.Certificate, clientCAs *x509.CertPool) credentials.TransportCredentials {
	return credentials.NewTLS(serverTLSConfig(serverCert, clientCAs))
}

// ClientCredentials returns gRPC transport credentials for an agent: TLS 1.3,
// presenting the (possibly rotating) client certificate from src, verifying the
// server against serverCAs and serverName, and — if pin is non-nil — refusing a
// server whose key does not match the pin. A nil src presents no client
// certificate.
func ClientCredentials(src ClientCertSource, serverCAs *x509.CertPool, serverName string, pin *Pin) credentials.TransportCredentials {
	return credentials.NewTLS(clientTLSConfig(src, serverCAs, serverName, pin))
}

// aeadCipherSuites is the AEAD-only allowlist. TLS 1.3 (which the transport pins)
// negotiates only AEAD suites by protocol; this explicit list plus the init guard
// make AEAD-only a load-time invariant that fails fast if a non-AEAD suite is
// ever introduced (for example if TLS 1.2 were re-enabled).
var aeadCipherSuites = []uint16{
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

var aeadSet = func() map[uint16]struct{} {
	m := make(map[uint16]struct{}, len(aeadCipherSuites))
	for _, s := range aeadCipherSuites {
		m[s] = struct{}{}
	}
	return m
}()

// aeadOnly returns an error if any suite is not in the AEAD allowlist.
func aeadOnly(suites []uint16) error {
	for _, s := range suites {
		if _, ok := aeadSet[s]; !ok {
			return fmt.Errorf("mtls: cipher suite 0x%04x is not AEAD; only AEAD suites are permitted", s)
		}
	}
	return nil
}

func init() {
	if err := aeadOnly(aeadCipherSuites); err != nil {
		panic(err)
	}
}
