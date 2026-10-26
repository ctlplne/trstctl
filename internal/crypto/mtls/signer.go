// SPDX-License-Identifier: BUSL-1.1

package mtls

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc/credentials"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// This file implements the cross-node mTLS transport for the isolated signing
// service (SIGNER-005 / S15.1 §3, §5.2), inside the AN-3 crypto boundary so the
// signer and control-plane packages name no crypto/* symbol themselves. The
// channel is TLS 1.3, AEAD-only (by protocol at this floor; the package-level
// AEAD allowlist guard in mtls.go fails the build if a non-AEAD suite is ever
// introduced), with the control plane and the signer each PINNING the other's
// certificate: an untrusted or merely CA-signed-but-unpinned peer is rejected in
// both directions. Both sides supply an operator-provisioned certificate, the
// trust anchor (CA) PEM for the peer, and the peer's public-key pin; all are
// loaded from files so neither binary holds key material in a string.

// SignerPeerConfig is the operator-provisioned mTLS material for one end of the
// signer channel: this end's own certificate + key, the CA bundle that anchors
// the *peer's* certificate, and the peer's public-key pin. Files are used (not
// inline strings) so a misconfiguration fails closed at load and no secret lives
// in a Go string (AN-8). PeerPinHex is the lowercase hex SHA-256 of the peer
// certificate's SubjectPublicKeyInfo (see PinPEM); it is REQUIRED — a missing or
// malformed pin is a hard error, never a silent "verify by CA only".
type SignerPeerConfig struct {
	// CertFile / KeyFile is this end's own leaf certificate and private key (PEM).
	CertFile string
	KeyFile  string
	// PeerCAFile is the PEM trust anchor (CA chain) used to verify the peer's
	// certificate. Required.
	PeerCAFile string
	// PeerPinHex pins the peer certificate's public key (hex SHA-256 of its SPKI).
	// Required: the peer must present exactly this key, not merely a certificate
	// the CA signed.
	PeerPinHex string
}

func (c SignerPeerConfig) validate() error {
	var missing []string
	if strings.TrimSpace(c.CertFile) == "" {
		missing = append(missing, "cert")
	}
	if strings.TrimSpace(c.KeyFile) == "" {
		missing = append(missing, "key")
	}
	if strings.TrimSpace(c.PeerCAFile) == "" {
		missing = append(missing, "peer-ca")
	}
	if strings.TrimSpace(c.PeerPinHex) == "" {
		missing = append(missing, "peer-pin")
	}
	if len(missing) > 0 {
		return fmt.Errorf("mtls: signer mTLS config missing required field(s): %s", strings.Join(missing, ", "))
	}
	return nil
}

// ParsePin decodes a lowercase/uppercase hex SHA-256 (64 hex chars) into a Pin.
// It is how an operator supplies the expected peer key on the command line / in
// config without the crypto boundary leaking out.
func ParsePin(hexPin string) (Pin, error) {
	b, err := hex.DecodeString(strings.TrimSpace(hexPin))
	if err != nil {
		return Pin{}, fmt.Errorf("mtls: pin is not valid hex: %w", err)
	}
	if len(b) != sha256.Size {
		return Pin{}, fmt.Errorf("mtls: pin must be a %d-byte (%d hex char) SHA-256; got %d bytes", sha256.Size, sha256.Size*2, len(b))
	}
	var p Pin
	copy(p[:], b)
	return p, nil
}

// PinPEM computes the public-key pin (hex SHA-256 of the leaf SPKI) for a
// certificate in PEM. Operators run it (via a tiny helper or this function in a
// test) to learn the pin to configure on the *other* end. The leaf is the first
// CERTIFICATE block.
func PinPEM(certPEM []byte) (string, error) {
	der, err := FirstCertDER(certPEM)
	if err != nil {
		return "", err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return "", fmt.Errorf("mtls: parse certificate: %w", err)
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:]), nil
}

func loadCAPool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile) // #nosec G304 -- operator-configured peer CA trust anchor path from the signer's own config (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("mtls: read peer CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("mtls: peer CA file contains no certificates")
	}
	return pool, nil
}

// SignerServerCredentials builds the gRPC transport credentials for the signing
// service's cross-node mTLS listener (SIGNER-005). The signer presents cfg.Cert,
// requires and verifies the control plane's client certificate against
// cfg.PeerCA, AND pins the control plane's specific key (cfg.PeerPin) — so a
// rogue peer, or a second certificate the same CA signed, is rejected at the
// handshake. TLS 1.3 only, AEAD-only. Fails closed on any missing/invalid input.
func SignerServerCredentials(cfg SignerPeerConfig) (credentials.TransportCredentials, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: load signer certificate: %w", err)
	}
	clientCAs, err := loadCAPool(cfg.PeerCAFile)
	if err != nil {
		return nil, err
	}
	pin, err := ParsePin(cfg.PeerPinHex)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(serverTLSConfigPinned(cert, clientCAs, &pin)), nil
}

// SignerClientCredentials builds the gRPC transport credentials for the control
// plane dialing an isolated signer over mTLS (SIGNER-005). The control plane
// presents cfg.Cert, verifies the signer's certificate against cfg.PeerCA, AND
// pins the signer's key (cfg.PeerPin); serverName is the signer certificate's
// expected SAN (DNS name or the service DNS). TLS 1.3 only, AEAD-only. Fails
// closed on any missing/invalid input.
func SignerClientCredentials(cfg SignerPeerConfig, serverName string) (credentials.TransportCredentials, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(serverName) == "" {
		return nil, errors.New("mtls: signer mTLS dialer requires a server name to verify the signer certificate SAN")
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: load control-plane client certificate: %w", err)
	}
	serverCAs, err := loadCAPool(cfg.PeerCAFile)
	if err != nil {
		return nil, err
	}
	pin, err := ParsePin(cfg.PeerPinHex)
	if err != nil {
		return nil, err
	}
	src := StaticSource(cert)
	return credentials.NewTLS(clientTLSConfig(src, serverCAs, serverName, &pin)), nil
}

// SignerPeerMaterial is a provisioned pair of mTLS configs — one for the signer
// (server) end and one for the control-plane (client) end — that already pin each
// other. It is the concrete answer to the design §10 "mTLS certificate
// provisioning for the cross-node path" open item: it gives an operator (or a
// bootstrap step / the eval stack) a working, mutually-pinned pair without
// hand-rolling a PKI, while keeping all x509/tls handling inside the AN-3
// boundary. The Signer/ControlPlane configs point at PEM files written under the
// chosen directory; ServerName is the SAN the control plane verifies.
type SignerPeerMaterial struct {
	Signer       SignerPeerConfig
	ControlPlane SignerPeerConfig
	ServerName   string
}

// GenerateSignerPeerMaterial mints a fresh CA, issues a signer (ServerAuth)
// certificate for serverName and a control-plane (ClientAuth) certificate, writes
// the four PEM files (signer cert+key, control-plane cert+key) and the shared CA
// PEM under dir (0600 keys, 0644 certs), and returns the two SignerPeerConfigs
// already cross-pinned: the signer pins the control plane's key and vice-versa.
// It is suitable for evaluation/bootstrap and for tests; production operators may
// instead supply their own files and pins (the SignerServer/ClientCredentials
// constructors take any well-formed material). certTTL bounds both leaves.
func GenerateSignerPeerMaterial(dir, serverName string, certTTL time.Duration) (*SignerPeerMaterial, error) {
	pair, err := GenerateSignerPeerPEM(serverName, certTTL)
	if err != nil {
		return nil, err
	}
	defer pair.Wipe()

	caPath := filepath.Join(dir, "signer-ca.pem")
	signerCertPath := filepath.Join(dir, "signer.crt")
	signerKeyPath := filepath.Join(dir, "signer.key")
	cpCertPath := filepath.Join(dir, "control-plane.crt")
	cpKeyPath := filepath.Join(dir, "control-plane.key")

	if err := os.WriteFile(caPath, pair.CA, 0o644); err != nil { // #nosec G306 -- writes the PUBLIC CA trust anchor bundle; world-readable is intended, no key material (CWE-276)
		return nil, fmt.Errorf("mtls: write CA: %w", err)
	}
	if err := writeCertKeyPEM(signerCertPath, signerKeyPath, pair.SignerCert, pair.SignerKey); err != nil {
		return nil, fmt.Errorf("mtls: write signer material: %w", err)
	}
	if err := writeCertKeyPEM(cpCertPath, cpKeyPath, pair.ControlPlaneCert, pair.ControlPlaneKey); err != nil {
		return nil, fmt.Errorf("mtls: write control-plane material: %w", err)
	}

	return &SignerPeerMaterial{
		ServerName: serverName,
		Signer: SignerPeerConfig{
			CertFile:   signerCertPath,
			KeyFile:    signerKeyPath,
			PeerCAFile: caPath,
			PeerPinHex: pair.ControlPlanePinHex,
		},
		ControlPlane: SignerPeerConfig{
			CertFile:   cpCertPath,
			KeyFile:    cpKeyPath,
			PeerCAFile: caPath,
			PeerPinHex: pair.SignerPinHex,
		},
	}, nil
}

// SignerPeerPEM is a cross-pinned signer channel pair held in memory, for a
// provisioner that stores it somewhere other than files: the Kubernetes
// operator writes each end into its own Secret (tls.crt, tls.key, peer-ca.pem,
// peer-pin). The minting CA's private key is discarded once both leaves are
// issued, so nothing can issue a third peer. Keys are PKCS#8 PEM; call Wipe
// once they are stored.
type SignerPeerPEM struct {
	CA               []byte
	SignerCert       []byte
	SignerKey        []byte
	ControlPlaneCert []byte
	ControlPlaneKey  []byte
	// SignerPinHex is the hex SHA-256 of the signer key's SPKI: the control
	// plane's peer-pin. ControlPlanePinHex is the signer's peer-pin.
	SignerPinHex       string
	ControlPlanePinHex string
	// NotAfter is when the earlier of the two leaves expires.
	NotAfter time.Time
}

// Wipe zeroes both private keys.
func (m *SignerPeerPEM) Wipe() {
	secret.Wipe(m.SignerKey)
	secret.Wipe(m.ControlPlaneKey)
}

// GenerateSignerPeerPEM mints the pair GenerateSignerPeerMaterial writes to
// files — a fresh CA, a signer certificate for serverName and a control-plane
// client certificate, each pinned by the other end — without touching the
// filesystem. certTTL bounds both leaves.
func GenerateSignerPeerPEM(serverName string, certTTL time.Duration) (*SignerPeerPEM, error) {
	if strings.TrimSpace(serverName) == "" {
		return nil, errors.New("mtls: signer mTLS material needs a server name (the signer certificate SAN)")
	}
	ca, err := NewCA("trstctl-signer-mtls-ca")
	if err != nil {
		return nil, err
	}
	serverCert, err := ca.IssueServerCertificate([]string{serverName}, certTTL)
	if err != nil {
		return nil, fmt.Errorf("mtls: issue signer certificate: %w", err)
	}
	clientCert, err := ca.IssueClientCertificate("trstctl-control-plane", certTTL)
	if err != nil {
		return nil, fmt.Errorf("mtls: issue control-plane certificate: %w", err)
	}
	pair := &SignerPeerPEM{CA: ca.BundlePEM()}
	if pair.SignerCert, pair.SignerKey, err = certKeyPEM(serverCert); err != nil {
		return nil, fmt.Errorf("mtls: encode signer material: %w", err)
	}
	if pair.ControlPlaneCert, pair.ControlPlaneKey, err = certKeyPEM(clientCert); err != nil {
		pair.Wipe()
		return nil, fmt.Errorf("mtls: encode control-plane material: %w", err)
	}
	// Cross-pin: the signer pins the control plane's key, the control plane pins
	// the signer's key.
	signerPin, cpPin := PinServer(serverCert), PinServer(clientCert)
	pair.SignerPinHex = hex.EncodeToString(signerPin[:])
	pair.ControlPlanePinHex = hex.EncodeToString(cpPin[:])
	pair.NotAfter = serverCert.Leaf.NotAfter
	if clientCert.Leaf.NotAfter.Before(pair.NotAfter) {
		pair.NotAfter = clientCert.Leaf.NotAfter
	}
	return pair, nil
}

// WriteCertKeyFiles writes a leaf certificate chain (PEM, 0644) and its private
// key (PKCS#8 PEM, 0600) to the given paths. It lets tests and runtime material
// provisioners persist certificates without importing crypto/x509 outside this
// boundary (AN-3).
func WriteCertKeyFiles(certPath, keyPath string, cert tls.Certificate) error {
	return writeCertKey(certPath, keyPath, cert)
}

// writeCertKey writes a leaf certificate chain (PEM, 0644) and its private key
// (PKCS#8 PEM, 0600) to the given paths.
func writeCertKey(certPath, keyPath string, cert tls.Certificate) error {
	chain, keyPEM, err := certKeyPEM(cert)
	if err != nil {
		return err
	}
	defer secret.Wipe(keyPEM)
	return writeCertKeyPEM(certPath, keyPath, chain, keyPEM)
}

func writeCertKeyPEM(certPath, keyPath string, chain, keyPEM []byte) error {
	if err := os.WriteFile(certPath, chain, 0o644); err != nil { // #nosec G306 -- writes the PUBLIC leaf certificate chain; the private key beside it is written 0600 (CWE-276)
		return err
	}
	return os.WriteFile(keyPath, keyPEM, 0o600)
}

// certKeyPEM encodes a leaf certificate chain and its PKCS#8 private key as PEM.
func certKeyPEM(cert tls.Certificate) (chain, keyPEM []byte, err error) {
	for _, der := range cert.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	key, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("mtls: unexpected non-ECDSA private key")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	defer secret.Wipe(der)
	return chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
