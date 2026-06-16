// Package yubihsm is the YubiHSM 2 key-management backend (S9.7), built from the S9.1
// backend template behind the AN-3 crypto boundary. GenerateKey asks the device to create
// an asymmetric signing key and returns a crypto.Signer that signs via the device — the
// private key never leaves the YubiHSM. Digests route through internal/crypto (no crypto/*),
// so the backend stays inside the AN-3 boundary.
//
// YubiHSM 2 behind the AN-3 boundary; the yubihsm-connector/PKCS#11 binding is a deferred
// follow-up — the backend operates over the Connector seam, validated against a software-backed
// double. A real binding is environment-specific (it needs the yubihsm-connector daemon or the
// vendor PKCS#11 module and a physical/emulated device), so this sprint injects the device
// access as a Go interface and exercises the backend against an in-process double on CI; the
// concrete connector binding lands later without touching the backend.
package yubihsm

import (
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
)

// Connector is the device-access seam. A real implementation wraps the yubihsm-connector
// (HTTP to the daemon) or the vendor PKCS#11 module; tests inject a software-backed double.
// Handles are opaque, connector-assigned identifiers (e.g. an object ID) for a key whose
// private material lives on the device. The seam carries no crypto/* types, keeping the
// binding swappable and the boundary intact (AN-3).
type Connector interface {
	// GenerateKey creates an asymmetric signing key on the device for alg and returns an
	// opaque handle plus the public key as DER (PKIX/SubjectPublicKeyInfo).
	GenerateKey(alg crypto.Algorithm) (handle string, publicDER []byte, err error)
	// SignDigest signs a pre-computed digest with the on-device key named by handle and
	// returns the raw signature.
	SignDigest(handle string, digest []byte, opts crypto.SignOptions) (sig []byte, err error)
	// Close releases the device session.
	Close() error
}

// Backend is a YubiHSM 2 crypto.Backend. It owns a Connector to a device session; key
// material never leaves the device.
type Backend struct {
	conn Connector
}

var _ crypto.Backend = (*Backend)(nil)

// Option configures a Backend. It exists so future device options (auth key, domain,
// capability set) can be added without changing New's signature.
type Option func(*Backend)

// New returns a YubiHSM backend over conn.
func New(conn Connector, opts ...Option) *Backend {
	b := &Backend{conn: conn}
	for _, o := range opts {
		o(b)
	}
	return b
}

// Name identifies the backend.
func (b *Backend) Name() string { return "yubihsm" }

// GenerateKey creates an on-device asymmetric signing key and returns a Signer for it.
func (b *Backend) GenerateKey(alg crypto.Algorithm) (crypto.Signer, error) {
	if b.conn == nil {
		return nil, fmt.Errorf("yubihsm: no connector configured")
	}
	handle, publicDER, err := b.conn.GenerateKey(alg)
	if err != nil {
		return nil, fmt.Errorf("yubihsm: generate key: %w", err)
	}
	if len(publicDER) == 0 {
		return nil, fmt.Errorf("yubihsm: device returned an empty public key for %s", alg)
	}
	pub := crypto.PublicKey{Algorithm: alg, DER: publicDER}
	return &hsmSigner{conn: b.conn, handle: handle, alg: alg, pub: pub}, nil
}

// hsmSigner signs a digest via the device; the key never leaves the YubiHSM.
type hsmSigner struct {
	conn   Connector
	handle string
	alg    crypto.Algorithm
	pub    crypto.PublicKey
}

func (s *hsmSigner) Public() crypto.PublicKey    { return s.pub }
func (s *hsmSigner) Algorithm() crypto.Algorithm { return s.alg }

// Sign hashes message through the crypto boundary (AN-3) and signs the resulting digest on
// the device.
func (s *hsmSigner) Sign(message []byte, opts crypto.SignOptions) ([]byte, error) {
	digest, err := crypto.Digest(hashOf(opts), message)
	if err != nil {
		return nil, err
	}
	sig, err := s.conn.SignDigest(s.handle, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("yubihsm: sign: %w", err)
	}
	return sig, nil
}

// hashOf defaults an empty hash to SHA-256, matching the software backend.
func hashOf(opts crypto.SignOptions) crypto.Hash {
	if opts.Hash == "" {
		return crypto.SHA256
	}
	return opts.Hash
}
