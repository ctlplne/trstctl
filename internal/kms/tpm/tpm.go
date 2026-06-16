// Package tpm is the TPM 2.0 key-management backend (S9.6), built from the S9.1 backend
// template behind the AN-3 crypto boundary. GenerateKey asks the TPM to create a key and
// returns a crypto.Signer that signs via the TPM — the private key never leaves the device.
// Digests route through internal/crypto (no crypto/*); the backend itself never touches
// private key material.
//
// TPM 2.0 (swtpm in tests) behind the AN-3 boundary; the go-tpm/device binding is a
// deferred follow-up — the backend operates over the Device seam, validated against a
// software-backed double.
//
// The Device seam exists because a real TPM binding (go-tpm talking to a /dev/tpm* device
// or a swtpm socket) is environment-specific and would change go.mod's direct/indirect set.
// CI exercises the backend against a faithful in-process double; real-device validation is
// the documented deferred follow-up (the same pattern the cloud backends use for their
// remote services).
package tpm

import (
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
)

// Device is the injectable TPM 2.0 seam. A real implementation drives a TPM over go-tpm
// (the deferred follow-up); tests inject a software-backed double. Created keys are
// referenced by an opaque handle string (a transient TPM handle or a persisted context);
// the private key never crosses this boundary — only the public key (DER SubjectPublicKeyInfo)
// and signatures over caller-supplied digests do.
type Device interface {
	// CreateKey provisions a signing key in the TPM for alg and returns an opaque handle
	// plus the public key as DER SubjectPublicKeyInfo (PKIX).
	CreateKey(alg crypto.Algorithm) (handle string, publicDER []byte, err error)
	// Sign signs digest with the key named by handle and returns the raw signature.
	Sign(handle string, digest []byte, opts crypto.SignOptions) (sig []byte, err error)
	// Close releases the device (closes the TPM connection/socket).
	Close() error
}

// Backend is a TPM 2.0 crypto.Backend. It owns a Device and turns the generic backend
// contract into TPM operations; it never holds private key material itself.
type Backend struct {
	dev Device
}

var _ crypto.Backend = (*Backend)(nil)

// Option configures a Backend.
type Option func(*Backend)

// New returns a TPM 2.0 backend that drives dev. In production dev is a go-tpm-backed
// device (deferred follow-up); in tests it is a software-backed double.
func New(dev Device, opts ...Option) *Backend {
	b := &Backend{dev: dev}
	for _, o := range opts {
		o(b)
	}
	return b
}

// Name identifies the backend.
func (b *Backend) Name() string { return "tpm2" }

// GenerateKey provisions a signing key in the TPM and returns a Signer for it. TPM 2.0
// devices commonly support ECDSA P-256 and RSA-2048; the device decides which algorithms
// it accepts, so unsupported algorithms surface as a CreateKey error.
func (b *Backend) GenerateKey(alg crypto.Algorithm) (crypto.Signer, error) {
	if b.dev == nil {
		return nil, errors.New("tpm: no device configured")
	}
	handle, pubDER, err := b.dev.CreateKey(alg)
	if err != nil {
		return nil, fmt.Errorf("tpm: create key: %w", err)
	}
	if len(pubDER) == 0 {
		return nil, fmt.Errorf("tpm: device returned an empty public key for %s", alg)
	}
	return &tpmSigner{
		dev:    b.dev,
		handle: handle,
		alg:    alg,
		pub:    crypto.PublicKey{Algorithm: alg, DER: pubDER},
	}, nil
}

// Close releases the underlying device.
func (b *Backend) Close() error {
	if b.dev == nil {
		return nil
	}
	return b.dev.Close()
}

// tpmSigner signs a digest via the TPM; the key never leaves the device.
type tpmSigner struct {
	dev    Device
	handle string
	alg    crypto.Algorithm
	pub    crypto.PublicKey
}

func (s *tpmSigner) Public() crypto.PublicKey    { return s.pub }
func (s *tpmSigner) Algorithm() crypto.Algorithm { return s.alg }

// Sign hashes message through the crypto boundary (AN-3) and asks the TPM to sign the
// resulting digest. Routing the digest in (rather than the message) matches how TPM 2.0
// signing works and keeps hashing inside internal/crypto.
func (s *tpmSigner) Sign(message []byte, opts crypto.SignOptions) ([]byte, error) {
	digest, err := crypto.Digest(hashOf(opts), message)
	if err != nil {
		return nil, err
	}
	sig, err := s.dev.Sign(s.handle, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("tpm: sign: %w", err)
	}
	return sig, nil
}

// hashOf defaults an unset hash to SHA-256, matching SignOptions' documented default.
func hashOf(opts crypto.SignOptions) crypto.Hash {
	if opts.Hash == "" {
		return crypto.SHA256
	}
	return opts.Hash
}
