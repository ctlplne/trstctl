// SPDX-License-Identifier: MPL-2.0

// Package pkcs11 is the PKCS#11 (HSM) key-management backend (S9.2), built from the
// S9.1 backend template behind the AN-3 crypto boundary. GenerateKey asks the token to
// create a key pair and returns a crypto.Signer that signs via the token's C_Sign — the
// private key never leaves the HSM, satisfying AN-8 for sealed key material.
//
// OpenModuleSession is the cgo adapter over github.com/miekg/pkcs11: it dlopens the
// configured module, C_Initialize's it, opens the selected token slot, and C_Login's
// with the token PIN. That real session implements the same seam as the software test
// double. None of crypto/* is imported here: every digest, public-key marshaling step,
// and signature verification helper routes through internal/crypto.
package pkcs11

import (
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
)

// Session is the injectable seam onto a logged-in PKCS#11 token session. It is the only
// surface the backend depends on, so the cgo module binding (miekg/pkcs11) and the
// software-backed test double both implement these three methods. A handle is the
// opaque, token-local identifier of a key pair (a CKA_LABEL or CKA_ID in a real
// module); the backend treats it as an opaque string and never inspects it.
type Session interface {
	// GenerateKey creates a key pair on the token for alg and returns its handle and
	// the PKIX/DER (SubjectPublicKeyInfo) encoding of the public key. The private key
	// stays on the token.
	GenerateKey(alg crypto.Algorithm) (handle string, publicDER []byte, err error)
	// SignDigest signs a pre-computed digest with the key named by handle. This mirrors
	// a C_Sign over a CKM_*_PKCS / CKM_ECDSA mechanism on a host-computed hash.
	SignDigest(handle string, digest []byte, opts crypto.SignOptions) (sig []byte, err error)
	// Close releases the session (a real impl would C_CloseSession / C_Finalize).
	Close() error
}

// Backend is a PKCS#11 crypto.Backend. It holds a single logged-in token session and
// generates keys on that token; the private material never leaves the HSM.
type Backend struct {
	session Session
}

var _ crypto.Backend = (*Backend)(nil)

// Option configures a Backend. It exists so the constructor can grow token-selection
// knobs without changing callers; today there are no options.
type Option func(*Backend)

// New returns a PKCS#11 backend over an already-opened, logged-in token session.
//
// The session is the AN-3 seam: a real deployment builds it with OpenModuleSession,
// while fast unit tests pass a software-backed double.
func New(session Session, opts ...Option) *Backend {
	b := &Backend{session: session}
	for _, o := range opts {
		o(b)
	}
	return b
}

// Name identifies the backend, for diagnostics and inventory.
func (b *Backend) Name() string { return "pkcs11" }

// GenerateKey creates a key pair on the token and returns a Signer bound to its handle.
func (b *Backend) GenerateKey(alg crypto.Algorithm) (crypto.Signer, error) {
	handle, publicDER, err := b.session.GenerateKey(alg)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: generate key: %w", err)
	}
	return &signer{
		session: b.session,
		handle:  handle,
		pub:     crypto.PublicKey{Algorithm: alg, DER: publicDER},
		alg:     alg,
	}, nil
}

// signer signs via the token's C_Sign; the private key never leaves the HSM.
type signer struct {
	session Session
	handle  string
	pub     crypto.PublicKey
	alg     crypto.Algorithm
}

func (s *signer) Public() crypto.PublicKey    { return s.pub }
func (s *signer) Algorithm() crypto.Algorithm { return s.alg }

// Sign hashes message on the host (the HSM signs a pre-computed digest) and delegates
// the signature to the token session.
func (s *signer) Sign(message []byte, opts crypto.SignOptions) ([]byte, error) {
	if opts.Hash == "" {
		opts.Hash = crypto.SHA256
	}
	digest, err := crypto.Digest(opts.Hash, message)
	if err != nil {
		return nil, err
	}
	sig, err := s.session.SignDigest(s.handle, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: sign: %w", err)
	}
	return sig, nil
}
