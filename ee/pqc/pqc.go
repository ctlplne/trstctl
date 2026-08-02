// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqc

import (
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/eddilithium3"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func schemeFor(a crypto.Algorithm) (sign.Scheme, bool) {
	switch a {
	case MLDSA44:
		return mldsa44.Scheme(), true
	case MLDSA65:
		return mldsa65.Scheme(), true
	case MLDSA87:
		return mldsa87.Scheme(), true
	case HybridEd25519Dilithium3:
		return eddilithium3.Scheme(), true
	default:
		return nil, false
	}
}

func isKEM(a crypto.Algorithm) bool {
	switch a {
	case MLKEM512, MLKEM768, MLKEM1024:
		return true
	default:
		return false
	}
}

// Signer is a post-quantum or hybrid signing key whose private material is held
// in a locked secret buffer (AN-8: mlock'd, non-dumpable, zeroized on Destroy)
// and parsed only for the moment of each signature. It implements crypto.Signer
// and crypto.DigestSigner, so it is interchangeable with classical keys behind
// the boundary.
type Signer struct {
	algorithm crypto.Algorithm
	scheme    sign.Scheme
	public    crypto.PublicKey
	priv      *secret.Buffer
}

// GenerateKey creates a new PQC or hybrid signing key. ML-KEM algorithms are
// rejected: they are key-encapsulation mechanisms, not signature schemes.
func GenerateKey(algorithm crypto.Algorithm) (*Signer, error) {
	scheme, ok := schemeFor(algorithm)
	if !ok {
		if isKEM(algorithm) {
			return nil, fmt.Errorf("pqc: %s is a key-encapsulation mechanism, not a signature scheme", algorithm)
		}
		return nil, fmt.Errorf("pqc: unsupported algorithm %q", algorithm)
	}
	pub, priv, err := scheme.GenerateKey()
	if err != nil {
		return nil, err
	}
	defer crypto.WipeBinaryPrivateKey(priv)
	if generatePrivateKeyObserver != nil {
		generatePrivateKeyObserver(priv)
	}
	skBytes, err := priv.MarshalBinary()
	if err != nil {
		return nil, err
	}
	buf, err := secret.NewFrom(skBytes)
	secret.Wipe(skBytes) // wipe the transient unlocked copy
	if err != nil {
		return nil, err
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		buf.Destroy()
		return nil, err
	}
	return &Signer{
		algorithm: algorithm,
		scheme:    scheme,
		public:    crypto.PublicKey{Algorithm: algorithm, DER: pubBytes},
		priv:      buf,
	}, nil
}

// NewSignerFromPrivateKey reconstructs a PQC signing key from CIRCL-marshaled
// private-key bytes. The bytes are copied into locked memory; the caller keeps
// ownership of privateKey and should wipe it after sealing/loading.
func NewSignerFromPrivateKey(algorithm crypto.Algorithm, privateKey []byte) (*Signer, error) {
	scheme, ok := schemeFor(algorithm)
	if !ok {
		if isKEM(algorithm) {
			return nil, fmt.Errorf("pqc: %s is a key-encapsulation mechanism, not a signature scheme", algorithm)
		}
		return nil, fmt.Errorf("pqc: unsupported algorithm %q", algorithm)
	}
	priv, err := scheme.UnmarshalBinaryPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("pqc: parse private key: %w", err)
	}
	defer crypto.WipeBinaryPrivateKey(priv)
	pub, ok := priv.Public().(sign.PublicKey)
	if !ok {
		return nil, fmt.Errorf("pqc: private key returned unexpected public key %T", priv.Public())
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("pqc: marshal public key: %w", err)
	}
	buf, err := secret.NewFrom(privateKey)
	if err != nil {
		return nil, err
	}
	return &Signer{
		algorithm: algorithm,
		scheme:    scheme,
		public:    crypto.PublicKey{Algorithm: algorithm, DER: pubBytes},
		priv:      buf,
	}, nil
}

// Algorithm reports the key's algorithm.
func (s *Signer) Algorithm() crypto.Algorithm { return s.algorithm }

// Public returns the public key.
func (s *Signer) Public() crypto.PublicKey { return s.public }

// Destroyed-key wording, kept as constants so every borrow site in this package reports
// the same message whether the key was already gone or a concurrent Destroy won the race
// for it.
const (
	destroyedSigningKeyMsg = "pqc: signing key has been destroyed"
	destroyedKEMKeyMsg     = "pqc: ML-KEM private key has been destroyed"
	destroyedSLHDSAKeyMsg  = "crypto: SLH-DSA key has been destroyed"
)

// destroyedKeyError maps the locked buffer's lifetime error onto this package's per-key
// destroyed wording, so callers keep seeing one stable message whether the key was
// already gone or a concurrent Destroy refused the borrow.
func destroyedKeyError(err error, msg string) error {
	if errors.Is(err, secret.ErrDestroyed) {
		return errors.New(msg)
	}
	return err
}

// borrowObserver is a test-only hook (nil in production) invoked at the top of every
// locked-buffer borrow in this package that parses private material, before the parse. It
// exists so the destroy-during-use lifetime tests can hold a borrow open while another
// goroutine calls Destroy, and has zero cost in production.
var borrowObserver func()

// PrivateKeyBytes returns a copy of the CIRCL-marshaled private key for sealed
// persistence. The returned bytes are unprotected memory; callers must wipe them
// promptly after sealing. The copy is taken inside the locked buffer's borrow, so a
// concurrent Destroy cannot wipe or unmap the region mid-copy (AN-8 lifetime).
func (s *Signer) PrivateKeyBytes() ([]byte, error) {
	var out []byte
	if err := s.priv.Use(func(sk []byte) error {
		out = make([]byte, len(sk))
		copy(out, sk)
		return nil
	}); err != nil {
		return nil, destroyedKeyError(err, destroyedSigningKeyMsg)
	}
	return out, nil
}

// Sign signs message. ML-DSA and the hybrid scheme sign the message directly
// (there is no separate digest step), so SignOptions is ignored.
//
// Lifetime (AN-4/AN-8): the whole private-key operation runs inside s.priv.Use, so the
// locked region is borrowed under the buffer's read lock for exactly as long as this
// method holds a slice into it. A concurrent Destroy — the signer's DestroyKey RPC racing
// this Sign — therefore waits for the signature to finish instead of wiping and
// munmapping the region under the parse, which was a use-after-free. A Destroy that lands
// FIRST is still honored: Use refuses the borrow and this returns the clean destroyed-key
// error rather than signing with dead material.
func (s *Signer) Sign(message []byte, _ crypto.SignOptions) ([]byte, error) {
	var sig []byte
	if err := s.priv.Use(func(sk []byte) error {
		// Test-only seam (nil in production): parks a signature INSIDE the borrow so a test
		// can prove a concurrent Destroy waits instead of freeing the region here.
		if borrowObserver != nil {
			borrowObserver()
		}
		priv, err := s.scheme.UnmarshalBinaryPrivateKey(sk)
		if err != nil {
			return err
		}
		defer crypto.WipeBinaryPrivateKey(priv)
		if signPrivateKeyObserver != nil {
			signPrivateKeyObserver(priv)
		}
		sig = s.scheme.Sign(priv, message, nil)
		return nil
	}); err != nil {
		return nil, destroyedKeyError(err, destroyedSigningKeyMsg)
	}
	return sig, nil
}

// SignDigest lets a PQC key satisfy crypto.DigestSigner. ML-DSA has no separate
// digest step, so it signs the supplied bytes directly.
func (s *Signer) SignDigest(digest []byte, opts crypto.SignOptions) ([]byte, error) {
	return s.Sign(digest, opts)
}

// Destroy zeroizes and releases the locked private key. It is idempotent.
func (s *Signer) Destroy() { s.priv.Destroy() }

// Test-only hooks (nil in production) used by residue tests to capture transient
// CIRCL private-key objects and verify they are wiped after the constructor/sign
// call returns.
var (
	generatePrivateKeyObserver func(sign.PrivateKey)
	signPrivateKeyObserver     func(sign.PrivateKey)
)

// Verify checks a PQC or hybrid signature over message using pub.
func Verify(pub crypto.PublicKey, message, signature []byte) error {
	scheme, ok := schemeFor(pub.Algorithm)
	if !ok {
		return fmt.Errorf("pqc: unsupported algorithm %q", pub.Algorithm)
	}
	pk, err := scheme.UnmarshalBinaryPublicKey(pub.DER)
	if err != nil {
		return err
	}
	if !scheme.Verify(pk, message, signature, nil) {
		return errors.New("pqc: signature verification failed")
	}
	return nil
}
