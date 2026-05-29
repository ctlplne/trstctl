package pqc

import (
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/eddilithium3"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"

	"certctl.io/certctl/internal/crypto"
	"certctl.io/certctl/internal/crypto/secret"
)

func schemeFor(a crypto.Algorithm) (sign.Scheme, bool) {
	switch a {
	case crypto.MLDSA44:
		return mldsa44.Scheme(), true
	case crypto.MLDSA65:
		return mldsa65.Scheme(), true
	case crypto.MLDSA87:
		return mldsa87.Scheme(), true
	case crypto.HybridEd25519Dilithium3:
		return eddilithium3.Scheme(), true
	default:
		return nil, false
	}
}

func isKEM(a crypto.Algorithm) bool {
	switch a {
	case crypto.MLKEM512, crypto.MLKEM768, crypto.MLKEM1024:
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

// Algorithm reports the key's algorithm.
func (s *Signer) Algorithm() crypto.Algorithm { return s.algorithm }

// Public returns the public key.
func (s *Signer) Public() crypto.PublicKey { return s.public }

// Sign signs message. ML-DSA and the hybrid scheme sign the message directly
// (there is no separate digest step), so SignOptions is ignored.
func (s *Signer) Sign(message []byte, _ crypto.SignOptions) ([]byte, error) {
	sk := s.priv.Bytes()
	if sk == nil {
		return nil, errors.New("pqc: signing key has been destroyed")
	}
	priv, err := s.scheme.UnmarshalBinaryPrivateKey(sk)
	if err != nil {
		return nil, err
	}
	return s.scheme.Sign(priv, message, nil), nil
}

// SignDigest lets a PQC key satisfy crypto.DigestSigner. ML-DSA has no separate
// digest step, so it signs the supplied bytes directly.
func (s *Signer) SignDigest(digest []byte, opts crypto.SignOptions) ([]byte, error) {
	return s.Sign(digest, opts)
}

// Destroy zeroizes and releases the locked private key. It is idempotent.
func (s *Signer) Destroy() { s.priv.Destroy() }

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
