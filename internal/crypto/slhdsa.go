package crypto

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/slhdsa"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// SLH-DSA (FIPS 205 / SPHINCS+) stateless hash-based post-quantum signatures
// (S14.3, F16), added entirely behind the AN-3 boundary to demonstrate the
// crypto-agility the architecture promises: a new algorithm is one package change
// with zero caller edits. Key material is sealed in a locked buffer (AN-8).

const (
	SLHDSA128s Algorithm = "SLH-DSA-SHA2-128s"
	SLHDSA128f Algorithm = "SLH-DSA-SHA2-128f"
	SLHDSA192s Algorithm = "SLH-DSA-SHA2-192s"
	SLHDSA256s Algorithm = "SLH-DSA-SHA2-256s"
)

// IsSLHDSA reports whether a names an SLH-DSA parameter set.
func IsSLHDSA(a Algorithm) bool {
	_, err := slhdsa.IDByName(string(a))
	return err == nil
}

func slhdsaID(a Algorithm) (slhdsa.ID, error) {
	id, err := slhdsa.IDByName(string(a))
	if err != nil {
		return 0, fmt.Errorf("crypto: unknown SLH-DSA parameter set %q: %w", a, err)
	}
	return id, nil
}

// SLHDSASigner is an SLH-DSA private key implementing Signer. SLH-DSA keys are not
// PKIX/PKCS#8 stdlib types, so the private key is held circl-marshaled inside a
// locked secret buffer and parsed transiently per signature (AN-8). Public().DER
// carries the circl-marshaled public key.
type SLHDSASigner struct {
	algorithm Algorithm
	der       *secret.Buffer
	pubDER    []byte
}

// GenerateSLHDSAKey generates an SLH-DSA key for the given parameter set.
func GenerateSLHDSAKey(a Algorithm) (*SLHDSASigner, error) {
	id, err := slhdsaID(a)
	if err != nil {
		return nil, err
	}
	pub, priv, err := slhdsa.GenerateKey(rand.Reader, id)
	if err != nil {
		return nil, fmt.Errorf("crypto: generate %s: %w", a, err)
	}
	privDER, err := priv.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal SLH-DSA key: %w", err)
	}
	buf, err := secret.NewFrom(privDER)
	secret.Wipe(privDER)
	if err != nil {
		return nil, err
	}
	pubDER, err := pub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal SLH-DSA public key: %w", err)
	}
	return &SLHDSASigner{algorithm: a, der: buf, pubDER: pubDER}, nil
}

// Algorithm implements Signer.
func (s *SLHDSASigner) Algorithm() Algorithm { return s.algorithm }

// Public implements Signer.
func (s *SLHDSASigner) Public() PublicKey {
	return PublicKey{Algorithm: s.algorithm, DER: append([]byte(nil), s.pubDER...)}
}

// Destroy zeroizes and releases the locked key.
func (s *SLHDSASigner) Destroy() { s.der.Destroy() }

// Sign signs message with SLH-DSA. The scheme hashes internally, so SignOptions is
// ignored. The private key is parsed transiently from the locked buffer.
func (s *SLHDSASigner) Sign(message []byte, _ SignOptions) ([]byte, error) {
	der := s.der.Bytes()
	if der == nil {
		return nil, fmt.Errorf("crypto: SLH-DSA key has been destroyed")
	}
	id, err := slhdsaID(s.algorithm)
	if err != nil {
		return nil, err
	}
	var priv slhdsa.PrivateKey
	priv.ID = id
	if err := priv.UnmarshalBinary(der); err != nil {
		return nil, fmt.Errorf("crypto: parse SLH-DSA key: %w", err)
	}
	sig, err := priv.Sign(rand.Reader, message, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: SLH-DSA sign: %w", err)
	}
	return sig, nil
}

// VerifySLHDSA verifies an SLH-DSA signature over message against pub.
func VerifySLHDSA(pub PublicKey, message, signature []byte) error {
	id, err := slhdsaID(pub.Algorithm)
	if err != nil {
		return err
	}
	pk := slhdsa.PublicKey{ID: id}
	if err := pk.UnmarshalBinary(pub.DER); err != nil {
		return fmt.Errorf("crypto: parse SLH-DSA public key: %w", err)
	}
	if !slhdsa.Verify(&pk, slhdsa.NewMessage(message), signature, nil) {
		return fmt.Errorf("crypto: SLH-DSA signature verification failed")
	}
	return nil
}
