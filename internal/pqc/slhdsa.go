// SPDX-License-Identifier: BUSL-1.1

package pqc

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/slhdsa"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// SLH-DSA (FIPS 205 / SPHINCS+) stateless hash-based post-quantum signatures
// (S14.3, F16), added entirely behind the AN-3 boundary to demonstrate the
// crypto-agility the architecture promises: a new algorithm is one package change
// with zero caller edits. Key material is sealed in a locked buffer (AN-8).

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
	defer crypto.WipeBinaryPrivateKey(&priv)
	if slhdsaPrivateKeyObserver != nil {
		slhdsaPrivateKeyObserver(&priv)
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

// NewSLHDSAKeyFromPrivateKey reconstructs an SLH-DSA signer from CIRCL-marshaled
// private-key bytes. The bytes are copied into locked memory; the caller keeps
// ownership of der and should wipe it after sealing/loading.
func NewSLHDSAKeyFromPrivateKey(a Algorithm, der []byte) (*SLHDSASigner, error) {
	id, err := slhdsaID(a)
	if err != nil {
		return nil, err
	}
	var priv slhdsa.PrivateKey
	priv.ID = id
	if err := priv.UnmarshalBinary(der); err != nil {
		return nil, fmt.Errorf("crypto: parse SLH-DSA key: %w", err)
	}
	defer crypto.WipeBinaryPrivateKey(&priv)
	pubDER, err := priv.PublicKey().MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal SLH-DSA public key: %w", err)
	}
	buf, err := secret.NewFrom(der)
	if err != nil {
		return nil, err
	}
	return &SLHDSASigner{algorithm: a, der: buf, pubDER: pubDER}, nil
}

// Algorithm implements Signer.
func (s *SLHDSASigner) Algorithm() Algorithm { return s.algorithm }

// Public implements Signer.
func (s *SLHDSASigner) Public() PublicKey {
	return PublicKey{Algorithm: s.algorithm, DER: append([]byte(nil), s.pubDER...)}
}

// PrivateKeyBytes returns a copy of the CIRCL-marshaled private key for sealed
// persistence. The returned bytes are unprotected memory; callers must wipe them
// promptly after sealing. The copy is taken inside the locked buffer's borrow, so a
// concurrent Destroy cannot wipe or unmap the region mid-copy (AN-8 lifetime).
func (s *SLHDSASigner) PrivateKeyBytes() ([]byte, error) {
	var out []byte
	if err := s.der.Use(func(der []byte) error {
		out = make([]byte, len(der))
		copy(out, der)
		return nil
	}); err != nil {
		return nil, destroyedKeyError(err, destroyedSLHDSAKeyMsg)
	}
	return out, nil
}

// Destroy zeroizes and releases the locked key.
func (s *SLHDSASigner) Destroy() { s.der.Destroy() }

// Sign signs message with SLH-DSA. The scheme hashes internally, so SignOptions is
// ignored. The private key is parsed transiently from the locked buffer.
//
// Lifetime (AN-4/AN-8): the parse and the signature both run inside s.der.Use, so a
// concurrent Destroy waits for the signature rather than wiping and unmapping the locked
// region under it; a Destroy that lands first refuses the borrow and this returns the
// destroyed-key error instead of signing with dead material.
func (s *SLHDSASigner) Sign(message []byte, _ SignOptions) ([]byte, error) {
	var sig []byte
	if err := s.der.Use(func(der []byte) error {
		// Test-only seam (nil in production): parks a signature INSIDE the borrow so a test
		// can prove a concurrent Destroy waits instead of freeing the region here.
		if borrowObserver != nil {
			borrowObserver()
		}
		id, err := slhdsaID(s.algorithm)
		if err != nil {
			return err
		}
		var priv slhdsa.PrivateKey
		priv.ID = id
		if err := priv.UnmarshalBinary(der); err != nil {
			return fmt.Errorf("crypto: parse SLH-DSA key: %w", err)
		}
		defer crypto.WipeBinaryPrivateKey(&priv)
		if slhdsaPrivateKeyObserver != nil {
			slhdsaPrivateKeyObserver(&priv)
		}
		out, err := priv.Sign(rand.Reader, message, nil)
		if err != nil {
			return fmt.Errorf("crypto: SLH-DSA sign: %w", err)
		}
		sig = out
		return nil
	}); err != nil {
		return nil, destroyedKeyError(err, destroyedSLHDSAKeyMsg)
	}
	return sig, nil
}

// SignDigest lets an SLH-DSA key satisfy DigestSigner. SLH-DSA hashes internally,
// so it signs the supplied digest bytes directly.
func (s *SLHDSASigner) SignDigest(digest []byte, opts SignOptions) ([]byte, error) {
	return s.Sign(digest, opts)
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

// slhdsaPrivateKeyObserver is a test-only hook (nil in production) used by
// residue tests to capture transient SLH-DSA private-key objects and verify they
// are wiped after constructors/signing return.
var slhdsaPrivateKeyObserver func(*slhdsa.PrivateKey)
