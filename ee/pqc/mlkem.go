// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqc

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func kemSchemeFor(a crypto.Algorithm) (kem.Scheme, bool) {
	switch a {
	case MLKEM512:
		return mlkem512.Scheme(), true
	case MLKEM768:
		return mlkem768.Scheme(), true
	case MLKEM1024:
		return mlkem1024.Scheme(), true
	default:
		return nil, false
	}
}

// KEMPrivateKey is an ML-KEM private key handle. The durable private bytes live
// in locked memory; parsed CIRCL keys exist only during construction or
// decapsulation and are wiped on return. This follows the same prior-art
// compile-time interface pattern as crypto.Signer/JCA/PKCS#11 handles: callers
// pass an algorithm and a key handle, not a runtime-loaded crypto engine.
type KEMPrivateKey struct {
	algorithm crypto.Algorithm
	scheme    kem.Scheme
	public    crypto.PublicKey
	priv      *secret.Buffer
}

// GenerateKEMKey creates a fresh ML-KEM-512/768/1024 key pair.
func GenerateKEMKey(algorithm crypto.Algorithm) (*KEMPrivateKey, error) {
	scheme, ok := kemSchemeFor(algorithm)
	if !ok {
		return nil, fmt.Errorf("pqc: unsupported ML-KEM algorithm %q", algorithm)
	}
	pub, priv, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	defer wipeKEMPrivateKey(priv)
	return newKEMPrivateKeyFromCIRCL(algorithm, scheme, pub, priv)
}

// DeriveKEMKey derives an ML-KEM key pair from a FIPS 203 seed. Production
// callers should normally use GenerateKEMKey; this exists for deterministic KATs
// and controlled fixtures.
func DeriveKEMKey(algorithm crypto.Algorithm, seed []byte) (*KEMPrivateKey, error) {
	scheme, ok := kemSchemeFor(algorithm)
	if !ok {
		return nil, fmt.Errorf("pqc: unsupported ML-KEM algorithm %q", algorithm)
	}
	if len(seed) != scheme.SeedSize() {
		return nil, fmt.Errorf("pqc: %s key seed has length %d, want %d", algorithm, len(seed), scheme.SeedSize())
	}
	pub, priv := scheme.DeriveKeyPair(seed)
	defer wipeKEMPrivateKey(priv)
	return newKEMPrivateKeyFromCIRCL(algorithm, scheme, pub, priv)
}

// NewKEMPrivateKey reconstructs an ML-KEM private-key handle from CIRCL-marshaled
// private bytes. The bytes are copied into locked memory; the caller keeps
// ownership of privateKey and should wipe it after loading.
func NewKEMPrivateKey(algorithm crypto.Algorithm, privateKey []byte) (*KEMPrivateKey, error) {
	scheme, ok := kemSchemeFor(algorithm)
	if !ok {
		return nil, fmt.Errorf("pqc: unsupported ML-KEM algorithm %q", algorithm)
	}
	priv, err := scheme.UnmarshalBinaryPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("pqc: parse ML-KEM private key: %w", err)
	}
	defer wipeKEMPrivateKey(priv)
	pub := priv.Public()
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("pqc: marshal ML-KEM public key: %w", err)
	}
	buf, err := secret.NewFrom(privateKey)
	if err != nil {
		return nil, err
	}
	return &KEMPrivateKey{
		algorithm: algorithm,
		scheme:    scheme,
		public:    crypto.PublicKey{Algorithm: algorithm, DER: pubBytes},
		priv:      buf,
	}, nil
}

func newKEMPrivateKeyFromCIRCL(algorithm crypto.Algorithm, scheme kem.Scheme, pub kem.PublicKey, priv kem.PrivateKey) (*KEMPrivateKey, error) {
	privateBytes, err := priv.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("pqc: marshal ML-KEM private key: %w", err)
	}
	buf, err := secret.NewFrom(privateBytes)
	secret.Wipe(privateBytes)
	if err != nil {
		return nil, err
	}
	publicBytes, err := pub.MarshalBinary()
	if err != nil {
		buf.Destroy()
		return nil, fmt.Errorf("pqc: marshal ML-KEM public key: %w", err)
	}
	return &KEMPrivateKey{
		algorithm: algorithm,
		scheme:    scheme,
		public:    crypto.PublicKey{Algorithm: algorithm, DER: publicBytes},
		priv:      buf,
	}, nil
}

// Algorithm reports the key's algorithm.
func (k *KEMPrivateKey) Algorithm() crypto.Algorithm { return k.algorithm }

// Public returns the encapsulation public key.
func (k *KEMPrivateKey) Public() crypto.PublicKey { return k.public }

// PrivateKeyBytes returns a copy of the CIRCL-marshaled private key for sealed
// persistence and deterministic tests. The returned bytes are unprotected
// memory; callers must wipe them promptly after use.
func (k *KEMPrivateKey) PrivateKeyBytes() ([]byte, error) {
	sk := k.priv.Bytes()
	if sk == nil {
		return nil, errors.New("pqc: ML-KEM private key has been destroyed")
	}
	out := make([]byte, len(sk))
	copy(out, sk)
	return out, nil
}

// Decapsulate opens ciphertext with the private key and returns the shared
// secret. The returned shared secret is secret material in ordinary memory;
// callers that keep it beyond immediate protocol use must wrap or wipe it.
func (k *KEMPrivateKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	sk := k.priv.Bytes()
	if sk == nil {
		return nil, errors.New("pqc: ML-KEM private key has been destroyed")
	}
	priv, err := k.scheme.UnmarshalBinaryPrivateKey(sk)
	if err != nil {
		return nil, fmt.Errorf("pqc: parse ML-KEM private key: %w", err)
	}
	defer wipeKEMPrivateKey(priv)
	ss, err := k.scheme.Decapsulate(priv, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("pqc: decapsulate ML-KEM ciphertext: %w", err)
	}
	return ss, nil
}

// Destroy zeroizes and releases the locked private key. It is idempotent.
func (k *KEMPrivateKey) Destroy() {
	if k == nil || k.priv == nil {
		return
	}
	k.priv.Destroy()
}

// Encapsulate generates a ciphertext and shared secret for an ML-KEM public key.
// It accepts only trstctl's crypto.PublicKey boundary type, so no CIRCL or
// standard-library crypto type leaks to callers.
func Encapsulate(pub crypto.PublicKey) (ciphertext, sharedSecret []byte, err error) {
	scheme, pk, err := unmarshalKEMPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	ct, ss, err := scheme.Encapsulate(pk)
	if err != nil {
		return nil, nil, fmt.Errorf("pqc: encapsulate ML-KEM public key: %w", err)
	}
	return ct, ss, nil
}

// EncapsulateDeterministically is the FIPS 203 KAT path. Production protocol
// code should use Encapsulate so the encapsulation seed comes from CSPRNG.
func EncapsulateDeterministically(pub crypto.PublicKey, seed []byte) (ciphertext, sharedSecret []byte, err error) {
	scheme, pk, err := unmarshalKEMPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	if len(seed) != scheme.EncapsulationSeedSize() {
		return nil, nil, fmt.Errorf("pqc: %s encapsulation seed has length %d, want %d", pub.Algorithm, len(seed), scheme.EncapsulationSeedSize())
	}
	ct, ss, err := scheme.EncapsulateDeterministically(pk, seed)
	if err != nil {
		return nil, nil, fmt.Errorf("pqc: deterministic ML-KEM encapsulation: %w", err)
	}
	return ct, ss, nil
}

func unmarshalKEMPublicKey(pub crypto.PublicKey) (kem.Scheme, kem.PublicKey, error) {
	scheme, ok := kemSchemeFor(pub.Algorithm)
	if !ok {
		return nil, nil, fmt.Errorf("pqc: unsupported ML-KEM algorithm %q", pub.Algorithm)
	}
	pk, err := scheme.UnmarshalBinaryPublicKey(pub.DER)
	if err != nil {
		return nil, nil, fmt.Errorf("pqc: parse ML-KEM public key: %w", err)
	}
	return scheme, pk, nil
}

func wipeKEMPrivateKey(key kem.PrivateKey) {
	if key == nil {
		return
	}
	encoded, err := key.MarshalBinary()
	if err != nil {
		runtime.KeepAlive(key)
		return
	}
	secret.Wipe(encoded)
	if unpackable, ok := key.(interface{ Unpack([]byte) error }); ok {
		_ = unpackable.Unpack(encoded)
	}
	secret.Wipe(encoded)
	runtime.KeepAlive(key)
}
