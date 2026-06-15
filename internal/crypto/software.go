package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // register SHA-256
	_ "crypto/sha512" // register SHA-384 and SHA-512
	"crypto/x509"
	"fmt"
	"math/big"
)

// SoftwareBackend generates and uses keys with the Go standard library. It is
// the default KeyGenerator; the private key lives in process memory.
type SoftwareBackend struct{}

// NewSoftwareBackend returns a software (stdlib) crypto backend.
func NewSoftwareBackend() *SoftwareBackend { return &SoftwareBackend{} }

// RandomBytes returns n cryptographically-secure random bytes. It lets callers
// outside the boundary obtain randomness (e.g. for opaque identifiers) without
// importing crypto/rand (AN-3).
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Name identifies the backend, for diagnostics.
func (*SoftwareBackend) Name() string { return "software" }

// GenerateKey implements KeyGenerator for RSA and ECDSA.
func (*SoftwareBackend) GenerateKey(algorithm Algorithm) (Signer, error) {
	key, err := generateStdlibKey(algorithm)
	if err != nil {
		return nil, err
	}
	return &softwareSigner{algorithm: algorithm, key: key}, nil
}

// generateStdlibKey generates a standard-library private key for the algorithm.
func generateStdlibKey(algorithm Algorithm) (crypto.Signer, error) {
	switch algorithm {
	case RSA2048, RSA3072, RSA4096:
		key, err := rsa.GenerateKey(rand.Reader, rsaBits(algorithm))
		if err != nil {
			return nil, fmt.Errorf("generate %s: %w", algorithm, err)
		}
		return key, nil
	case ECDSAP256, ECDSAP384, ECDSAP521:
		key, err := ecdsa.GenerateKey(ecdsaCurve(algorithm), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate %s: %w", algorithm, err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", algorithm)
	}
}

// softwareSigner is a stdlib-backed Signer. key is a crypto.Signer
// (*rsa.PrivateKey or *ecdsa.PrivateKey).
type softwareSigner struct {
	algorithm Algorithm
	key       crypto.Signer
}

func (s *softwareSigner) Algorithm() Algorithm { return s.algorithm }

func (s *softwareSigner) Public() PublicKey {
	der, _ := x509.MarshalPKIXPublicKey(s.key.Public())
	return PublicKey{Algorithm: s.algorithm, DER: der}
}

func (s *softwareSigner) Sign(message []byte, opts SignOptions) ([]byte, error) {
	digest, err := Digest(opts.Hash, message)
	if err != nil {
		return nil, err
	}
	return signDigest(s.key, digest, opts)
}

// Digest hashes data with the given hash algorithm. It exists so callers that
// must sign or verify a pre-computed digest can produce one without importing a
// standard-library crypto package (AN-3).
func Digest(h Hash, data []byte) ([]byte, error) {
	ch, err := cryptoHash(h)
	if err != nil {
		return nil, err
	}
	hasher := ch.New()
	if _, err := hasher.Write(data); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

// classifyStdlibKey maps a parsed standard-library private key to the trustctl
// Algorithm it implements, by key type and parameter size/curve. It returns the
// empty Algorithm for a key it does not recognize. It backs the BYOK import path
// (NewLockedSignerFromPKCS8), which uses it to reject a mislabeled key — a caller
// declaring ECDSA-P256 while importing an RSA key, say — before the mislabel can
// propagate into the signer's reported algorithm or public key.
func classifyStdlibKey(signer crypto.Signer) Algorithm {
	switch k := signer.(type) {
	case *rsa.PrivateKey:
		switch k.N.BitLen() {
		case 2048:
			return RSA2048
		case 3072:
			return RSA3072
		case 4096:
			return RSA4096
		}
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return ECDSAP256
		case elliptic.P384():
			return ECDSAP384
		case elliptic.P521():
			return ECDSAP521
		}
	}
	return ""
}

// wipeStdlibKey best-effort zeroizes the secret scalars of a transiently-parsed
// standard-library private key (SIGNER-008). For ECDSA that is D; for RSA it is D
// and the prime factors / CRT values. It cannot reach copies the runtime may have
// made (Go gives no such guarantee), so it is defense-in-depth that shrinks the
// window in which the unprotected key sits in dumpable heap, complementing the
// signer's process-wide core-dump suppression. The durable fix is HSM custody so
// the key never materializes here at all (EXC-CRYPTO-01).
func wipeStdlibKey(key any) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if k != nil {
			zeroBigInt(k.D)
		}
	case *rsa.PrivateKey:
		if k == nil {
			return
		}
		zeroBigInt(k.D)
		for i := range k.Primes {
			zeroBigInt(k.Primes[i])
		}
		zeroBigInt(k.Precomputed.Dp)
		zeroBigInt(k.Precomputed.Dq)
		zeroBigInt(k.Precomputed.Qinv)
	}
}

// zeroBigInt clears the words backing a *big.Int and sets it to zero.
func zeroBigInt(n *big.Int) {
	if n == nil {
		return
	}
	w := n.Bits()
	for i := range w {
		w[i] = 0
	}
	n.SetInt64(0)
}

// signDigest signs a pre-computed digest with a standard-library private key.
func signDigest(key crypto.Signer, digest []byte, opts SignOptions) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		ch, err := cryptoHash(opts.Hash)
		if err != nil {
			return nil, err
		}
		switch opts.RSAPadding {
		case "", RSAPKCS1v15:
			return rsa.SignPKCS1v15(rand.Reader, k, ch, digest)
		case RSAPSS:
			return rsa.SignPSS(rand.Reader, k, ch, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: ch})
		default:
			return nil, fmt.Errorf("unsupported RSA padding %q", opts.RSAPadding)
		}
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, k, digest)
	default:
		return nil, fmt.Errorf("unsupported key type %T", key)
	}
}

// Verify checks a signature over message using pub. It is backend-independent
// (public-key math only), so callers verify without touching a private key or a
// specific backend.
func Verify(pub PublicKey, message, signature []byte, opts SignOptions) error {
	digest, err := Digest(opts.Hash, message)
	if err != nil {
		return err
	}
	return VerifyDigest(pub, digest, signature, opts)
}

// VerifyDigest checks a signature over a pre-computed digest.
func VerifyDigest(pub PublicKey, digest, signature []byte, opts SignOptions) error {
	parsed, err := x509.ParsePKIXPublicKey(pub.DER)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	switch k := parsed.(type) {
	case *rsa.PublicKey:
		ch, err := cryptoHash(opts.Hash)
		if err != nil {
			return err
		}
		switch opts.RSAPadding {
		case "", RSAPKCS1v15:
			return rsa.VerifyPKCS1v15(k, ch, digest, signature)
		case RSAPSS:
			return rsa.VerifyPSS(k, ch, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: ch})
		default:
			return fmt.Errorf("unsupported RSA padding %q", opts.RSAPadding)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest, signature) {
			return fmt.Errorf("ecdsa: signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type %T", parsed)
	}
}

func rsaBits(a Algorithm) int {
	switch a {
	case RSA2048:
		return 2048
	case RSA3072:
		return 3072
	case RSA4096:
		return 4096
	default:
		return 0
	}
}

func ecdsaCurve(a Algorithm) elliptic.Curve {
	switch a {
	case ECDSAP256:
		return elliptic.P256()
	case ECDSAP384:
		return elliptic.P384()
	case ECDSAP521:
		return elliptic.P521()
	default:
		return nil
	}
}

func cryptoHash(h Hash) (crypto.Hash, error) {
	switch h {
	case "", SHA256:
		return crypto.SHA256, nil
	case SHA384:
		return crypto.SHA384, nil
	case SHA512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash %q", h)
	}
}
