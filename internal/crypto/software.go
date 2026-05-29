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
)

// SoftwareBackend generates and uses keys with the Go standard library. It is
// the default KeyGenerator; the private key lives in process memory.
type SoftwareBackend struct{}

// NewSoftwareBackend returns a software (stdlib) crypto backend.
func NewSoftwareBackend() *SoftwareBackend { return &SoftwareBackend{} }

// Name identifies the backend, for diagnostics.
func (*SoftwareBackend) Name() string { return "software" }

// GenerateKey implements KeyGenerator for RSA and ECDSA.
func (*SoftwareBackend) GenerateKey(algorithm Algorithm) (Signer, error) {
	switch algorithm {
	case RSA2048, RSA3072, RSA4096:
		key, err := rsa.GenerateKey(rand.Reader, rsaBits(algorithm))
		if err != nil {
			return nil, fmt.Errorf("generate %s: %w", algorithm, err)
		}
		return &softwareSigner{algorithm: algorithm, key: key}, nil
	case ECDSAP256, ECDSAP384, ECDSAP521:
		key, err := ecdsa.GenerateKey(ecdsaCurve(algorithm), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate %s: %w", algorithm, err)
		}
		return &softwareSigner{algorithm: algorithm, key: key}, nil
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
	h, digest, err := hashMessage(opts.Hash, message)
	if err != nil {
		return nil, err
	}
	switch key := s.key.(type) {
	case *rsa.PrivateKey:
		switch opts.RSAPadding {
		case "", RSAPKCS1v15:
			return rsa.SignPKCS1v15(rand.Reader, key, h, digest)
		case RSAPSS:
			return rsa.SignPSS(rand.Reader, key, h, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h})
		default:
			return nil, fmt.Errorf("unsupported RSA padding %q", opts.RSAPadding)
		}
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, key, digest)
	default:
		return nil, fmt.Errorf("unsupported key type %T", s.key)
	}
}

// Verify checks signature over message using pub. It is backend-independent
// (public-key math only), so callers verify without touching a private key or a
// specific backend.
func Verify(pub PublicKey, message, signature []byte, opts SignOptions) error {
	h, digest, err := hashMessage(opts.Hash, message)
	if err != nil {
		return err
	}
	parsed, err := x509.ParsePKIXPublicKey(pub.DER)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	switch key := parsed.(type) {
	case *rsa.PublicKey:
		switch opts.RSAPadding {
		case "", RSAPKCS1v15:
			return rsa.VerifyPKCS1v15(key, h, digest, signature)
		case RSAPSS:
			return rsa.VerifyPSS(key, h, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h})
		default:
			return fmt.Errorf("unsupported RSA padding %q", opts.RSAPadding)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest, signature) {
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

// hashMessage returns the crypto.Hash id and the digest of message.
func hashMessage(h Hash, message []byte) (crypto.Hash, []byte, error) {
	ch, err := cryptoHash(h)
	if err != nil {
		return 0, nil, err
	}
	hasher := ch.New()
	if _, err := hasher.Write(message); err != nil {
		return 0, nil, err
	}
	return ch, hasher.Sum(nil), nil
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
