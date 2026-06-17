package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// PKCS8 returns a copy of the locked private key as PKCS#8 DER, for sealed
// persistence (R3.2: keys survive a signer restart). The returned slice is
// unprotected memory — the caller MUST seal it and wipe the copy promptly, so the
// key does not live unsealed for long.
func (l *LockedSigner) PKCS8() ([]byte, error) {
	der := l.der.Bytes()
	if der == nil {
		return nil, errors.New("crypto: locked key has been destroyed")
	}
	out := make([]byte, len(der))
	copy(out, der)
	return out, nil
}

// LockedKeyFromPKCS8 reconstructs a locked key from PKCS#8 DER — the inverse of
// PKCS8 — deriving the algorithm from the key. der is copied into locked memory;
// the caller should wipe its own copy.
func LockedKeyFromPKCS8(der []byte) (*LockedSigner, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse PKCS#8: %w", err)
	}
	defer wipeStdlibKey(key)
	if lockedKeyFromPKCS8Observer != nil {
		lockedKeyFromPKCS8Observer(key)
	}
	alg, err := algorithmOf(key)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("crypto: parsed key %T is not a signer", key)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal public key: %w", err)
	}
	buf, err := secret.NewFrom(der)
	if err != nil {
		return nil, err
	}
	return &LockedSigner{
		algorithm: alg,
		public:    PublicKey{Algorithm: alg, DER: pubDER},
		der:       buf,
	}, nil
}

// lockedKeyFromPKCS8Observer is a test-only hook (nil in production) that lets
// residue tests capture the parsed import key and verify it is wiped after
// LockedKeyFromPKCS8 returns.
var lockedKeyFromPKCS8Observer func(parsedKey any)

// algorithmOf maps a parsed private key to its trstctl Algorithm.
func algorithmOf(key any) (Algorithm, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		switch k.Curve.Params().Name {
		case "P-256":
			return ECDSAP256, nil
		case "P-384":
			return ECDSAP384, nil
		case "P-521":
			return ECDSAP521, nil
		}
		return "", fmt.Errorf("crypto: unsupported ECDSA curve %q", k.Curve.Params().Name)
	case *rsa.PrivateKey:
		switch k.N.BitLen() {
		case 2048:
			return RSA2048, nil
		case 3072:
			return RSA3072, nil
		case 4096:
			return RSA4096, nil
		}
		return "", fmt.Errorf("crypto: unsupported RSA size %d", k.N.BitLen())
	default:
		return "", fmt.Errorf("crypto: unsupported key type %T", key)
	}
}
