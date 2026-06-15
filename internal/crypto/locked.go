package crypto

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"trustctl.io/trustctl/internal/crypto/secret"
)

// LockedSigner holds its private key as PKCS#8 DER inside a locked secret buffer
// (mlock + MADV_DONTDUMP + zeroized on Destroy, per AN-8). The key is parsed
// into a transient standard-library value only for the moment of each
// signature, so the unprotected form of the key lives in memory for
// milliseconds at most. It implements DigestSigner.
type LockedSigner struct {
	algorithm Algorithm
	public    PublicKey
	der       *secret.Buffer
}

// GenerateLockedKey generates a new key and stores its private material in a
// locked secret buffer.
func GenerateLockedKey(algorithm Algorithm) (*LockedSigner, error) {
	key, err := generateStdlibKey(algorithm)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	buf, err := secret.NewFrom(der)
	secret.Wipe(der) // wipe the transient, unlocked copy
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		buf.Destroy()
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return &LockedSigner{
		algorithm: algorithm,
		public:    PublicKey{Algorithm: algorithm, DER: pubDER},
		der:       buf,
	}, nil
}

// NewLockedSignerFromPKCS8 is the bring-your-own-key (BYOK) import constructor: it
// takes an operator-supplied private key as PKCS#8 DER ([]byte, never a string —
// AN-8) and the algorithm it implements, validates that the bytes parse to a
// supported signer of that algorithm, and stores the material in a locked secret
// buffer exactly as GenerateLockedKey does for a freshly minted key. The der slice
// is NOT wiped here (the caller owns it and may need to retry); callers that want
// it gone should secret.Wipe it after this returns. It exists so an externally
// generated CA/issuing key can be custodied under the same locked-buffer, parse-
// per-signature discipline as a generated one (EXC-CRYPTO-01 / CRYPTO-005).
func NewLockedSignerFromPKCS8(algorithm Algorithm, der []byte) (*LockedSigner, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("byok: parse PKCS#8 private key: %w", err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("byok: imported key %T is not a signer", parsed)
	}
	// Confirm the supplied algorithm matches the key the bytes actually encode, so a
	// caller cannot mislabel (e.g. import an RSA key as ECDSA-P256) and have the
	// mislabel propagate into the signer's reported Algorithm/public key.
	if got := classifyStdlibKey(signer); got != algorithm {
		// Best-effort wipe the transiently-parsed key before refusing.
		wipeStdlibKey(parsed)
		return nil, fmt.Errorf("byok: imported key is %s, not the declared %s", got, algorithm)
	}
	buf, err := secret.NewFrom(der)
	if err != nil {
		wipeStdlibKey(parsed)
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		buf.Destroy()
		wipeStdlibKey(parsed)
		return nil, fmt.Errorf("byok: marshal public key: %w", err)
	}
	wipeStdlibKey(parsed) // the locked buffer now holds the only copy we keep
	return &LockedSigner{
		algorithm: algorithm,
		public:    PublicKey{Algorithm: algorithm, DER: pubDER},
		der:       buf,
	}, nil
}

// Algorithm reports the key's algorithm.
func (l *LockedSigner) Algorithm() Algorithm { return l.algorithm }

// Public returns the public key.
func (l *LockedSigner) Public() PublicKey { return l.public }

// SignDigest parses the locked private key, signs digest, and lets the parsed key
// go out of scope immediately. The transiently-parsed standard-library key is
// best-effort zeroized before return (wipeStdlibKey) so the unprotected copy does
// not outlive the single signature — narrowing the AN-8 residual window the design
// documents (SIGNER-008). Go offers no guarantee the runtime did not already copy
// the value, so this is defense-in-depth on top of the signer's process-wide
// RLIMIT_CORE=0 / PR_SET_DUMPABLE=0; the durable fix is HSM custody (EXC-CRYPTO-01).
func (l *LockedSigner) SignDigest(digest []byte, opts SignOptions) ([]byte, error) {
	der := l.der.Bytes()
	if der == nil {
		return nil, errors.New("crypto: locked key has been destroyed")
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	defer wipeStdlibKey(key)
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("crypto: parsed key %T is not a signer", key)
	}
	return signDigest(signer, digest, opts)
}

// Destroy zeroizes and releases the locked key. It is idempotent.
func (l *LockedSigner) Destroy() { l.der.Destroy() }

// GeneratePKCS8 generates a fresh private key for the algorithm and returns it as
// PKCS#8 DER ([]byte, never a string — AN-8). It is the boundary primitive for the
// generate-then-export on-ramp: an operator who wants to escrow or re-import a key
// (true BYOK) obtains the bytes here, behind the AN-3 boundary, rather than any
// caller importing crypto/x509 to marshal a key itself. The caller owns the
// returned slice and MUST secret.Wipe it once it is sealed/handed off, since it is
// the unprotected private key.
func GeneratePKCS8(algorithm Algorithm) ([]byte, error) {
	key, err := generateStdlibKey(algorithm)
	if err != nil {
		return nil, err
	}
	defer wipeStdlibKey(key)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return der, nil
}
