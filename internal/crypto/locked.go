package crypto

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"runtime"

	"trstctl.com/trstctl/internal/crypto/secret"
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
	defer wipeStdlibKey(key)
	if generateLockedKeyObserver != nil {
		generateLockedKeyObserver(key)
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
	if newLockedSignerFromPKCS8Observer != nil {
		newLockedSignerFromPKCS8Observer(parsed)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		wipeStdlibKey(parsed)
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

// SignDigest signs digest with the locked private key, materializing the key in
// the clear only for the single signature and explicitly zeroizing it before
// return (SIGNER-008 / AN-8).
//
// The durable copy of the key is the mlock'd, MADV_DONTDUMP secret.Buffer in
// l.der; this method reads it, parses a transient standard-library key (whose
// secret scalars are big.Int words on the Go heap that the runtime, unlike the
// buffer, does not lock), signs, and then guarantees the transient key's secret
// scalars are zeroized before it becomes garbage. The wipe is ordered after the
// signature with an explicit call (not a bare defer that the compiler might treat
// as dead) and bracketed with runtime.KeepAlive so neither the key nor the wipe is
// optimized away. This shrinks the AN-8 residual to the smallest window Go allows
// — the key is unprotected only for the duration of one signature, then cleared —
// complementing the signer's process-wide RLIMIT_CORE=0 / PR_SET_DUMPABLE=0. Go
// cannot promise the runtime never copied the value mid-operation, so the
// eliminate-it-entirely fix remains HSM custody where the key never materializes
// here (EXC-CRYPTO-01).
func (l *LockedSigner) SignDigest(digest []byte, opts SignOptions) ([]byte, error) {
	der := l.der.Bytes()
	if der == nil {
		return nil, errors.New("crypto: locked key has been destroyed")
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	// Zeroize the transient key's secret scalars after we are done, and keep both
	// the key and its source buffer alive across the whole operation so the wipe is
	// not reordered before the sign or elided.
	defer func() {
		wipeStdlibKey(key)
		runtime.KeepAlive(key)
		runtime.KeepAlive(l.der)
	}()
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("crypto: parsed key %T is not a signer", key)
	}
	// Test-only seam (nil in production): hand the residue test a reference to the
	// transiently-parsed key so it can assert the secret scalars are zero AFTER this
	// method returns (i.e. after the deferred wipe runs). Verifies SIGNER-008.
	if signDigestKeyObserver != nil {
		signDigestKeyObserver(key)
	}
	return signDigest(signer, digest, opts)
}

// signDigestKeyObserver is a test-only hook (set via export_test.go) invoked with
// the transiently-parsed private key inside SignDigest. It is nil in production and
// has zero cost there. It exists so a test can hold the key reference and verify
// the post-Sign wipe zeroized its secret scalars.
var signDigestKeyObserver func(parsedKey any)

// generateLockedKeyObserver is a test-only hook (nil in production) that lets the
// constructor residue test capture the generated stdlib key and verify it is wiped
// after GenerateLockedKey returns.
var generateLockedKeyObserver func(generatedKey any)

// newLockedSignerFromPKCS8Observer is a test-only hook (nil in production) that
// lets BYOK residue tests capture the parsed key and verify it is wiped after
// NewLockedSignerFromPKCS8 returns.
var newLockedSignerFromPKCS8Observer func(parsedKey any)

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
