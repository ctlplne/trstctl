package ca

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// lockedKey custodies a CA's ECDSA signing private key inside a locked secret
// buffer (mlock + MADV_DONTDUMP + zeroized on Destroy, per AN-8). The unprotected
// standard-library *ecdsa.PrivateKey is reconstructed only for the moment of a
// single signing operation and then dropped — the same pattern crypto.LockedSigner
// uses — so the live, swappable, dumpable form of the highest-value key in the
// product lives in memory for milliseconds per signature rather than for the whole
// lifetime of the in-process CA (CRYPTO-005).
//
// The full custody story (the signer/HSM holding CA keys so they never materialize
// in the control-plane address space at all) is EXC-CRYPTO-01; this is the
// reference-path hardening that applies AN-8 to the live key in the meantime.
type lockedKey struct {
	der *secret.Buffer   // PKCS#8 DER of the private key, in locked memory
	pub *ecdsa.PublicKey // public half (not secret) kept for cert templates
}

// newLockedKey moves k's private material into a locked buffer and wipes the
// transient unlocked PKCS#8 copy. The caller's *ecdsa.PrivateKey should go out of
// scope promptly afterward; only the public key is retained in the clear.
func newLockedKey(k *ecdsa.PrivateKey) (*lockedKey, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, fmt.Errorf("ca: marshal CA private key: %w", err)
	}
	buf, err := secret.NewFrom(der)
	secret.Wipe(der) // wipe the transient, unlocked copy regardless of error
	if err != nil {
		return nil, err
	}
	return &lockedKey{der: buf, pub: &k.PublicKey}, nil
}

// public returns the CA's public key for building certificate templates.
func (l *lockedKey) public() *ecdsa.PublicKey { return l.pub }

// sign parses the locked private key, hands it to fn for exactly one signing
// operation, and wipes the reconstructed key's secret scalar before returning so
// the unprotected copy does not outlive the call. fn must not retain the key.
func (l *lockedKey) sign(fn func(*ecdsa.PrivateKey) error) error {
	der := l.der.Bytes()
	if der == nil {
		return errors.New("ca: CA key has been destroyed")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return fmt.Errorf("ca: parse CA private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("ca: parsed CA key %T is not ECDSA", parsed)
	}
	// Best-effort zeroization of the transiently-parsed private scalar after the
	// signature. The big.Int words are the secret; clearing them shrinks the window
	// in which the live key sits in unprotected heap. Go offers no guarantee the
	// runtime did not already copy the value, so this is defense-in-depth on top of
	// the process-wide RLIMIT_CORE=0 / PR_SET_DUMPABLE=0 the signer sets (CRYPTO-005,
	// shares the residual with SIGNER-008).
	defer wipeECDSA(key)
	return fn(key)
}

// destroy zeroizes and releases the locked key. It is idempotent.
func (l *lockedKey) destroy() {
	if l.der != nil {
		l.der.Destroy()
	}
}

// wipeECDSA zeroes the secret scalar D of a parsed ECDSA private key. It cannot
// reach copies the runtime may have made, but it clears the value this code holds.
func wipeECDSA(k *ecdsa.PrivateKey) {
	if k == nil || k.D == nil {
		return
	}
	words := k.D.Bits()
	for i := range words {
		words[i] = 0
	}
	k.D.SetInt64(0)
}
