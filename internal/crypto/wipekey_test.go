package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
)

// TestWipeStdlibKeyZeroesSecretScalars guards SIGNER-008: the helper that wipes the
// transiently-parsed private key during LockedSigner.SignDigest must actually zero
// the secret scalars, so the unprotected copy is cleared before the parsed key is
// dropped. A regression that drops the wipe (or stops covering RSA's CRT values)
// fails here.
func TestWipeStdlibKeyZeroesSecretScalars(t *testing.T) {
	t.Run("ecdsa", func(t *testing.T) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		wipeStdlibKey(k)
		if k.D.Sign() != 0 {
			t.Errorf("ecdsa D not zeroed after wipe: %s", k.D)
		}
	})

	t.Run("rsa", func(t *testing.T) {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		wipeStdlibKey(k)
		if k.D.Sign() != 0 {
			t.Errorf("rsa D not zeroed: %s", k.D)
		}
		for i, p := range k.Primes {
			if p.Sign() != 0 {
				t.Errorf("rsa prime[%d] not zeroed: %s", i, p)
			}
		}
		for name, v := range map[string]*big.Int{
			"Dp":   k.Precomputed.Dp,
			"Dq":   k.Precomputed.Dq,
			"Qinv": k.Precomputed.Qinv,
		} {
			if v != nil && v.Sign() != 0 {
				t.Errorf("rsa precomputed %s not zeroed: %s", name, v)
			}
		}
	})

	// nil and unknown types must be no-ops, never panic.
	wipeStdlibKey(nil)
	wipeStdlibKey((*ecdsa.PrivateKey)(nil))
	wipeStdlibKey("not a key")
}

// TestSignDigestWipesParsedKeyAndStillSigns proves the wipe is wired into the
// signing path without breaking correctness: a LockedSigner still produces a
// verifiable signature even though each SignDigest now zeroizes the key it parsed.
func TestSignDigestWipesParsedKeyAndStillSigns(t *testing.T) {
	ls, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateLockedKey: %v", err)
	}
	defer ls.Destroy()
	msg := []byte("sign me")
	digest, err := Digest(SHA256, msg)
	if err != nil {
		t.Fatal(err)
	}
	// Two consecutive signatures must both succeed and verify — proving the wipe of
	// the first parse did not corrupt the locked source for the second.
	for i := 0; i < 2; i++ {
		sig, err := ls.SignDigest(digest, SignOptions{Hash: SHA256})
		if err != nil {
			t.Fatalf("SignDigest #%d: %v", i, err)
		}
		if err := VerifyDigest(ls.Public(), digest, sig, SignOptions{Hash: SHA256}); err != nil {
			t.Fatalf("VerifyDigest #%d: %v", i, err)
		}
	}
}

// TestSignDigestZeroizesTransientKeyAfterOp is the SIGNER-008 acceptance test: it
// captures the transiently-parsed private key via the in-package observer hook and
// asserts that, AFTER SignDigest returns (the deferred wipe has run), the secret
// scalars are zero. Pre-fix (no deferred wipe / no runtime.KeepAlive ordering) the
// parsed key's D would still hold the private scalar after the op — exactly the
// residual this finding names. The locked source buffer must remain usable, so a
// follow-up signature still verifies.
func TestSignDigestZeroizesTransientKeyAfterOp(t *testing.T) {
	for _, tc := range []struct {
		name string
		alg  Algorithm
	}{
		{"ecdsa", ECDSAP256},
		{"rsa", RSA2048},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ls, err := GenerateLockedKey(tc.alg)
			if err != nil {
				t.Fatalf("GenerateLockedKey: %v", err)
			}
			defer ls.Destroy()

			var captured any
			prev := signDigestKeyObserver
			signDigestKeyObserver = func(k any) { captured = k }
			defer func() { signDigestKeyObserver = prev }()

			digest, err := Digest(SHA256, []byte("zeroize me"))
			if err != nil {
				t.Fatal(err)
			}
			sig, err := ls.SignDigest(digest, SignOptions{Hash: SHA256})
			if err != nil {
				t.Fatalf("SignDigest: %v", err)
			}
			if err := VerifyDigest(ls.Public(), digest, sig, SignOptions{Hash: SHA256}); err != nil {
				t.Fatalf("signature did not verify: %v", err)
			}
			if captured == nil {
				t.Fatal("observer was not called — SignDigest did not materialize a key")
			}

			// After the op, the transient key's secret scalars must be zero.
			switch k := captured.(type) {
			case *ecdsa.PrivateKey:
				if k.D.Sign() != 0 {
					t.Errorf("ecdsa D not zeroized after SignDigest: %s", k.D)
				}
			case *rsa.PrivateKey:
				if k.D.Sign() != 0 {
					t.Errorf("rsa D not zeroized after SignDigest")
				}
				for i, p := range k.Primes {
					if p.Sign() != 0 {
						t.Errorf("rsa prime[%d] not zeroized after SignDigest", i)
					}
				}
			default:
				t.Fatalf("unexpected key type %T", captured)
			}

			// The locked source buffer is intact: another signature still works.
			if _, err := ls.SignDigest(digest, SignOptions{Hash: SHA256}); err != nil {
				t.Fatalf("locked key unusable after transient wipe: %v", err)
			}
		})
	}
}

func TestGenerateLockedKeyZeroizesGeneratedStdlibKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		alg  Algorithm
	}{
		{"ecdsa", ECDSAP256},
		{"rsa", RSA2048},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var captured any
			prev := generateLockedKeyObserver
			generateLockedKeyObserver = func(k any) { captured = k }
			defer func() { generateLockedKeyObserver = prev }()

			ls, err := GenerateLockedKey(tc.alg)
			if err != nil {
				t.Fatalf("GenerateLockedKey: %v", err)
			}
			defer ls.Destroy()
			assertStdlibPrivateKeyWiped(t, captured)
		})
	}
}

func TestPKCS8ImportConstructorsZeroizeParsedStdlibKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		alg  Algorithm
	}{
		{"ecdsa", ECDSAP256},
		{"rsa", RSA2048},
	} {
		t.Run("locked-key-from-pkcs8/"+tc.name, func(t *testing.T) {
			der, err := GeneratePKCS8(tc.alg)
			if err != nil {
				t.Fatalf("GeneratePKCS8: %v", err)
			}
			defer func() {
				for i := range der {
					der[i] = 0
				}
			}()

			var captured any
			prev := lockedKeyFromPKCS8Observer
			lockedKeyFromPKCS8Observer = func(k any) { captured = k }
			defer func() { lockedKeyFromPKCS8Observer = prev }()

			ls, err := LockedKeyFromPKCS8(der)
			if err != nil {
				t.Fatalf("LockedKeyFromPKCS8: %v", err)
			}
			defer ls.Destroy()
			assertStdlibPrivateKeyWiped(t, captured)
		})

		t.Run("new-locked-signer-from-pkcs8/"+tc.name, func(t *testing.T) {
			der, err := GeneratePKCS8(tc.alg)
			if err != nil {
				t.Fatalf("GeneratePKCS8: %v", err)
			}
			defer func() {
				for i := range der {
					der[i] = 0
				}
			}()

			var captured any
			prev := newLockedSignerFromPKCS8Observer
			newLockedSignerFromPKCS8Observer = func(k any) { captured = k }
			defer func() { newLockedSignerFromPKCS8Observer = prev }()

			ls, err := NewLockedSignerFromPKCS8(tc.alg, der)
			if err != nil {
				t.Fatalf("NewLockedSignerFromPKCS8: %v", err)
			}
			defer ls.Destroy()
			assertStdlibPrivateKeyWiped(t, captured)
		})
	}
}

func assertStdlibPrivateKeyWiped(t *testing.T, captured any) {
	t.Helper()
	if captured == nil {
		t.Fatal("observer was not called")
	}
	switch k := captured.(type) {
	case *ecdsa.PrivateKey:
		if k.D.Sign() != 0 {
			t.Fatalf("ecdsa D still live after constructor returned")
		}
	case *rsa.PrivateKey:
		if k.D.Sign() != 0 {
			t.Fatalf("rsa D still live after constructor returned")
		}
		for i, p := range k.Primes {
			if p.Sign() != 0 {
				t.Fatalf("rsa prime[%d] still live after constructor returned", i)
			}
		}
	default:
		t.Fatalf("unexpected captured key type %T", captured)
	}
}
