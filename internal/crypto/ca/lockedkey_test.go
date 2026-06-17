package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"reflect"
	"testing"
	"time"
)

// TestCAKeyIsLockedNotBareECDSA guards CRYPTO-005: the live CA signing key must be
// custodied in a locked secret buffer (AN-8), not stored as a bare
// *ecdsa.PrivateKey on the Go heap for the CA's whole lifetime. A regression that
// reverts CA.key / Authority.key to *ecdsa.PrivateKey fails here.
func TestCAKeyIsLockedNotBareECDSA(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  reflect.Type
	}{
		{"CA", reflect.TypeOf(CA{})},
		{"Authority", reflect.TypeOf(Authority{})},
	} {
		f, ok := tc.typ.FieldByName("key")
		if !ok {
			t.Fatalf("%s has no key field", tc.name)
		}
		if f.Type == reflect.TypeOf((*ecdsa.PrivateKey)(nil)) {
			t.Errorf("%s.key is a bare *ecdsa.PrivateKey; CA keys must live in a locked secret buffer (AN-8/CRYPTO-005)", tc.name)
		}
		if got := f.Type.String(); got != "*ca.lockedKey" {
			t.Errorf("%s.key type = %s, want *ca.lockedKey (the AN-8 locked-buffer custodian)", tc.name, got)
		}
	}
}

// TestLockedKeySignsAndDestroys exercises the locked-key signing path and its
// fail-closed behavior after destruction.
func TestLockedKeySignsAndDestroys(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lk, err := newLockedKey(k)
	if err != nil {
		t.Fatalf("newLockedKey: %v", err)
	}
	// public() returns the public half for templates.
	if lk.public() == nil || !lk.public().Equal(&k.PublicKey) {
		t.Fatal("locked key public() must equal the source public key")
	}
	// sign reconstructs the private key for exactly one operation.
	signed := false
	if err := lk.sign(func(priv *ecdsa.PrivateKey) error {
		if priv == nil || priv.D == nil {
			t.Fatal("sign handed a nil/empty private key")
		}
		signed = true
		return nil
	}); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !signed {
		t.Fatal("sign did not invoke the callback")
	}
	// After destroy, signing must fail closed (no key material to parse).
	lk.destroy()
	lk.destroy() // idempotent
	if err := lk.sign(func(*ecdsa.PrivateKey) error { return nil }); err == nil {
		t.Error("sign succeeded after destroy; a destroyed locked key must fail closed")
	}
}

func TestNewLockedKeyZeroizesSourcePrivateScalar(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var captured *ecdsa.PrivateKey
	prev := newLockedKeyObserver
	newLockedKeyObserver = func(k *ecdsa.PrivateKey) { captured = k }
	defer func() { newLockedKeyObserver = prev }()

	lk, err := newLockedKey(k)
	if err != nil {
		t.Fatalf("newLockedKey: %v", err)
	}
	defer lk.destroy()
	if captured == nil {
		t.Fatal("observer was not called")
	}
	if captured.D.Sign() != 0 {
		t.Fatalf("source ECDSA private scalar still live after newLockedKey returned")
	}
	if lk.public() == nil {
		t.Fatal("locked key lost public key while wiping source private scalar")
	}
}

// TestCAHierarchyRoundTripsWithLockedKey is an end-to-end smoke over the locked-key
// path: a root signs an intermediate, the intermediate issues a leaf, and the root
// signs a CRL — all through the locked buffer.
func TestCAHierarchyRoundTripsWithLockedKey(t *testing.T) {
	root, err := NewRoot(CASpec{CommonName: "root", MaxPathLen: 1, TTL: time.Hour})
	if err != nil {
		t.Fatalf("NewRoot: %v", err)
	}
	defer root.Destroy()
	sub, err := root.CreateIntermediate(CASpec{CommonName: "sub", TTL: time.Hour})
	if err != nil {
		t.Fatalf("CreateIntermediate: %v", err)
	}
	defer sub.Destroy()
	if _, err := sub.IssueLeaf(leafCSR(t, "leaf", nil), time.Hour); err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	if _, err := root.CreateCRL(nil, 1, time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
}
