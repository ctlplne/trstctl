package transit

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

func TestTransitEncryptDecryptAcrossVersions(t *testing.T) {
	ctx := context.Background()
	rec := &auditsink.Recorder{}
	k := New("t1", rec)
	if err := k.CreateKey(ctx, "app", KindAEAD); err != nil {
		t.Fatal(err)
	}
	pt := []byte("classified")
	aad := []byte("ctx")
	ct1, err := k.Encrypt(ctx, "app", pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	// Rotate: a new version is now latest, but the old ciphertext must still decrypt.
	if _, err := k.Rotate(ctx, "app"); err != nil {
		t.Fatal(err)
	}
	got, err := k.Decrypt(ctx, "app", ct1, aad)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("decrypt v1 after rotation = %q (err %v)", got, err)
	}
	// Rewrap upgrades the ciphertext to the latest version, still decrypting.
	ct2, err := k.Rewrap(ctx, "app", ct1, aad)
	if err != nil {
		t.Fatal(err)
	}
	if ct2 == ct1 {
		t.Error("rewrap did not change the ciphertext")
	}
	got2, err := k.Decrypt(ctx, "app", ct2, aad)
	if err != nil || !bytes.Equal(got2, pt) {
		t.Fatalf("decrypt rewrapped = %q (err %v)", got2, err)
	}
	// AAD mismatch fails.
	if _, err := k.Decrypt(ctx, "app", ct2, []byte("wrong")); err == nil {
		t.Error("decrypt succeeded with wrong AAD")
	}
}

func TestTransitHMACAndSign(t *testing.T) {
	ctx := context.Background()
	k := New("t1", nil)
	_ = k.CreateKey(ctx, "mac", KindHMAC)
	m1, _ := k.HMAC(ctx, "mac", []byte("data"))
	m2, _ := k.HMAC(ctx, "mac", []byte("data"))
	if !bytes.Equal(m1, m2) {
		t.Error("HMAC not deterministic")
	}
	if m3, _ := k.HMAC(ctx, "mac", []byte("other")); bytes.Equal(m1, m3) {
		t.Error("HMAC collision on different input")
	}

	_ = k.CreateKey(ctx, "sig", KindSign)
	msg := []byte("sign me")
	sig, pub, err := k.Sign(ctx, "sig", msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Verify(ctx, msg, sig, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := k.Verify(ctx, []byte("tampered"), sig, pub); err == nil {
		t.Error("verify accepted a tampered message")
	}
}

func TestTransitKindMismatch(t *testing.T) {
	ctx := context.Background()
	k := New("t1", nil)
	_ = k.CreateKey(ctx, "mac", KindHMAC)
	if _, err := k.Encrypt(ctx, "mac", []byte("x"), nil); err == nil {
		t.Error("encrypt succeeded on an HMAC key")
	}
}
