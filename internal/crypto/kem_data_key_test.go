// SPDX-License-Identifier: BUSL-1.1

package crypto_test

import (
	"bytes"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func TestKEMDataKeyEnvelopeRoundTripAndBinding(t *testing.T) {
	ss := bytes.Repeat([]byte{0x42}, 32)
	dek := []byte("0123456789abcdef0123456789abcdef")
	aad := []byte("trstctl/pcas/kem-data-key/v1|spiffe://x|3|backup:a")
	wrapped, err := crypto.KEMDataKeySeal(ss, dek, aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := crypto.KEMDataKeyOpen(ss, wrapped, aad)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("open: %v got=%x", err, got)
	}
	if _, err := crypto.KEMDataKeyOpen(ss, wrapped, []byte("trstctl/pcas/kem-data-key/v1|spiffe://x|4|backup:a")); err == nil {
		t.Fatal("an envelope bound to epoch 3 opened under epoch 4")
	}
	other := bytes.Repeat([]byte{0x43}, 32)
	if _, err := crypto.KEMDataKeyOpen(other, wrapped, aad); err == nil {
		t.Fatal("an envelope opened under a different shared secret")
	}
	if _, err := crypto.KEMDataKeySeal(ss, bytes.Repeat([]byte{1}, crypto.MaxKEMDataKeyBytes+1), aad); err == nil {
		t.Fatal("a data key over the size bound was sealed")
	}
	if _, err := crypto.KEMDataKeySeal([]byte("short"), dek, aad); err == nil {
		t.Fatal("a short shared secret derived a key")
	}
}
