// SPDX-License-Identifier: BUSL-1.1

package seal

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// CR-220: dynamic-secret principal names are derived digests, so the derivation
// is pinned by a known answer (computed independently with RFC 5869 HKDF-SHA256
// and HMAC-SHA256): changing it renames every principal and must be a
// deliberate, reviewed break.
func TestDerivedDigestIsAPurposeBoundKeyedDigest(t *testing.T) {
	kek, err := NewLocalKEK(bytes.Repeat([]byte{0x61}, kekSize))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kek.Destroy)
	material := []byte("known-answer material")

	got, err := kek.DerivedDigest([]byte("trstctl.dynsecret.principal-name.v1"), material)
	if err != nil {
		t.Fatal(err)
	}
	if want := "079f30cca1593704aedaf2e7733d733717c33e3f1ff882b52f404bedcae51be9"; hex.EncodeToString(got) != want {
		t.Fatalf("DerivedDigest known answer = %x, want %s", got, want)
	}
	other, err := kek.DerivedDigest([]byte("another purpose"), material)
	if err != nil {
		t.Fatal(err)
	}
	if want := "01bb1f2cda4b850b2e29bd8847331eb5748fb69ac393ef697345262d30b8e707"; hex.EncodeToString(other) != want {
		t.Fatalf("another label's known answer = %x, want %s", other, want)
	}
	again, err := kek.DerivedDigest([]byte("trstctl.dynsecret.principal-name.v1"), material)
	if err != nil || !bytes.Equal(again, got) {
		t.Fatalf("DerivedDigest is not deterministic: %x then %x (%v)", got, again, err)
	}
	keyed, err := kek.KeyedDigest([]byte("trstctl.dynsecret.principal-name.v1"), material)
	if err != nil || bytes.Equal(keyed, got) {
		t.Fatalf("DerivedDigest must not equal KeyedDigest under the same name (%v)", err)
	}
	if _, err := kek.DerivedDigest(nil, material); err == nil {
		t.Fatal("DerivedDigest accepted an empty label")
	}
}
