// SPDX-License-Identifier: BUSL-1.1

//go:build cgo

package pkcs11

import (
	"encoding/binary"
	"testing"

	p11 "github.com/miekg/pkcs11"
)

// A123: only a 32-byte key that is sensitive, not extractable, and allowed to
// both encrypt and decrypt may wrap a tenant domain KEK.
func TestSecretKeyPolicyNeedsASensitiveNonExtractableAES256Key(t *testing.T) {
	ulong := func(v uint64) []byte {
		b := make([]byte, 8)
		binary.NativeEndian.PutUint64(b, v)
		return b
	}
	flag := func(on bool) []byte {
		if on {
			return []byte{1}
		}
		return []byte{0}
	}
	attrs := func(length uint64, sensitive, extractable, encrypt, decrypt bool) []*p11.Attribute {
		return []*p11.Attribute{
			{Type: p11.CKA_VALUE_LEN, Value: ulong(length)},
			{Type: p11.CKA_SENSITIVE, Value: flag(sensitive)},
			{Type: p11.CKA_EXTRACTABLE, Value: flag(extractable)},
			{Type: p11.CKA_ENCRYPT, Value: flag(encrypt)},
			{Type: p11.CKA_DECRYPT, Value: flag(decrypt)},
		}
	}
	if !secretKeyPolicyHolds(attrs(32, true, false, true, true)) {
		t.Fatal("a sensitive, non-extractable AES-256 key was refused")
	}
	for name, bad := range map[string][]*p11.Attribute{
		"AES-128":        attrs(16, true, false, true, true),
		"not sensitive":  attrs(32, false, false, true, true),
		"extractable":    attrs(32, true, true, true, true),
		"cannot encrypt": attrs(32, true, false, false, true),
		"cannot decrypt": attrs(32, true, false, true, false),
		"missing flag":   attrs(32, true, false, true, true)[:4],
		"short ulong":    {{Type: p11.CKA_VALUE_LEN, Value: []byte{32}}},
	} {
		if secretKeyPolicyHolds(bad) {
			t.Errorf("%s key was accepted", name)
		}
	}
}
