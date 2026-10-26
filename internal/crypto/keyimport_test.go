// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"errors"
	"testing"
)

// A128: an operator's private key sealed to the signer's one-time import key
// opens only under that key and the exact binding (tenant, operation, expected
// public key); a rebuilt key from the persisted seed opens it too; tampering,
// another key, another binding and a destroyed key are all refused.
func TestKeyImportSealOpensOnlyUnderItsKeyAndBinding(t *testing.T) {
	key, err := GenerateKeyImportKey()
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := GeneratePKCS8(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	spki := []byte("expected public key")
	info := KeyImportInfo("tenant-a", "ceremony-1", spki)
	sealed, err := SealKeyImport(key.Public(), info, pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, pkcs8) {
		t.Fatal("the sealed key carries the plaintext")
	}
	opened, err := key.Open(info, sealed)
	if err != nil || !bytes.Equal(opened, pkcs8) {
		t.Fatalf("open = %v, equal=%v", err, bytes.Equal(opened, pkcs8))
	}

	seed, err := key.Seed()
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := NewKeyImportKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rebuilt.Public(), key.Public()) {
		t.Fatal("a key rebuilt from its seed has a different public half")
	}
	if opened, err := rebuilt.Open(info, sealed); err != nil || !bytes.Equal(opened, pkcs8) {
		t.Fatalf("rebuilt key open = %v", err)
	}

	other, err := GenerateKeyImportKey()
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0x01
	for name, attempt := range map[string]func() ([]byte, error){
		"another tenant":    func() ([]byte, error) { return key.Open(KeyImportInfo("tenant-b", "ceremony-1", spki), sealed) },
		"another operation": func() ([]byte, error) { return key.Open(KeyImportInfo("tenant-a", "ceremony-2", spki), sealed) },
		"another expected key": func() ([]byte, error) {
			return key.Open(KeyImportInfo("tenant-a", "ceremony-1", []byte("other")), sealed)
		},
		"another import key": func() ([]byte, error) { return other.Open(info, sealed) },
		"tampered":           func() ([]byte, error) { return key.Open(info, tampered) },
		"truncated":          func() ([]byte, error) { return key.Open(info, sealed[:len(sealed)/2]) },
	} {
		if _, err := attempt(); !errors.Is(err, ErrKeyImportOpen) {
			t.Errorf("%s: open = %v, want ErrKeyImportOpen", name, err)
		}
	}

	if _, err := SealKeyImport(key.Public(), info, nil); err == nil {
		t.Error("an empty plaintext was sealed")
	}
	if _, err := SealKeyImport(key.Public(), info, make([]byte, MaxKeyImportPlaintext+1)); err == nil {
		t.Error("an oversized plaintext was sealed")
	}
	if _, err := SealKeyImport([]byte("not a public key"), info, pkcs8); err == nil {
		t.Error("a malformed public key was accepted")
	}
	if _, err := NewKeyImportKey(make([]byte, KeyImportSeedSize-1)); err == nil {
		t.Error("a short seed was accepted")
	}
	key.Destroy()
	if _, err := key.Open(info, sealed); err == nil {
		t.Error("a destroyed import key opened a sealed key")
	}
}

// FuzzKeyImportOpen feeds arbitrary bytes, as an operator-supplied sealed key,
// to the opener: it must refuse without panicking.
func FuzzKeyImportOpen(f *testing.F) {
	key, err := GenerateKeyImportKey()
	if err != nil {
		f.Fatal(err)
	}
	info := KeyImportInfo("tenant", "operation", []byte("spki"))
	sealed, err := SealKeyImport(key.Public(), info, []byte("plaintext private key"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sealed)
	f.Add([]byte{})
	f.Add(make([]byte, 1200))
	f.Fuzz(func(t *testing.T, input []byte) {
		if opened, err := key.Open(info, input); err == nil && !bytes.Equal(input, sealed) {
			t.Fatalf("arbitrary input opened to %d bytes", len(opened))
		}
	})
}
