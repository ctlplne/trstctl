// SPDX-License-Identifier: BUSL-1.1

package tenantwrap

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto/seal"
)

// gcmWrapper stands in for an HSM AES-256 key: AES-256-GCM with a random IV,
// iv || ciphertext || tag, reporting a failed tag as ErrUnwrap. dropAAD models
// a module that ignores associated data.
type gcmWrapper struct {
	aead    cipher.AEAD
	dropAAD bool
	fail    error
	resize  int
	seen    [][]byte
}

func newGCMWrapper(t *testing.T) *gcmWrapper {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return &gcmWrapper{aead: aead}
}

func (w *gcmWrapper) Seal(plaintext, aad []byte) ([]byte, error) {
	if w.fail != nil {
		return nil, w.fail
	}
	if w.dropAAD {
		aad = nil
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	out := w.aead.Seal(iv, iv, plaintext, aad)
	w.seen = append(w.seen, out)
	return out[:len(out)+w.resize], nil
}

func (w *gcmWrapper) Open(sealed, aad []byte) ([]byte, error) {
	if w.fail != nil {
		return nil, w.fail
	}
	if w.dropAAD {
		aad = nil
	}
	plain, err := w.aead.Open(nil, sealed[:12], sealed[12:], aad)
	if err != nil {
		return nil, ErrUnwrap
	}
	return plain, nil
}

func sameKEK(t *testing.T, a, b *seal.LocalKEK) {
	t.Helper()
	dek := bytes.Repeat([]byte{0x42}, 32)
	wrapped, err := a.WrapDEK(dek)
	if err != nil {
		t.Fatal(err)
	}
	back, err := b.UnwrapDEK(wrapped)
	if err != nil || !bytes.Equal(back, dek) {
		t.Fatalf("the reopened domain KEK is not the created one: %v", err)
	}
}

// A123: a domain KEK wrapped by a key outside the process round-trips under
// the same wrapper and binding, and the container never carries the KEK.
func TestExternalDomainKEKRoundTrip(t *testing.T) {
	w := newGCMWrapper(t)
	created, wrapped, err := CreateDomainKEKExternal(w, testDomainBindingA)
	if err != nil {
		t.Fatalf("CreateDomainKEKExternal: %v", err)
	}
	defer created.Destroy()
	if len(wrapped) != externalEncodedSize || !bytes.HasPrefix(wrapped, []byte(externalFormatMagic)) {
		t.Fatalf("container is %d bytes %q, want %d bytes of %s", len(wrapped), wrapped[:4], externalEncodedSize, externalFormatMagic)
	}
	if err := created.WithKey(func(kek []byte) error {
		if bytes.Contains(wrapped, kek) {
			return errors.New("the container carries the plaintext domain KEK")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	opened, err := OpenDomainKEKExternal(w, wrapped, testDomainBindingA)
	if err != nil {
		t.Fatalf("OpenDomainKEKExternal: %v", err)
	}
	defer opened.Destroy()
	sameKEK(t, created, opened)
}

// A wrong binding, a different wrapper key, or a changed container does not
// open, and the binding holds even under a module that drops associated data.
func TestExternalDomainKEKRefusesAnotherBindingOrWrapper(t *testing.T) {
	w := newGCMWrapper(t)
	created, wrapped, err := CreateDomainKEKExternal(w, testDomainBindingA)
	if err != nil {
		t.Fatal(err)
	}
	created.Destroy()
	if _, err := OpenDomainKEKExternal(w, wrapped, testDomainBindingB); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("open under another binding = %v, want ErrUnwrap", err)
	}
	if _, err := OpenDomainKEKExternal(newGCMWrapper(t), wrapped, testDomainBindingA); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("open under another wrapper key = %v, want ErrUnwrap", err)
	}

	lax := newGCMWrapper(t)
	lax.dropAAD = true
	laxKEK, laxWrapped, err := CreateDomainKEKExternal(lax, testDomainBindingA)
	if err != nil {
		t.Fatal(err)
	}
	laxKEK.Destroy()
	if _, err := OpenDomainKEKExternal(lax, laxWrapped, testDomainBindingB); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("a module that drops associated data opened another binding: %v", err)
	}

	for name, mutate := range map[string]func([]byte){
		"magic":    func(b []byte) { b[0] ^= 0x01 },
		"version":  func(b []byte) { b[4]++ },
		"length":   func(b []byte) { b[6]++ },
		"sealed":   func(b []byte) { b[headerSize+20] ^= 0x01 },
		"checksum": func(b []byte) { b[len(b)-1] ^= 0x01 },
	} {
		changed := append([]byte(nil), wrapped...)
		mutate(changed)
		if _, err := OpenDomainKEKExternal(w, changed, testDomainBindingA); !errors.Is(err, ErrCorrupt) {
			t.Errorf("a container with a changed %s = %v, want ErrCorrupt", name, err)
		}
	}
	if _, err := OpenDomainKEKExternal(w, wrapped[:len(wrapped)-1], testDomainBindingA); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a truncated container = %v, want ErrCorrupt", err)
	}
}

// The two container kinds never stand in for each other.
func TestExternalAndLocalContainersAreNotInterchangeable(t *testing.T) {
	w := newGCMWrapper(t)
	created, external, err := CreateDomainKEKExternal(w, testDomainBindingA)
	if err != nil {
		t.Fatal(err)
	}
	created.Destroy()
	path := writePrivateWrapper(t, bytes.Repeat([]byte{0x22}, localKeySize))
	if _, err := OpenDomainKEK(path, external, testDomainBindingA); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a local wrapper opened an external container: %v", err)
	}
	local, localWrapped, err := CreateDomainKEK(path, testDomainBindingA)
	if err != nil {
		t.Fatal(err)
	}
	local.Destroy()
	if _, err := OpenDomainKEKExternal(w, localWrapped, testDomainBindingA); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("an external wrapper opened a local container: %v", err)
	}
}

// A wrapper that fails keeps its classification, an unclassified failure is an
// unavailable wrapper, an output of the wrong size is a custody failure, and
// none of them returns key material.
func TestExternalDomainKEKFailuresReturnNoKey(t *testing.T) {
	if _, _, err := CreateDomainKEKExternal(newGCMWrapper(t), nil); !errors.Is(err, ErrDomainBinding) {
		t.Fatalf("create without a binding = %v", err)
	}
	if _, _, err := CreateDomainKEKExternal(nil, testDomainBindingA); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("create without a wrapper = %v", err)
	}
	down := newGCMWrapper(t)
	down.fail = errors.New("CKR_DEVICE_REMOVED")
	if key, wrapped, err := CreateDomainKEKExternal(down, testDomainBindingA); !errors.Is(err, ErrUnavailable) || key != nil || wrapped != nil {
		t.Fatalf("create with a failing wrapper = %v (key %v, %d bytes)", err, key != nil, len(wrapped))
	}
	short := newGCMWrapper(t)
	short.resize = -1
	if key, _, err := CreateDomainKEKExternal(short, testDomainBindingA); !errors.Is(err, ErrCustody) || key != nil {
		t.Fatalf("create with a short wrapper output = %v", err)
	}

	w := newGCMWrapper(t)
	created, wrapped, err := CreateDomainKEKExternal(w, testDomainBindingA)
	if err != nil {
		t.Fatal(err)
	}
	created.Destroy()
	w.fail = errors.New("CKR_SESSION_HANDLE_INVALID")
	if key, err := OpenDomainKEKExternal(w, wrapped, testDomainBindingA); !errors.Is(err, ErrUnavailable) || key != nil {
		t.Fatalf("open with a failing wrapper = %v", err)
	}
	if _, err := OpenDomainKEKExternal(nil, wrapped, testDomainBindingA); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("open without a wrapper = %v", err)
	}
	if _, err := OpenDomainKEKExternal(w, wrapped, nil); !errors.Is(err, ErrDomainBinding) {
		t.Fatalf("open without a binding = %v", err)
	}
}

func FuzzParseExternalDomainKEK(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte(externalFormatMagic))
	f.Add(make([]byte, externalEncodedSize))
	f.Add(encodeExternalDomainKEK(make([]byte, externalWrappedSize)))
	f.Fuzz(func(t *testing.T, input []byte) {
		sealed, err := parseExternalDomainKEK(input)
		if err == nil && len(sealed) != externalWrappedSize {
			t.Fatalf("parsed %d sealed bytes, want %d", len(sealed), externalWrappedSize)
		}
	})
}
