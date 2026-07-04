// SPDX-License-Identifier: MPL-2.0

package seal_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"trstctl.com/trstctl/internal/crypto/seal"
)

// fakeWrapper is an in-memory KeyWrapper for fuzzing seal.Open without touching a
// real KEK/HSM. WrapDEK prepends a fixed tag and UnwrapDEK strips it (rejecting any
// wrapped blob that does not carry the tag), so the harness exercises the container
// decode path — magic/version dispatch, wrappedLen slicing, nonce/ciphertext
// slicing — independently of the AEAD math, and a mutated wrappedLen that points
// past the buffer is what we want Open to reject cleanly (not panic).
type fakeWrapper struct{}

var fakeTag = []byte("FAKEWRAP")

func (fakeWrapper) WrapDEK(dek []byte) ([]byte, error) {
	return append(append([]byte{}, fakeTag...), dek...), nil
}

func (fakeWrapper) UnwrapDEK(wrapped []byte) ([]byte, error) {
	if len(wrapped) < len(fakeTag) || !bytes.Equal(wrapped[:len(fakeTag)], fakeTag) {
		return nil, seal.ErrDecrypt
	}
	return append([]byte{}, wrapped[len(fakeTag):]...), nil
}

// FuzzOpenSeal drives arbitrary bytes through seal.Open, the binary sealed-blob
// decoder (FUZZ-001). Open parses an attacker-influenceable container — the format
// magic, the version byte it DISPATCHES on, the 2-byte big-endian wrappedLen, and
// the stored-byte slices for the wrapped DEK / nonce / ciphertext — before any
// AEAD verification. Sealed blobs are read from at-rest storage and backups, so a
// truncated, version-bumped, or wrappedLen-mutated blob must fail closed
// (ErrFormat / ErrDecrypt), never panic or read out of bounds. CLAUDE.md §6.
//
// This test lives inside the AN-3 crypto boundary (internal/crypto/seal), so it may
// use crypto/rand directly to mint a real Seal() seed.
func FuzzOpenSeal(f *testing.F) {
	w := fakeWrapper{}

	// A real Seal() output reaches the success path (and is the base for mutations).
	plaintext := []byte("seed-secret-material-0123456789ab")
	good, err := seal.Seal(w, plaintext, nil)
	if err != nil {
		f.Fatalf("seed Seal: %v", err)
	}
	f.Add(good)

	// Truncations of a valid blob at several boundaries (magic, version, wrappedLen,
	// inside the wrapped DEK).
	for _, n := range []int{0, 1, 3, 4, 5, 6, 7, len(good) - 1} {
		if n >= 0 && n <= len(good) {
			f.Add(append([]byte{}, good[:n]...))
		}
	}

	// Same length as a valid blob but a wrong (unknown) version byte.
	if len(good) > len(magicBytes) {
		wrongVer := append([]byte{}, good...)
		wrongVer[len(magicBytes)] = 0xFF
		f.Add(wrongVer)
	}

	// A mutated wrappedLen that points well past the buffer (the 2 bytes after
	// magic|version). This is the classic out-of-bounds-slice bait.
	if len(good) > len(magicBytes)+1+2 {
		bigLen := append([]byte{}, good...)
		bigLen[len(magicBytes)+1] = 0xFF
		bigLen[len(magicBytes)+2] = 0xFF
		f.Add(bigLen)
	}

	// Right magic+version but nothing after (forces the body-length guards).
	hdr := append(append([]byte{}, magicBytes...), 0x01)
	f.Add(hdr)

	// Wrong magic, correct length shape.
	wrongMagic := append([]byte{}, good...)
	if len(wrongMagic) > 0 {
		wrongMagic[0] ^= 0xFF
		f.Add(wrongMagic)
	}

	// Random bytes of a few sizes.
	for _, n := range []int{2, 8, 32, 64} {
		b := make([]byte, n)
		_, _ = rand.Read(b)
		f.Add(b)
	}
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, sealed []byte) {
		// Only the absence of a panic / out-of-bounds read is asserted. A malformed
		// or unauthenticated container legitimately returns an error; a successful
		// Open must round-trip to the original plaintext under the same wrapper.
		got, err := seal.Open(w, sealed, nil)
		if err == nil && !bytes.Equal(got, plaintext) {
			t.Fatalf("Open returned nil error but plaintext %q != seed", got)
		}
	})
}

// magicBytes mirrors the unexported seal magic ('C','S','L','1') so the harness can
// build header-shaped seeds without reaching into the package internals.
var magicBytes = []byte{'C', 'S', 'L', '1'}
