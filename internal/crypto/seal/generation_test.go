// SPDX-License-Identifier: BUSL-1.1

package seal

import (
	"bytes"
	"errors"
	"testing"
)

// A198: a later deployment KEK generation's wrapped data key carries its
// generation; the untagged LocalKEK form is generation 0 and is routed by its
// length, so even an untagged value that happens to start with the tag's magic
// stays generation 0.
func TestWrappedGenerationRoutesByLengthThenTag(t *testing.T) {
	local := testKEK(t, 0x31)
	wrapped, err := local.WrapDEK(bytes.Repeat([]byte{0x07}, dekSize))
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapped) != LocalWrappedDEKSize {
		t.Fatalf("a LocalKEK-wrapped data key is %d bytes, want %d", len(wrapped), LocalWrappedDEKSize)
	}
	generation, inner, err := WrappedGeneration(wrapped)
	if err != nil || generation != 0 || !bytes.Equal(inner, wrapped) {
		t.Fatalf("untagged = generation %d err %v", generation, err)
	}
	lookalike := append([]byte(nil), wrapped...)
	copy(lookalike, generationMagic)
	if generation, _, err := WrappedGeneration(lookalike); err != nil || generation != 0 {
		t.Fatalf("an untagged value starting with the magic = generation %d err %v, want 0", generation, err)
	}

	tagged, err := TagGeneration(7, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	generation, inner, err = WrappedGeneration(tagged)
	if err != nil || generation != 7 || !bytes.Equal(inner, wrapped) {
		t.Fatalf("tagged = generation %d err %v", generation, err)
	}
	for name, bad := range map[string][]byte{
		"generation zero":  append(append(append([]byte(nil), generationMagic...), 0, 0, 0, 0), wrapped...),
		"wrong magic":      append([]byte("XKG1\x00\x00\x00\x01"), wrapped...),
		"header only":      append([]byte(nil), tagged[:generationHeaderSize]...),
		"short and opaque": []byte("short"),
	} {
		if _, _, err := WrappedGeneration(bad); !errors.Is(err, ErrGeneration) {
			t.Errorf("%s: err = %v, want ErrGeneration", name, err)
		}
	}
	if _, err := TagGeneration(0, wrapped); !errors.Is(err, ErrGeneration) {
		t.Fatalf("tagging generation 0 = %v, want ErrGeneration", err)
	}
	if _, err := TagGeneration(1, make([]byte, LocalWrappedDEKSize-generationHeaderSize)); !errors.Is(err, ErrGeneration) {
		t.Fatalf("a tagged value of the untagged length = %v, want ErrGeneration", err)
	}
}

// generationWrapper wraps under one LocalKEK and tags the result, as a later
// deployment generation does.
type generationWrapper struct {
	generation uint32
	key        *LocalKEK
}

func (w generationWrapper) WrapDEK(dek []byte) ([]byte, error) {
	inner, err := w.key.WrapDEK(dek)
	if err != nil {
		return nil, err
	}
	return TagGeneration(w.generation, inner)
}

func (w generationWrapper) UnwrapDEK(wrapped []byte) ([]byte, error) {
	generation, inner, err := WrappedGeneration(wrapped)
	if err != nil || generation != w.generation {
		return nil, ErrDecrypt
	}
	return w.key.UnwrapDEK(inner)
}

// routedWrappers unwraps by generation, as the deployment keyring does.
type routedWrappers struct {
	local *LocalKEK
	next  generationWrapper
}

func (w routedWrappers) WrapDEK(dek []byte) ([]byte, error) { return w.next.WrapDEK(dek) }

func (w routedWrappers) UnwrapDEK(wrapped []byte) ([]byte, error) {
	generation, inner, err := WrappedGeneration(wrapped)
	if err != nil {
		return nil, ErrDecrypt
	}
	if generation == 0 {
		return w.local.UnwrapDEK(inner)
	}
	return w.next.UnwrapDEK(wrapped)
}

// RewrapContainerDEK moves a v1 and a v2 container's data key to the next
// generation without touching the payload; both still open, and the pair
// validator accepts exactly that change.
func TestRewrapContainerDEKKeepsEverythingButTheWrappedKey(t *testing.T) {
	local := testKEK(t, 0x41)
	ring := routedWrappers{local: local, next: generationWrapper{generation: 2, key: testKEK(t, 0x42)}}
	aad := []byte("row-aad")
	v1, err := Seal(local, []byte("deployment secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := SealDomain(local, []byte("labeled secret"), aad, []byte("transit"))
	if err != nil {
		t.Fatal(err)
	}
	for name, before := range map[string][]byte{"v1": v1, "v2": v2} {
		rewrap := func(wrapped []byte) ([]byte, bool, error) {
			dek, err := ring.UnwrapDEK(wrapped)
			if err != nil {
				return nil, false, err
			}
			next, err := ring.WrapDEK(dek)
			return next, true, err
		}
		after, changed, err := RewrapContainerDEK(before, rewrap)
		if err != nil || !changed {
			t.Fatalf("%s: rewrap changed=%v err=%v", name, changed, err)
		}
		beforePayload, _ := PayloadCiphertext(before)
		afterPayload, _ := PayloadCiphertext(after)
		if !bytes.Equal(beforePayload, afterPayload) {
			t.Fatalf("%s: the payload changed", name)
		}
		wrapped, labeled, err := ContainerWrappedDEK(after)
		if err != nil || labeled != (name == "v2") {
			t.Fatalf("%s: labeled=%v err=%v", name, labeled, err)
		}
		if generation, _, err := WrappedGeneration(wrapped); err != nil || generation != 2 {
			t.Fatalf("%s: rewrapped generation = %d err %v", name, generation, err)
		}
		if err := ValidateRewrappedDEK(ring, before, after); err != nil {
			t.Fatalf("%s: pair validation: %v", name, err)
		}
		if _, err := Open(local, after, aad); err == nil {
			t.Fatalf("%s: the previous generation still opens the rewrapped container", name)
		}
		if name == "v1" {
			plain, err := Open(ring, after, aad)
			if err != nil || string(plain) != "deployment secret" {
				t.Fatalf("v1: open after rewrap = %q %v", plain, err)
			}
		} else {
			plain, err := OpenDomain(ring, after, aad, []byte("transit"))
			if err != nil || string(plain) != "labeled secret" {
				t.Fatalf("v2: open after rewrap = %q %v", plain, err)
			}
		}
		kept, changed, err := RewrapContainerDEK(after, func([]byte) ([]byte, bool, error) { return nil, false, nil })
		if err != nil || changed || !bytes.Equal(kept, after) {
			t.Fatalf("%s: an unchanged rewrap altered the container", name)
		}
	}

	other, err := Seal(local, []byte("different payload"), aad)
	if err != nil {
		t.Fatal(err)
	}
	moved, _, err := RewrapContainerDEK(other, func(wrapped []byte) ([]byte, bool, error) {
		dek, err := ring.UnwrapDEK(wrapped)
		if err != nil {
			return nil, false, err
		}
		next, err := ring.WrapDEK(dek)
		return next, true, err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRewrappedDEK(ring, v1, moved); err == nil {
		t.Fatal("the validator accepted a pair whose payloads differ")
	}
	otherWrapped, _, err := ContainerWrappedDEK(other)
	if err != nil {
		t.Fatal(err)
	}
	swapped, _, err := RewrapContainerDEK(v1, func([]byte) ([]byte, bool, error) {
		return otherWrapped, true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRewrappedDEK(ring, v1, swapped); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("a pair whose wrapped keys hold different data keys = %v, want ErrDecrypt", err)
	}
}

func testKEK(t *testing.T, fill byte) *LocalKEK {
	t.Helper()
	k, err := NewLocalKEK(bytes.Repeat([]byte{fill}, kekSize))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Destroy)
	return k
}
