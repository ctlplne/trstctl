// SPDX-License-Identifier: BUSL-1.1

package kmswrap

import (
	"bytes"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeKMS stands in for the KMS wrap adapter: it "wraps" by XOR with a fixed
// pad and counts every call.
type fakeKMS struct {
	wraps, unwraps atomic.Int64
	fail           atomic.Bool
	short          atomic.Bool
}

var fakePad = bytes.Repeat([]byte{0x5a}, wrapperKeySize)

func (f *fakeKMS) WrapDEK(dek []byte) ([]byte, error) {
	f.wraps.Add(1)
	out := make([]byte, len(dek))
	for i := range dek {
		out[i] = dek[i] ^ fakePad[i%len(fakePad)]
	}
	return append([]byte("kms:"), out...), nil
}

func (f *fakeKMS) UnwrapDEK(wrapped []byte) ([]byte, error) {
	f.unwraps.Add(1)
	if f.fail.Load() {
		return nil, errors.New("kms: the key is disabled")
	}
	body := bytes.TrimPrefix(wrapped, []byte("kms:"))
	out := make([]byte, len(body))
	for i := range body {
		out[i] = body[i] ^ fakePad[i%len(fakePad)]
	}
	if f.short.Load() {
		return out[:16], nil
	}
	return out, nil
}

func newTestWrapperKey(t *testing.T, kms *fakeKMS, cache time.Duration) *WrapperKey {
	t.Helper()
	wrapped, err := CreateWrapperKey(kms)
	if err != nil {
		t.Fatal(err)
	}
	k, err := NewWrapperKey(kms, wrapped, cache)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Close)
	return k
}

// OD-10: with caching off (the default) every Seal and Open unwraps the
// wrapper key through the KMS and keeps nothing.
func TestWrapperKeyUnwrapsThroughTheKMSForEveryUseWhenNotCachedOD10(t *testing.T) {
	kms := &fakeKMS{}
	k := newTestWrapperKey(t, kms, 0)
	sealed, err := k.Seal([]byte("domain KEK container"), []byte("binding"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		plain, err := k.Open(sealed, []byte("binding"))
		if err != nil || string(plain) != "domain KEK container" {
			t.Fatalf("open %d = %q, %v", i, plain, err)
		}
	}
	if got := k.Unwraps(); got != 3 || k.Cached() {
		t.Fatalf("unwraps = %d cached = %v; want 3 and nothing kept", got, k.Cached())
	}
	if _, err := k.Open(sealed, []byte("another binding")); !errors.Is(err, ErrWrapperKeySealedInvalid) {
		t.Fatalf("another binding: %v", err)
	}
	if len(sealed) != gcmNonceSize+len("domain KEK container")+gcmTagSize {
		t.Fatalf("sealed is %d bytes, want nonce || ciphertext || tag", len(sealed))
	}
}

// OD-10: with a time limit the key is unwrapped once and held in locked
// memory; when the limit passes the held key is wiped, and the next use
// unwraps again. Callers arriving together share one unwrap.
func TestWrapperKeyCachesForTheTimeLimitAndWipesItOD10(t *testing.T) {
	kms := &fakeKMS{}
	k := newTestWrapperKey(t, kms, 400*time.Millisecond)
	var wg sync.WaitGroup
	sealedOut := make([][]byte, 8)
	for i := range sealedOut {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sealed, err := k.Seal([]byte(strconv.Itoa(i)), nil)
			if err != nil {
				t.Error(err)
			}
			sealedOut[i] = sealed
		}(i)
	}
	wg.Wait()
	for i, sealed := range sealedOut {
		if plain, err := k.Open(sealed, nil); err != nil || string(plain) != strconv.Itoa(i) {
			t.Fatalf("open %d = %v, %v", i, plain, err)
		}
	}
	if got := k.Unwraps(); got != 1 || !k.Cached() {
		t.Fatalf("within the time limit: unwraps = %d cached = %v; want one unwrap, held", got, k.Cached())
	}
	k.mu.Lock()
	held := k.cached
	k.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for k.Cached() {
		if time.Now().After(deadline) {
			t.Fatal("the held key outlived its time limit")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if held.Len() != 0 {
		t.Fatal("the expired key's memory was not wiped and released")
	}
	if _, err := k.Open(sealedOut[0], nil); err != nil {
		t.Fatal(err)
	}
	if got := k.Unwraps(); got != 2 {
		t.Fatalf("after expiry: unwraps = %d, want 2", got)
	}
}

// OD-10: Close (the signer's shutdown) wipes the held key at once and
// refuses every later use without calling the KMS.
func TestWrapperKeyCloseWipesAndRefusesOD10(t *testing.T) {
	kms := &fakeKMS{}
	k := newTestWrapperKey(t, kms, time.Hour)
	sealed, err := k.Seal([]byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	k.mu.Lock()
	held := k.cached
	k.mu.Unlock()
	k.Close()
	if held == nil || held.Len() != 0 || k.Cached() {
		t.Fatal("Close did not wipe the held key")
	}
	before := k.Unwraps()
	if _, err := k.Open(sealed, nil); !errors.Is(err, ErrWrapperKeyUnavailable) {
		t.Fatalf("open after Close: %v", err)
	}
	if k.Unwraps() != before {
		t.Fatal("a closed wrapper key called the KMS")
	}
}

// OD-10: a KMS that refuses (a disabled key, a revoked grant) or answers
// with a key of the wrong size makes the wrapper key unavailable, and a time
// limit outside zero to 24 hours is refused.
func TestWrapperKeyFailuresOD10(t *testing.T) {
	kms := &fakeKMS{}
	k := newTestWrapperKey(t, kms, 0)
	sealed, err := k.Seal([]byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	kms.fail.Store(true)
	if _, err := k.Open(sealed, nil); !errors.Is(err, ErrWrapperKeyUnavailable) {
		t.Fatalf("a refusing KMS: %v", err)
	}
	kms.fail.Store(false)
	kms.short.Store(true)
	if _, err := k.Open(sealed, nil); !errors.Is(err, ErrWrapperKeyUnavailable) {
		t.Fatalf("a short key: %v", err)
	}
	for _, limit := range []time.Duration{-time.Second, MaxWrapperKeyCache + time.Second} {
		if _, err := NewWrapperKey(kms, []byte("kms:x"), limit); err == nil {
			t.Fatalf("a %s time limit was accepted", limit)
		}
	}
	if _, err := NewWrapperKey(nil, []byte("kms:x"), 0); !errors.Is(err, ErrWrapperKeyUnavailable) {
		t.Fatal("a wrapper key without a KMS was accepted")
	}
}
