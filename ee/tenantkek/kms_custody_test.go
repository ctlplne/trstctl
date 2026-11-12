// SPDX-License-Identifier: LicenseRef-trstctl-EE

package tenantkek_test

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/tenantkek"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/kmswrap"
	"trstctl.com/trstctl/internal/crypto/tenantwrap"
)

var odBindingB = []byte("tenant=bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb;domain=22222222-2222-4222-8222-222222222222;generation=1")

// kmsDouble stands in for the KMS wrap adapter: AES-GCM under one key that
// never leaves it, counting every unwrap.
type kmsDouble struct {
	key      []byte
	unwraps  atomic.Int64
	disabled atomic.Bool
}

func newKMSDouble(t *testing.T) *kmsDouble {
	t.Helper()
	key, err := crypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	return &kmsDouble{key: key}
}

func (k *kmsDouble) WrapDEK(dek []byte) ([]byte, error) {
	return crypto.AESGCMSeal(k.key, dek, []byte("kms-double"))
}

func (k *kmsDouble) UnwrapDEK(wrapped []byte) ([]byte, error) {
	k.unwraps.Add(1)
	if k.disabled.Load() {
		return nil, errors.New("the KMS key is disabled")
	}
	return crypto.AESGCMOpen(k.key, wrapped, []byte("kms-double"))
}

func kmsWrapperKey(t *testing.T, kms *kmsDouble, cache time.Duration) *kmswrap.WrapperKey {
	t.Helper()
	wrapped, err := kmswrap.CreateWrapperKey(kms)
	if err != nil {
		t.Fatal(err)
	}
	key, err := kmswrap.NewWrapperKey(kms, wrapped, cache)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// OD-10 (A200-L4): a tenant domain KEK kept under a wrapper key that a cloud
// KMS key wraps. With caching off every custody call unwraps the wrapper key
// through the KMS; with a time limit the custody makes one KMS call however
// many data keys it wraps and unwraps, and Close wipes the cached key.
func TestCustodyKeepsDomainKEKsUnderAKMSWrapperOD10(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		cache time.Duration
		// unwraps after the startup probe, one create, one open and five
		// data-key wraps and unwraps
		want int64
	}{
		{"cache off", 0, 2 + 1 + 1 + 10},
		{"cache on", time.Hour, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kms := newKMSDouble(t)
			key := kmsWrapperKey(t, kms, tc.cache)
			c, err := tenantkek.NewWithKMS(nil, nil, map[string]*kmswrap.WrapperKey{"kms-a": key})
			if err != nil {
				t.Fatal(err)
			}
			if got := c.Wrappers(); len(got) != 1 || got[0] != "kms-a" {
				t.Fatalf("wrappers = %v", got)
			}
			wrapped, err := c.CreateDomainKEK(ctx, "kms-a", bindingA)
			if err != nil || !bytes.HasPrefix(wrapped, []byte("TDH1")) {
				t.Fatalf("create = %q, %v", wrapped, err)
			}
			if err := c.OpenDomainKEK(ctx, "kms-a", wrapped, bindingA); err != nil {
				t.Fatalf("open: %v", err)
			}
			for i := 0; i < 5; i++ {
				dek, err := crypto.RandomBytes(32)
				if err != nil {
					t.Fatal(err)
				}
				wrappedDEK, err := c.WrapDataKey(ctx, "kms-a", wrapped, bindingA, dek)
				if err != nil {
					t.Fatalf("wrap %d: %v", i, err)
				}
				back, err := c.UnwrapDataKey(ctx, "kms-a", wrapped, bindingA, wrappedDEK)
				if err != nil || !bytes.Equal(back, dek) {
					t.Fatalf("unwrap %d: %v", i, err)
				}
			}
			if got := kms.unwraps.Load(); got != tc.want {
				t.Fatalf("KMS unwraps = %d, want %d", got, tc.want)
			}
			if err := c.OpenDomainKEK(ctx, "kms-a", wrapped, odBindingB); !errors.Is(err, tenantwrap.ErrUnwrap) {
				t.Fatalf("another binding: %v", err)
			}
			if err := c.Close(); err != nil || key.Cached() {
				t.Fatalf("close = %v, still cached %v", err, key.Cached())
			}
			if _, err := c.WrapDataKey(ctx, "kms-a", wrapped, bindingA, make([]byte, 32)); !errors.Is(err, tenantwrap.ErrUnavailable) {
				t.Fatalf("after close: %v", err)
			}
		})
	}
}

// OD-10: a KMS that stops unwrapping (a disabled key) makes the wrapper
// unavailable, not the data invalid; a wrapper ID cannot be both an HSM key
// and a KMS wrapper; and startup refuses a KMS wrapper that does not work.
func TestCustodyKMSWrapperFailuresOD10(t *testing.T) {
	ctx := context.Background()
	kms := newKMSDouble(t)
	key := kmsWrapperKey(t, kms, 0)
	c, err := tenantkek.NewWithKMS(nil, nil, map[string]*kmswrap.WrapperKey{"kms-a": key})
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := c.CreateDomainKEK(ctx, "kms-a", bindingA)
	if err != nil {
		t.Fatal(err)
	}
	kms.disabled.Store(true)
	if err := c.OpenDomainKEK(ctx, "kms-a", wrapped, bindingA); !errors.Is(err, tenantwrap.ErrUnavailable) || errors.Is(err, tenantwrap.ErrUnwrap) {
		t.Fatalf("a disabled KMS key: %v", err)
	}
	if _, err := tenantkek.NewWithKMS(nil, nil, map[string]*kmswrap.WrapperKey{"kms-b": key}); err == nil {
		t.Fatal("startup accepted a KMS wrapper the KMS no longer unwraps")
	}
	tok := newFakeToken(t, "hsm-key-a")
	if _, err := tenantkek.NewWithKMS(tok, map[string]string{"shared": "hsm-key-a"}, map[string]*kmswrap.WrapperKey{"shared": key}); err == nil {
		t.Fatal("a wrapper ID named both an HSM key and a KMS wrapper")
	}
	if _, err := tenantkek.NewWithKMS(nil, nil, nil); err == nil {
		t.Fatal("a custody with no wrappers was accepted")
	}
}
