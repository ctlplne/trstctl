// SPDX-License-Identifier: BUSL-1.1

package eventprotect

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/seal"
)

func TestCustodyFenceReusesOnlyLiveMatchingAuthority(t *testing.T) {
	first, cfg, ref := keyAuthorityFixture(t)
	if err := first.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	other, err := NewFileAuthority(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := other.Close(); err != nil {
			t.Error(err)
		}
	}()
	var escaped context.Context
	if err := first.WithCustodyFence(t.Context(), ref, func(ctx context.Context) error {
		escaped = ctx
		if _, err := first.CreationEvidence(ctx, ref); err != nil {
			return err
		}
		if _, err := other.CreationEvidence(ctx, ref); !errors.Is(err, ErrContext) {
			t.Fatal("another authority borrowed custody fence")
		}
		foreign := ref
		foreign.TenantID = "2c14fe81-1956-4e9d-a174-e27a38e8e979"
		if _, err := first.CreationEvidence(ctx, foreign); !errors.Is(err, ErrContext) {
			t.Fatal("another tenant borrowed custody fence")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := first.CreationEvidence(escaped, ref); !errors.Is(err, ErrContext) {
		t.Fatal("expired custody fence remained usable")
	}
}

func TestCustodyFenceRefusesConcurrentNestedKeyBorrow(t *testing.T) {
	keys, _, ref := keyAuthorityFixture(t)
	if err := keys.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	if err := keys.WithCustodyFence(t.Context(), ref, func(ctx context.Context) error {
		entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		go func() {
			done <- keys.WithKey(ctx, ref, func(seal.KeyWrapper) error { close(entered); <-release; return nil })
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("first nested key borrow did not enter")
		}
		defer func() {
			close(release)
			if err := <-done; err != nil {
				t.Error(err)
			}
		}()
		if _, err := keys.CreationEvidence(ctx, ref); !errors.Is(err, ErrContext) {
			t.Fatalf("concurrent custody use did not refuse: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCustodyFenceNestedReadDoesNotWaitBehindClose(t *testing.T) {
	keys, _, ref := keyAuthorityFixture(t)
	if err := keys.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	if err := keys.WithCustodyFence(t.Context(), ref, func(ctx context.Context) error {
		go func() { closed <- keys.Close() }()
		select {
		case <-closed:
			t.Fatal("close crossed an active custody fence")
		case <-time.After(20 * time.Millisecond):
		}
		_, err := keys.CreationEvidence(ctx, ref)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not finish after custody release")
	}
}
