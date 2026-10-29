// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/store"
)

func TestEventProtectionKeyLockSerializesReplicasAndTenantAliases(t *testing.T) {
	s := newStore(t)
	replica, err := store.Open(t.Context(), testDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(replica.Close)
	ref := eventprotect.KeyRef{TenantID: "d59b4292-1adc-4d43-a405-781f95b1779c", ID: "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb"}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- s.WithKeyLock(t.Context(), ref, func(context.Context) error {
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first replica did not acquire custody lock")
	}
	defer func() {
		close(release)
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	alias := eventprotect.KeyRef{TenantID: strings.ToUpper(ref.TenantID), ID: strings.ToUpper(ref.ID)}
	called := false
	started := time.Now()
	err = replica.WithKeyLock(t.Context(), alias, func(context.Context) error { called = true; return nil })
	if !errors.Is(err, store.ErrDatastoreBusy) || called || time.Since(started) > time.Second {
		t.Fatalf("replica/alias did not fail fast on held custody: %v called=%v", err, called)
	}
	other := ref
	other.TenantID = "2c14fe81-1956-4e9d-a174-e27a38e8e979"
	if err := replica.WithKeyLock(t.Context(), other, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("another tenant was blocked: %v", err)
	}
}

func TestEventProtectionKeyLockReleasesOnCallbackError(t *testing.T) {
	s := newStore(t)
	ref := eventprotect.KeyRef{TenantID: "d59b4292-1adc-4d43-a405-781f95b1779c", ID: "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb"}
	want := errors.New("fixture callback failed")
	if err := s.WithKeyLock(t.Context(), ref, func(context.Context) error { return want }); !errors.Is(err, want) {
		t.Fatal(err)
	}
	if err := s.WithKeyLock(t.Context(), ref, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("callback error leaked a custody lock: %v", err)
	}
	for _, invalid := range []eventprotect.KeyRef{{}, {TenantID: ref.TenantID, ID: "bad"}} {
		if err := s.WithKeyLock(t.Context(), invalid, func(context.Context) error { t.Fatal("malformed ref reached callback"); return nil }); err == nil {
			t.Fatal("malformed custody identity accepted")
		}
	}
}
