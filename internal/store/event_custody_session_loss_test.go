// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/store"
)

func TestEventCustodySurvivesLostPostgresFenceWithoutOverlappingCallbacks(t *testing.T) {
	s := newStore(t)
	peer, err := store.Open(t.Context(), testDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(peer.Close)
	base := t.TempDir()
	open := func(locker *store.Store) *eventprotect.FileAuthority {
		t.Helper()
		keys, err := eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{Directory: filepath.Join(base, "keys"), BackupRoots: []string{filepath.Join(base, "events")}, Locker: locker})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = keys.Close() })
		return keys
	}
	first, second := open(s), open(peer)
	ref := eventprotect.KeyRef{TenantID: tenantA, ID: "02f0b795-3f17-46a9-a9cc-a7bdd7ee21eb"}
	if err := first.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- first.WithKey(t.Context(), ref, func(seal.KeyWrapper) error { close(entered); <-release; return nil })
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first custodian did not enter")
	}
	defer func() {
		close(release)
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	var pid int
	//trstctl:system-query — owned integration database; identify only this test's exact advisory lock before terminating its one backend to model session loss.
	if err := peer.SystemPool().QueryRow(t.Context(), `SELECT pid FROM pg_locks WHERE locktype='advisory' AND granted
	 AND classid=((hashtextextended($1,0)>>32)&4294967295)::oid
	 AND objid=(hashtextextended($1,0)&4294967295)::oid AND objsubid=1`, "event-protection-tenant:"+tenantA).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	var stopped bool
	//trstctl:system-query — terminate only the verified backend holding the exact owned custody fixture lock; no other session or database is affected.
	if err := peer.SystemPool().QueryRow(t.Context(), `SELECT pg_terminate_backend($1)`, pid).Scan(&stopped); err != nil || !stopped {
		t.Fatalf("terminate fixture fence: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	called := false
	err = second.WithKey(ctx, ref, func(seal.KeyWrapper) error { called = true; return nil })
	if err == nil || called {
		t.Fatalf("lost database session allowed overlapping custody callbacks: err=%v called=%v", err, called)
	}
}
