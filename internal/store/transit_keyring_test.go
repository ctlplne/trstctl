// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"bytes"
	"context"
	"testing"
)

// A125: a tenant's sealed transit keyring is one row saved by compare-and-swap
// on its revision, so two replicas cannot overwrite each other, and RLS keeps
// one tenant's row from another.
func TestTransitKeyringRowsSaveByRevisionAndStayWithTheirTenant(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	const tenantA = "a1250000-0000-4000-8000-000000000001"
	const tenantB = "b1250000-0000-4000-8000-000000000002"
	seedTenant(t, s, tenantA)
	seedTenant(t, s, tenantB)

	if _, _, found, err := s.LoadTransitKeyring(ctx, tenantA); err != nil || found {
		t.Fatalf("an empty tenant's keyring = found %v, %v", found, err)
	}
	rev, saved, err := s.SaveTransitKeyring(ctx, tenantA, []byte("sealed-1"), 0)
	if err != nil || !saved || rev != 1 {
		t.Fatalf("first save = %d %v %v", rev, saved, err)
	}
	if _, saved, err := s.SaveTransitKeyring(ctx, tenantA, []byte("sealed-other"), 0); err != nil || saved {
		t.Fatalf("a second first save = saved %v, %v; want refused", saved, err)
	}
	rev, saved, err = s.SaveTransitKeyring(ctx, tenantA, []byte("sealed-2"), 1)
	if err != nil || !saved || rev != 2 {
		t.Fatalf("save over revision 1 = %d %v %v", rev, saved, err)
	}
	if _, saved, err := s.SaveTransitKeyring(ctx, tenantA, []byte("sealed-stale"), 1); err != nil || saved {
		t.Fatalf("a save over a stale revision = saved %v, %v; want refused", saved, err)
	}
	sealed, rev, found, err := s.LoadTransitKeyring(ctx, tenantA)
	if err != nil || !found || rev != 2 || !bytes.Equal(sealed, []byte("sealed-2")) {
		t.Fatalf("load = %q %d %v %v", sealed, rev, found, err)
	}
	if _, _, found, err := s.LoadTransitKeyring(ctx, tenantB); err != nil || found {
		t.Fatalf("tenant B sees a keyring: found %v, %v", found, err)
	}
	if _, saved, err := s.SaveTransitKeyring(ctx, tenantB, []byte("sealed-b"), 2); err != nil || saved {
		t.Fatalf("tenant B saved over tenant A's revision: saved %v, %v", saved, err)
	}
	if _, _, err := s.SaveTransitKeyring(ctx, tenantA, nil, 2); err == nil {
		t.Fatal("an empty sealed keyring was accepted")
	}
}
