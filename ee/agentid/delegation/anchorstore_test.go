// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"context"
	"testing"
)

func TestDurableAnchorStore_PutLoadAndLookup(t *testing.T) {
	store := NewDurableAnchorStore(t.TempDir())
	tenantID := "11111111-1111-1111-1111-111111111111"
	keyID := "root-key"
	want := RootAnchor{PublicDER: []byte{0x30, 0x02, 0x01, 0x02}, AuthRef: "webauthn:root"}

	if err := store.PutRootAnchor(context.Background(), tenantID, keyID, want); err != nil {
		t.Fatalf("PutRootAnchor: %v", err)
	}
	got, err := store.GetRootAnchor(tenantID, keyID)
	if err != nil {
		t.Fatalf("GetRootAnchor: %v", err)
	}
	if string(got.PublicDER) != string(want.PublicDER) || got.AuthRef != want.AuthRef {
		t.Fatalf("GetRootAnchor = %+v, want %+v", got, want)
	}

	all, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	loaded := all[tenantID][keyID]
	if string(loaded.PublicDER) != string(want.PublicDER) || loaded.AuthRef != want.AuthRef {
		t.Fatalf("Load = %+v, want %+v", loaded, want)
	}

	dynamic, ok := store.Anchor(tenantID, keyID)
	if !ok {
		t.Fatal("dynamic Anchor lookup did not find the provisioned anchor")
	}
	if dynamic.AuthRef != want.AuthRef {
		t.Fatalf("dynamic anchor auth_ref = %q, want %q", dynamic.AuthRef, want.AuthRef)
	}
}

func TestDurableAnchorStore_UnsafePathRefused(t *testing.T) {
	store := NewDurableAnchorStore(t.TempDir())
	if err := store.PutRootAnchor(context.Background(), "../tenant", "root-key", RootAnchor{PublicDER: []byte{1}, AuthRef: "a"}); err == nil {
		t.Fatal("unsafe tenant path was accepted")
	}
	if err := store.PutRootAnchor(context.Background(), "tenant", "../root", RootAnchor{PublicDER: []byte{1}, AuthRef: "a"}); err == nil {
		t.Fatal("unsafe key path was accepted")
	}
}
