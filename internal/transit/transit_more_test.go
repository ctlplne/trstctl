// SPDX-License-Identifier: BUSL-1.1

package transit

import (
	"context"
	"reflect"
	"testing"
)

func TestServiceListsOnlyTenantKeyMetadataInStableOrder(t *testing.T) {
	ctx := context.Background()
	svc := NewService(nil)
	t.Cleanup(svc.Destroy)

	for _, tc := range []struct {
		tenant string
		name   string
		kind   Kind
	}{
		{tenant: "tenant-a", name: "signing", kind: KindSign},
		{tenant: "tenant-b", name: "other-tenant", kind: KindAEAD},
		{tenant: "tenant-a", name: "encryption", kind: KindAEAD},
		{tenant: "tenant-a", name: "integrity", kind: KindHMAC},
	} {
		if _, err := svc.CreateKey(ctx, tc.tenant, tc.name, tc.kind); err != nil {
			t.Fatalf("CreateKey(%s/%s): %v", tc.tenant, tc.name, err)
		}
	}

	got, err := svc.ListKeys(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("ListKeys(tenant-a): %v", err)
	}
	want := []KeyInfo{
		{Name: "encryption", Kind: KindAEAD, Version: 1},
		{Name: "integrity", Kind: KindHMAC, Version: 1},
		{Name: "signing", Kind: KindSign, Version: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ListKeys(tenant-a) = %+v, want %+v", got, want)
	}

	empty, err := svc.ListKeys(ctx, "tenant-with-no-keys")
	if err != nil {
		t.Fatalf("ListKeys(empty tenant): %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("ListKeys(empty tenant) returned metadata: %+v", empty)
	}
}

func TestTransitErrorPaths(t *testing.T) {
	ctx := context.Background()
	k := New("t1", nil)
	if err := k.CreateKey(ctx, "a", KindAEAD); err != nil {
		t.Fatal(err)
	}
	if err := k.CreateKey(ctx, "a", KindAEAD); err == nil {
		t.Error("duplicate key creation accepted")
	}
	if err := k.CreateKey(ctx, "x", "bogus"); err == nil {
		t.Error("unknown key kind accepted")
	}
	if _, err := k.Encrypt(ctx, "missing", []byte("x"), nil); err == nil {
		t.Error("encrypt with unknown key accepted")
	}
	if _, err := k.Decrypt(ctx, "a", "not-a-ciphertext", nil); err == nil {
		t.Error("malformed ciphertext accepted")
	}
	if _, err := k.Decrypt(ctx, "a", "trv:99:AAAA", nil); err == nil {
		t.Error("unknown key version accepted")
	}
	if _, err := k.Rotate(ctx, "missing"); err == nil {
		t.Error("rotate of unknown key accepted")
	}
	if _, err := k.HMAC(ctx, "a", []byte("d")); err == nil {
		t.Error("HMAC on an AEAD key accepted")
	}
	if _, _, err := k.Sign(ctx, "a", []byte("d")); err == nil {
		t.Error("Sign on an AEAD key accepted")
	}
}

func TestKeyringDestroyZeroizesKeyBytes(t *testing.T) {
	ctx := context.Background()
	k := New("t1", nil)
	if err := k.CreateKey(ctx, "a", KindAEAD); err != nil {
		t.Fatal(err)
	}
	keyBytes := k.keys["a"].aead[1]
	if allZero(keyBytes) {
		t.Fatal("generated key was all zero before destroy")
	}
	k.Destroy()
	if !allZero(keyBytes) {
		t.Fatalf("key bytes still present after Destroy: %x", keyBytes)
	}
	if len(k.keys) != 0 {
		t.Fatalf("destroyed keyring retained %d key metadata entries", len(k.keys))
	}
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func TestListKeyVersionsReturnsCompleteMetadataOnlyHistory(t *testing.T) {
	ctx := context.Background()
	svc := NewService(nil)
	t.Cleanup(svc.Destroy)
	if _, err := svc.CreateKey(ctx, "tenant-a", "payments", KindAEAD); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := svc.Rotate(ctx, "tenant-a", "payments"); err != nil {
			t.Fatal(err)
		}
	}

	kind, versions, err := svc.ListKeyVersions(ctx, "tenant-a", "payments")
	if err != nil {
		t.Fatal(err)
	}
	if kind != KindAEAD {
		t.Fatalf("kind = %q, want %q", kind, KindAEAD)
	}
	if len(versions) != 3 {
		t.Fatalf("versions = %+v, want the complete three-version history", versions)
	}
	for i, got := range versions {
		wantVersion := i + 1
		if got.Version != wantVersion || got.Current != (wantVersion == 3) {
			t.Fatalf("versions[%d] = %+v, want version=%d current=%v", i, got, wantVersion, wantVersion == 3)
		}
	}

	if _, _, err := svc.ListKeyVersions(ctx, "tenant-b", "payments"); err == nil {
		t.Fatal("a different tenant read tenant-a's key-version history")
	}
}
