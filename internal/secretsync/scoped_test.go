// SPDX-License-Identifier: BUSL-1.1

package secretsync

import (
	"context"
	"errors"
	"slices"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// A237: a scoped sync walks the destination's keys (a path that is both a
// secret and a folder appears as both), reads each back as a digest only, and
// deletes a path idempotently.
func TestVaultKVV2ScopedListsReadsBackAndDeletesA237(t *testing.T) {
	ctx := context.Background()
	token := []byte("vault-token")
	kv := newVaultKVV2Emulator(t, token, "team-a")
	kv.seed("db", 1, map[string][]byte{"value": []byte("root-value")})
	kv.seed("db/password", 2, map[string][]byte{"value": []byte("pw-value"), "owner": []byte("dba")})
	kv.seed("app/config", 1, map[string][]byte{"other": []byte("not-ours")})
	p, err := NewVaultKVV2Pusher(VaultKVV2Config{
		Endpoint: kv.server.URL, HTTPClient: kv.server.Client(), Token: token,
		Mount: "team-secrets", PathPrefix: "apps", Namespace: "team-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	scoped, ok := NewTarget("kv", p).Scoped()
	if !ok {
		t.Fatal("a KV v2 target does not offer scoped operations")
	}
	keys, err := scoped.ListKeys(ctx, "", 10)
	if err != nil || !slices.Equal(keys, []string{"app/config", "db", "db/password"}) {
		t.Fatalf("keys %v %v", keys, err)
	}
	if keys, err := scoped.ListKeys(ctx, "db", 10); err != nil || !slices.Equal(keys, []string{"db/password"}) {
		t.Fatalf("keys under db %v %v", keys, err)
	}
	if keys, err := scoped.ListKeys(ctx, "nothing-here", 10); err != nil || len(keys) != 0 {
		t.Fatalf("an empty prefix: %v %v", keys, err)
	}
	if _, err := scoped.ListKeys(ctx, "", 2); !errors.Is(err, ErrScopedListLimit) {
		t.Fatalf("over the limit: %v", err)
	}
	if exists, digest, err := scoped.ReadDigest(ctx, "db/password"); err != nil || !exists || digest != crypto.SHA256Hex([]byte("pw-value")) {
		t.Fatalf("digest %v %q %v", exists, digest, err)
	}
	if exists, digest, err := scoped.ReadDigest(ctx, "app/config"); err != nil || !exists || digest != "" {
		t.Fatalf("a path without this target's field: %v %q %v", exists, digest, err)
	}
	if exists, _, err := scoped.ReadDigest(ctx, "missing"); err != nil || exists {
		t.Fatalf("a missing path: %v %v", exists, err)
	}
	for range 2 {
		if err := scoped.Delete(ctx, "db/password"); err != nil {
			t.Fatalf("delete: %v", err)
		}
	}
	if exists, _, _ := scoped.ReadDigest(ctx, "db/password"); exists {
		t.Fatal("the deleted path still reads")
	}
	if _, ok := NewTarget("webhook", pushOnly{}).Scoped(); ok {
		t.Fatal("a target without listable keys offered scoped operations")
	}
}

type pushOnly struct{}

func (pushOnly) Push(context.Context, string, []byte) error { return nil }

type a237l2PushOnly struct{}

func (a237l2PushOnly) Push(context.Context, string, []byte) error { return nil }

type a237l2FlatPushOnly struct{ a237l2PushOnly }

func (a237l2FlatPushOnly) FlatKeys() bool { return true }
func (a237l2FlatPushOnly) ValidKey(key string) error {
	if key == "bad" {
		return errors.New("not a variable name")
	}
	return nil
}

// A237-L2: a target that can't list its keys has no scoped view of its own;
// its receipt-only view lists nothing, refuses read-backs and deletes, says it
// lists no keys and reads nothing back, and keeps the target's key rules.
func TestScopedFromReceiptsListsNothingAndKeepsKeyRulesA237L2(t *testing.T) {
	ctx := context.Background()
	plain := NewTarget("hook", a237l2PushOnly{})
	if _, ok := plain.Scoped(); ok {
		t.Fatal("a push-only target offered a listing scoped view")
	}
	view := plain.ScopedFromReceipts()
	if keys, err := view.ListKeys(ctx, "", 10); err != nil || len(keys) != 0 {
		t.Fatalf("receipt-only ListKeys = %v, %v", keys, err)
	}
	if _, _, err := view.ReadDigest(ctx, "k"); !errors.Is(err, ErrScopedReceiptOnly) {
		t.Fatalf("receipt-only ReadDigest = %v", err)
	}
	if err := view.Delete(ctx, "k"); !errors.Is(err, ErrScopedReceiptOnly) {
		t.Fatalf("receipt-only Delete = %v", err)
	}
	if ScopedListsKeys(view) || ScopedReadsBack(view) || ScopedFlatKeys(view) || ScopedValidKey(view, "bad") != nil {
		t.Fatal("a plain receipt-only view claims a listing, a read-back or key rules")
	}
	flat := NewTarget("ci", a237l2FlatPushOnly{}).ScopedFromReceipts()
	if !ScopedFlatKeys(flat) || ScopedValidKey(flat, "bad") == nil || ScopedValidKey(flat, "GOOD") != nil {
		t.Fatal("the receipt-only view dropped the target's key rules")
	}
	if !ScopedListsKeys(newScopedListingDouble()) {
		t.Fatal("a listing scoped target reads as receipt-only")
	}
}

type scopedListingDouble struct{}

func newScopedListingDouble() ScopedTarget { return scopedListingDouble{} }
func (scopedListingDouble) ListKeys(context.Context, string, int) ([]string, error) {
	return nil, nil
}
func (scopedListingDouble) ReadDigest(context.Context, string) (bool, string, error) {
	return false, "", nil
}
func (scopedListingDouble) Delete(context.Context, string) error { return nil }
