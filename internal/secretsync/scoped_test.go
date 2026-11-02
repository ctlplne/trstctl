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
