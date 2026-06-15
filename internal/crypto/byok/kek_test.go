package byok

import (
	"context"
	"errors"
	"testing"
)

// TestManagedKEK_LifecycleGenerateRotateRevokeZeroize drives the secrets KEK
// through generate → wrap → rotate → revoke → zeroize and asserts the AN-2 event
// sequence, that rotation re-keys (a DEK wrapped under v1 no longer unwraps under
// v2), that a revoked KEK refuses to wrap/unwrap (fail-closed), and that a
// zeroized KEK is terminal.
func TestManagedKEK_LifecycleGenerateRotateRevokeZeroize(t *testing.T) {
	ctx := context.Background()
	sink := &recordingSink{}

	k, err := GenerateKEK(ctx, sink, testTenant, "kek-1")
	if err != nil {
		t.Fatalf("GenerateKEK: %v", err)
	}
	if k.State() != StateActive || k.Version() != 1 {
		t.Fatalf("after generate: state=%s version=%d", k.State(), k.Version())
	}

	dek := []byte("0123456789abcdef0123456789abcdef") // 32-byte DEK
	wrappedV1, err := k.WrapDEK(dek)
	if err != nil {
		t.Fatalf("WrapDEK (v1): %v", err)
	}
	gotDek, err := k.UnwrapDEK(wrappedV1)
	if err != nil {
		t.Fatalf("UnwrapDEK (v1): %v", err)
	}
	if string(gotDek) != string(dek) {
		t.Fatalf("v1 unwrap round-trip mismatch")
	}

	// Rotate: a fresh KEK. The v1-wrapped DEK must NOT unwrap under v2 (re-key proof).
	if err := k.Rotate(ctx, testTenant); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if k.Version() != 2 {
		t.Fatalf("after rotate: version=%d, want 2", k.Version())
	}
	if _, err := k.UnwrapDEK(wrappedV1); err == nil {
		t.Fatalf("a DEK wrapped under the superseded v1 KEK unwrapped under v2 — KEK was not re-keyed")
	}
	// The new KEK wraps/unwraps fresh.
	wrappedV2, err := k.WrapDEK(dek)
	if err != nil {
		t.Fatalf("WrapDEK (v2): %v", err)
	}
	if _, err := k.UnwrapDEK(wrappedV2); err != nil {
		t.Fatalf("UnwrapDEK (v2): %v", err)
	}

	// Revoke: wrap/unwrap refused.
	if err := k.Revoke(ctx, testTenant); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := k.WrapDEK(dek); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked KEK wrapped (or wrong error): %v", err)
	}
	if _, err := k.UnwrapDEK(wrappedV2); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked KEK unwrapped (or wrong error): %v", err)
	}

	// Zeroize: terminal; still refused.
	if err := k.Zeroize(ctx, testTenant); err != nil {
		t.Fatalf("Zeroize: %v", err)
	}
	if k.State() != StateZeroized {
		t.Fatalf("after zeroize: state=%s", k.State())
	}
	if _, err := k.WrapDEK(dek); !errors.Is(err, ErrZeroized) {
		t.Fatalf("zeroized KEK wrapped (or wrong error): %v", err)
	}

	want := []string{EventKeyGenerated, EventKeyRotated, EventKeyRevoked, EventKeyZeroized}
	got := sink.types()
	if len(got) != len(want) {
		t.Fatalf("event sequence = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("event[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	for _, e := range sink.events {
		if e.Kind != "kek" {
			t.Errorf("KEK event %s has kind %q, want kek", e.Type, e.Kind)
		}
		if len(e.PublicDER) != 0 {
			t.Errorf("KEK event %s carries a public key (a KEK has none): %x", e.Type, e.PublicDER)
		}
	}
}

// TestImportKEK_BYOK proves the BYOK KEK import wipes the caller's raw key bytes.
func TestImportKEK_BYOK(t *testing.T) {
	ctx := context.Background()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	rawCopy := append([]byte(nil), raw...)
	k, err := ImportKEK(ctx, &recordingSink{}, testTenant, "kek-byok", raw)
	if err != nil {
		t.Fatalf("ImportKEK: %v", err)
	}
	if k.Version() != 1 {
		t.Fatalf("imported KEK version=%d", k.Version())
	}
	if string(raw) == string(rawCopy) {
		t.Fatalf("ImportKEK did not wipe the caller's raw KEK bytes (AN-8 violation)")
	}
	// Still usable after import.
	if _, err := k.WrapDEK(make([]byte, 32)); err != nil {
		t.Fatalf("imported KEK WrapDEK: %v", err)
	}
}
