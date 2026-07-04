// SPDX-License-Identifier: MPL-2.0

package idem

import (
	"context"
	"errors"
	"testing"
)

func TestMemoryReplaysResult(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	calls := 0
	fn := func(context.Context) ([]byte, error) { calls++; return []byte("result"), nil }
	r1, err := m.Do(ctx, "t1", "k", fn)
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := m.Do(ctx, "t1", "k", fn)
	if string(r1) != "result" || string(r2) != "result" || calls != 1 {
		t.Errorf("not idempotent: r1=%q r2=%q calls=%d", r1, r2, calls)
	}
}

func TestMemoryErrorReleasesClaim(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	calls := 0
	fn := func(context.Context) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("transient")
		}
		return []byte("ok"), nil
	}
	if _, err := m.Do(ctx, "t1", "k", fn); err == nil {
		t.Fatal("expected the first call to error")
	}
	// The failed key must be retryable (the claim was released, not cached).
	r, err := m.Do(ctx, "t1", "k", fn)
	if err != nil || string(r) != "ok" || calls != 2 {
		t.Errorf("error did not release the claim: r=%q err=%v calls=%d", r, err, calls)
	}
}

func TestMemoryScopesByTenant(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	_, _ = m.Do(ctx, "t1", "k", func(context.Context) ([]byte, error) { return []byte("a"), nil })
	r, _ := m.Do(ctx, "t2", "k", func(context.Context) ([]byte, error) { return []byte("b"), nil })
	if string(r) != "b" {
		t.Errorf("same key in a different tenant collided: %q", r)
	}
}
