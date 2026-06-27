package privacy

import (
	"context"
	"errors"
	"testing"
	"time"
)

type testRetentionSource struct {
	policy RetentionPolicy
	found  bool
	err    error
}

func (s testRetentionSource) RetentionPolicy(context.Context, string, RetentionPolicy) (RetentionPolicy, bool, error) {
	return s.policy, s.found, s.err
}

func TestResolveRetentionPolicyDefaultsAndOverride(t *testing.T) {
	base := RetentionPolicy{OwnerInactiveAfter: 10 * time.Hour}.WithDefaults()
	got, err := ResolveRetentionPolicy(context.Background(), nil, "tenant-a", base)
	if err != nil {
		t.Fatalf("resolve nil source: %v", err)
	}
	if got.OwnerInactiveAfter != 10*time.Hour {
		t.Fatalf("nil source owner window = %s, want base override", got.OwnerInactiveAfter)
	}

	override := RetentionPolicy{OwnerInactiveAfter: time.Hour}
	got, err = ResolveRetentionPolicy(context.Background(), testRetentionSource{policy: override, found: true}, "tenant-a", base)
	if err != nil {
		t.Fatalf("resolve override: %v", err)
	}
	if got.OwnerInactiveAfter != time.Hour {
		t.Fatalf("override owner window = %s, want 1h", got.OwnerInactiveAfter)
	}
	if got.IdentityTerminalAfter != DefaultRetentionPolicy().IdentityTerminalAfter {
		t.Fatalf("override did not inherit defaults: %+v", got)
	}
}

func TestResolveRetentionPolicySourceErrorFailsClosed(t *testing.T) {
	want := errors.New("policy store unavailable")
	if _, err := ResolveRetentionPolicy(context.Background(), testRetentionSource{err: want}, "tenant-a", RetentionPolicy{}); !errors.Is(err, want) {
		t.Fatalf("source error = %v, want %v", err, want)
	}
}
