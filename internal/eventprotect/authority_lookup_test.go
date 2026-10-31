// SPDX-License-Identifier: BUSL-1.1
package eventprotect

import (
	"errors"
	"testing"
)

func TestCurrentKeyStateDistinguishesNeverEnabledFromLostMaterial(t *testing.T) {
	authority, _, request, grant, _ := destructionFixture(t)
	missing := request.Ref
	missing.ID = "9078bf84-5f54-4e76-aaba-b76dcfbfd6b6"
	if _, found, err := authority.LookupKeyState(t.Context(), missing); err != nil || found || grant.calls != 0 {
		t.Fatalf("never-enabled reference became missing-key authority: %v", err)
	}
	creation, err := authority.CreationEvidence(t.Context(), request.Ref)
	if err != nil {
		t.Fatal(err)
	}
	state, found, err := authority.LookupKeyState(t.Context(), request.Ref)
	if err != nil || !found || state.Phase != CustodyKeyActive || state.Creation.Digest() != creation.Digest() || state.Receipt != "" || grant.calls != 0 {
		t.Fatalf("current active identity unavailable: %v", err)
	}
	if err := authority.root.Remove(keyName(request.Ref)); err != nil {
		t.Fatal(err)
	}
	if _, found, err := authority.LookupKeyState(t.Context(), request.Ref); !errors.Is(err, ErrKey) || !found {
		t.Fatalf("unexplained material loss became never-enabled state: found=%v err=%v", found, err)
	}
}

func TestCurrentKeyStateReadbackUsesOriginalSignedAbsenceWithoutEffectAuthority(t *testing.T) {
	authority, cfg, request, grant, key := destructionFixture(t)
	receipt, err := authority.Destroy(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.EvidenceKey = nil
	cfg.DestructionAuthority = nil
	cfg.VerificationKeys = key.JWKS()
	reader, err := NewFileAuthority(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	calls := grant.calls
	state, found, err := reader.LookupKeyState(t.Context(), request.Ref)
	if err != nil || !found || state.Phase != CustodyKeyDestroyed || state.Receipt != receipt || state.Creation.Digest() != request.CreationDigest || grant.calls != calls {
		t.Fatalf("readback lost exact signed identity or repeated effect: %v", err)
	}
}

func TestCurrentKeyStateRefusesMaterialWithoutItsIndependentRecord(t *testing.T) {
	authority, _, request, grant, _ := destructionFixture(t)
	if err := authority.root.Remove(recordName(request.Ref)); err != nil {
		t.Fatal(err)
	}
	if _, found, err := authority.LookupKeyState(t.Context(), request.Ref); !errors.Is(err, ErrKey) || !found || grant.calls != 0 {
		t.Fatalf("orphaned material became never-enabled state: found=%v err=%v", found, err)
	}
}
