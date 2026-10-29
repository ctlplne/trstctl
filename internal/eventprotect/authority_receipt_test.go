// SPDX-License-Identifier: BUSL-1.1

package eventprotect

import (
	"errors"
	"os"
	"testing"

	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/seal"
)

func TestDestructionReceiptReadbackNeedsNoCurrentSourceAuthorization(t *testing.T) {
	authority, cfg, request, grant, _ := destructionFixture(t)
	if receipt, found, err := authority.DestructionReceipt(t.Context(), request.Ref); err != nil || found || receipt != "" {
		t.Fatalf("active custody looked destroyed: found=%v err=%v", found, err)
	}
	receipt, err := authority.Destroy(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	// A pre-offboard data restore has no current source/outbox authorization.
	// Reading independently retained signed evidence must not repeat the effect.
	grant.err = errors.New("old restored source has no offboard command")
	calls := grant.calls
	restarted, err := NewFileAuthority(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	got, found, err := restarted.DestructionReceipt(t.Context(), request.Ref)
	if err != nil || !found || got != receipt || grant.calls != calls {
		t.Fatalf("readback repeated authorization or changed signed evidence: found=%v err=%v", found, err)
	}
}

func TestDestructionReceiptReadbackRefusesUnexplainedLoss(t *testing.T) {
	authority, _, request, _, _ := destructionFixture(t)
	if err := authority.root.Remove(keyName(request.Ref)); err != nil {
		t.Fatal(err)
	}
	if receipt, found, err := authority.DestructionReceipt(t.Context(), request.Ref); !errors.Is(err, ErrKey) || found || receipt != "" {
		t.Fatalf("unexplained loss became erasure evidence: found=%v err=%v", found, err)
	}
}

func TestDestructionReceiptReadbackRefusesReintroducedMaterial(t *testing.T) {
	authority, _, request, _, _ := destructionFixture(t)
	if _, err := authority.Destroy(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	file, err := authority.root.OpenFile(keyName(request.Ref), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if receipt, found, err := authority.DestructionReceipt(t.Context(), request.Ref); !errors.Is(err, ErrKey) || found || receipt != "" {
		t.Fatalf("retained material was reported erased: found=%v err=%v", found, err)
	}
}

func TestDestructionReceiptReadbackSurvivesSignerRotationAndSignerlessRestore(t *testing.T) {
	authority, cfg, request, _, oldKey := destructionFixture(t)
	receipt, err := authority.Destroy(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	rotated, err := jose.GenerateRSASigningKey("a233-rotated-audit-evidence")
	if err != nil {
		t.Fatal(err)
	}
	cfg.EvidenceKey, cfg.VerificationKeys = rotated, oldKey.JWKS()
	for _, signerless := range []bool{false, true} {
		if signerless {
			cfg.EvidenceKey, cfg.DestructionAuthority = nil, nil
		}
		restarted, err := NewFileAuthority(cfg)
		if err != nil {
			t.Fatal(err)
		}
		got, found, err := restarted.DestructionReceipt(t.Context(), request.Ref)
		if err != nil || !found || got != receipt {
			t.Fatalf("pinned historical receipt failed after signer rotation/restoration: signerless=%v found=%v err=%v", signerless, found, err)
		}
		if err := restarted.WithKey(t.Context(), request.Ref, func(seal.KeyWrapper) error { t.Fatal("erased key opened"); return nil }); !errors.Is(err, ErrDestroyed) {
			t.Fatalf("historical receipt was not applied to key reads: %v", err)
		}
		if err := restarted.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// A signerless restore must never choose trust from the receipt itself.
	cfg.VerificationKeys = rotated.JWKS()
	untrusted, err := NewFileAuthority(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = untrusted.Close() })
	if receipt, found, err := untrusted.DestructionReceipt(t.Context(), request.Ref); !errors.Is(err, ErrKey) || found || receipt != "" {
		t.Fatalf("unpinned signing key gained restore authority: found=%v err=%v", found, err)
	}
}
