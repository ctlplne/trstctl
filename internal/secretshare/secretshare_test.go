package secretshare

import (
	"context"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/approval"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
)

// TestRedeemTokenNeverInAuditLog is the GAP-001 acceptance: the one-time-link
// redeem token is the bearer capability that releases the secret, so it must
// NEVER appear in any emitted audit/event record — an audit-reader who could
// recover it would redeem the secret before the legitimate recipient. The audit
// trail is preserved via a non-secret share_id and a non-reversible
// SHA-256(token), and redemption must still work end-to-end.
func TestRedeemTokenNeverInAuditLog(t *testing.T) {
	ctx := context.Background()
	rec := &auditsink.Recorder{}
	s := New("t1", rec, nil)

	tok, err := s.Create(ctx, []byte("the-secret"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Redemption still works.
	got, err := s.View(ctx, tok)
	if err != nil || string(got) != "the-secret" {
		t.Fatalf("view = %q (err %v); redemption must still work after the fix", got, err)
	}

	// The token must not leak into ANY audit record (create or view).
	recs := rec.Records()
	if len(recs) == 0 {
		t.Fatal("expected audit records for create+view")
	}
	wantHash := crypto.SHA256Hex([]byte(tok))
	sawShared, sawViewed := false, false
	for _, r := range recs {
		if strings.Contains(string(r.Data), tok) {
			t.Errorf("audit %q leaks the redeem token: %s", r.Type, r.Data)
		}
		switch r.Type {
		case "secret.shared":
			sawShared = true
		case "secret.share.viewed":
			sawViewed = true
		}
		// A non-reversible reference (hash) is the only correlation allowed.
		if r.Type == "secret.shared" || r.Type == "secret.share.viewed" {
			if !strings.Contains(string(r.Data), wantHash) {
				t.Errorf("audit %q does not carry the non-reversible token hash for correlation: %s", r.Type, r.Data)
			}
		}
	}
	if !sawShared || !sawViewed {
		t.Errorf("expected both secret.shared and secret.share.viewed audit events (shared=%v viewed=%v)", sawShared, sawViewed)
	}
}

func TestOneTimeLinkSelfDestructs(t *testing.T) {
	ctx := context.Background()
	rec := &auditsink.Recorder{}
	s := New("t1", rec, nil)
	tok, err := s.Create(ctx, []byte("the-secret"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.View(ctx, tok)
	if err != nil || string(got) != "the-secret" {
		t.Fatalf("first view = %q (err %v)", got, err)
	}
	// Second view returns nothing.
	if _, err := s.View(ctx, tok); err == nil {
		t.Error("second view succeeded — link did not self-destruct")
	}
	if rec.Count("secret.share.viewed") != 1 {
		t.Error("view not audited")
	}
}

func TestExpiredLinkReturnsNothing(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	s := New("t1", nil, clock)
	tok, _ := s.Create(context.Background(), []byte("x"), time.Minute)
	now = now.Add(2 * time.Minute) // past expiry
	if _, err := s.View(context.Background(), tok); err == nil {
		t.Error("expired link returned a secret")
	}
}

// TestExpiredLinkZeroizesSecret is the GAP-007 acceptance: when a link expires and
// is reaped on View, the stored secret bytes are zeroized before the backing array
// is handed to the GC (AN-8), not merely delete()d from the map. Pre-fix the expiry
// path only delete()d the entry, leaving the bytes intact in freed heap.
func TestExpiredLinkZeroizesSecret(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	s := New("t1", nil, clock)
	tok, _ := s.Create(context.Background(), []byte("zero-me-secret"), time.Minute)

	// Capture the link's backing array (white-box, same package).
	s.mu.Lock()
	backing := s.links[tok].secret
	s.mu.Unlock()
	if allZero(backing) {
		t.Fatal("stored secret was already zero before expiry (test setup wrong)")
	}

	now = now.Add(2 * time.Minute) // past expiry
	if _, err := s.View(context.Background(), tok); err == nil {
		t.Fatal("expired link returned a secret")
	}
	if !allZero(backing) {
		t.Errorf("expired link did not zeroize its stored secret: %v", backing)
	}
}

// TestDestroyZeroizesPendingSecrets is the GAP-007 acceptance for shutdown/eviction:
// Destroy zeroizes every still-pending (un-viewed) shared secret.
func TestDestroyZeroizesPendingSecrets(t *testing.T) {
	s := New("t1", nil, nil)
	tok, _ := s.Create(context.Background(), []byte("pending-secret"), time.Hour)
	s.mu.Lock()
	backing := s.links[tok].secret
	s.mu.Unlock()
	s.Destroy()
	if len(s.links) != 0 {
		t.Error("Destroy did not clear links")
	}
	if !allZero(backing) {
		t.Errorf("Destroy did not zeroize pending secret: %v", backing)
	}
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return len(b) > 0
}

func TestSecretChangeRequiresApproval(t *testing.T) {
	ctx := context.Background()
	applied := false
	mgr, err := NewChangeApprovals("t1", func(_ context.Context, _, resource string) (string, error) {
		applied = true
		return "change-" + resource, nil
	}, &auditsink.Recorder{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.RequestIssuance(ctx, approval.RequestSpec{ID: "chg-1", Resource: "secret:app/db", Requester: "alice"}); err != nil {
		t.Fatal(err)
	}
	// Not applied until dual-control approvals complete.
	if _, _ = mgr.Approve(ctx, "t1", "chg-1", "bob"); applied {
		t.Error("change applied after a single approval")
	}
	if _, err := mgr.Approve(ctx, "t1", "chg-1", "carol"); err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Error("change not applied after dual-control approval")
	}
}
