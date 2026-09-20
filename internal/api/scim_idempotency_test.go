// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
)

// TestSCIMDerivedIdempotencyKeyIsBoundedInTime is the regression guard for the
// swallowed-deprovision defect. A SCIM provider that sends no Idempotency-Key
// gets one derived from its request, and that derivation was over
// method+path+body alone — stable FOREVER. Two genuinely separate operations
// with byte-identical bodies therefore collapsed into one.
//
// The realistic sequence is deprovision -> reprovision -> deprovision: the second
// deprovision has an identical body, so it was treated as a replay of the first,
// returned that recorded result, and never ran. The user stayed provisioned
// while SCIM reported success.
func TestSCIMDerivedIdempotencyKeyIsBoundedInTime(t *testing.T) {
	body := []byte(`{"active":false}`)
	req := func() *http.Request {
		return httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/alice", nil)
	}

	// An immediate retry — the reason providers need idempotency — must dedupe.
	first, _ := scimIdempotencyKey(req(), body)
	again, _ := scimIdempotencyKey(req(), body)
	if first != again {
		t.Fatalf("two immediate identical requests derived different keys (%q vs %q); a provider retry would double-apply",
			first, again)
	}

	// And the window must actually be bounded, or a later repeat is swallowed.
	if scimRetryWindow <= 0 {
		t.Fatal("the derived key dedupes forever; a repeated deprovision is silently swallowed")
	}
	if scimRetryWindow > time.Hour {
		t.Fatalf("retry window %s is long enough to swallow a deliberate repeat", scimRetryWindow)
	}
}

// TestSCIMExplicitIdempotencyKeyWins pins the behaviour that was already right:
// a provider that supplies its own key controls deduplication, and nothing is
// derived on its behalf.
func TestSCIMExplicitIdempotencyKeyWins(t *testing.T) {
	r := httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/alice", nil)
	r.Header.Set("Idempotency-Key", "provider-supplied-key")
	got, prev := scimIdempotencyKey(r, []byte(`{"active":false}`))
	if got != "provider-supplied-key" {
		t.Fatalf("explicit key = %q, want it used verbatim", got)
	}
	if prev != "" {
		t.Fatalf("explicit key derived a previous-bucket key %q; the provider owns dedupe entirely", prev)
	}
}

// TestSCIMDerivedKeySeparatesDistinctOperations keeps the derivation honest:
// different targets or different bodies must never share a key, or one user's
// deprovision would suppress another's.
func TestSCIMDerivedKeySeparatesDistinctOperations(t *testing.T) {
	alice := httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/alice", nil)
	bob := httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/bob", nil)
	body := []byte(`{"active":false}`)

	aliceKey, _ := scimIdempotencyKey(alice, body)
	bobKey, _ := scimIdempotencyKey(bob, body)
	if aliceKey == bobKey {
		t.Fatal("two different users share an idempotency key; one deprovision would suppress the other")
	}
	aliceOther, _ := scimIdempotencyKey(alice, []byte(`{"active":true}`))
	if aliceKey == aliceOther {
		t.Fatal("deprovision and reprovision share an idempotency key")
	}
}

// TestSCIMBoundaryStraddlingRetryIsDeduped is the regression guard for AUD-201
// follow-up I3/V9. The derived key folds in a 5-minute wall-clock bucket, and
// exactly one key was derived and looked up — no previous-bucket fallback
// existed anywhere — so a byte-identical retry at 12:00:02 of a request first
// sent at 11:59:58 hashed a different bucket, claimed a fresh row, and re-ran
// the mutation (duplicate execution and duplicate tenant.member.* audit
// events). The old comment claimed "an immediate retry lands in the same
// bucket and dedupes", false at every boundary; the old test called the
// derivation twice back-to-back and never crossed one. The clock is injected,
// so the boundary is exact rather than flaky.
func TestSCIMBoundaryStraddlingRetryIsDeduped(t *testing.T) {
	origNow := scimNow
	t.Cleanup(func() { scimNow = origNow })
	// Two seconds before a bucket boundary.
	current := time.Date(2026, 3, 14, 12, 4, 58, 0, time.UTC)
	scimNow = func() time.Time { return current }

	a := &API{idem: orchestrator.NewMemoryIdempotency(), orch: &orchestrator.Orchestrator{}}
	tok := scimToken{Name: "okta", TenantID: "tenant-a", TokenHash: "hash-1"}
	body := []byte(`{"active":false}`)

	runs := 0
	do := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/alice", nil)
		key, prev := scimIdempotencyKey(r, body)
		a.scimMutate(w, r, tok, key, prev, body, func(ctx context.Context, tenantID string) (int, any, error) {
			runs++
			return http.StatusOK, map[string]string{"applied": "yes"}, nil
		})
		return w
	}

	if w := do(); w.Code != http.StatusOK {
		t.Fatalf("first request = %d, want 200", w.Code)
	}
	if runs != 1 {
		t.Fatalf("first request ran %d times", runs)
	}

	// The retry arrives four seconds later — across the bucket boundary.
	current = current.Add(4 * time.Second)
	w := do()
	if w.Code != http.StatusOK {
		t.Fatalf("boundary retry = %d, want the recorded 200", w.Code)
	}
	if runs != 1 {
		t.Fatalf("a byte-identical retry across the bucket boundary re-ran the mutation (%d executions); "+
			"the promised dedupe is lost exactly when a provider retry needs it", runs)
	}

	// A DELIBERATE repeat well past the window must be its own operation.
	current = current.Add(11 * time.Minute)
	if w := do(); w.Code != http.StatusOK {
		t.Fatalf("deliberate repeat = %d, want 200", w.Code)
	}
	if runs != 2 {
		t.Fatalf("a deliberate repeat %s later was swallowed (%d executions)", 11*time.Minute, runs)
	}
}
