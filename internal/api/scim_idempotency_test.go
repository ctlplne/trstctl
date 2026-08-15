// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
	first := scimIdempotencyKey(req(), body)
	again := scimIdempotencyKey(req(), body)
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
	if got := scimIdempotencyKey(r, []byte(`{"active":false}`)); got != "provider-supplied-key" {
		t.Fatalf("explicit key = %q, want it used verbatim", got)
	}
}

// TestSCIMDerivedKeySeparatesDistinctOperations keeps the derivation honest:
// different targets or different bodies must never share a key, or one user's
// deprovision would suppress another's.
func TestSCIMDerivedKeySeparatesDistinctOperations(t *testing.T) {
	alice := httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/alice", nil)
	bob := httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/bob", nil)
	body := []byte(`{"active":false}`)

	if scimIdempotencyKey(alice, body) == scimIdempotencyKey(bob, body) {
		t.Fatal("two different users share an idempotency key; one deprovision would suppress the other")
	}
	if scimIdempotencyKey(alice, body) == scimIdempotencyKey(alice, []byte(`{"active":true}`)) {
		t.Fatal("deprovision and reprovision share an idempotency key")
	}
}
