// SPDX-License-Identifier: MPL-2.0

package api

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/store"
)

// TestDatastoreTimeoutMapsToStructured503 is the OPS-TIMEOUTS-001 serving
// half: a bounded datastore failure (pool-acquire timeout or statement
// deadline) must surface as a structured 503 problem, not a generic 500.
func TestDatastoreTimeoutMapsToStructured503(t *testing.T) {
	a := New(nil, nil, nil)
	rec := httptest.NewRecorder()
	a.writeError(rec, fmt.Errorf("begin tenant tx: %w", store.ErrDatastoreBusy))
	if rec.Code != 503 {
		t.Fatalf("busy datastore mapped to %d, want 503", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"datastore is busy", "retry"} {
		if !containsFold(body, want) {
			t.Fatalf("503 problem body %q must mention %q", body, want)
		}
	}
}

func containsFold(haystack, needle string) bool {
	// small helper: case-insensitive contains without extra imports
	lower := func(s string) string {
		b := []byte(s)
		for i, c := range b {
			if 'A' <= c && c <= 'Z' {
				b[i] = c + 'a' - 'A'
			}
		}
		return string(b)
	}
	h, n := lower(haystack), lower(needle)
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}
