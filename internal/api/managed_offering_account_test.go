// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestManagedTenantBrowserCannotOmitReviewedAccount(t *testing.T) {
	a := New(nil, nil, nil)
	for _, authorization := range []string{"", "Bearer non-secret-fixture"} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/managed-offering/tenants", nil)
		r.Header.Set("Authorization", authorization)
		// The normal route guard authenticates before this handler. Presence of
		// the browser cookie requires a reviewed account even if another auth
		// header is also present; an old browser must reload, not mutate blindly.
		r.AddCookie(&http.Cookie{Name: a.browserSessionCookieName(), Value: "synthetic-session"})
		w := httptest.NewRecorder()
		a.provisionManagedTenant(w, r)
		if w.Code != http.StatusConflict {
			t.Fatalf("browser without reviewed account = %d, want 409", w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/managed-offering/tenants", nil)
	if err := a.checkManagedTenantReviewedAccount(r); err != nil {
		t.Fatalf("non-browser caller must retain normal authentication path: %v", err)
	}
}
