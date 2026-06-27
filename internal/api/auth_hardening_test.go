package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAuthCallbackRejectsMissingNonce: the OIDC callback must reject a request
// that carries no nonce cookie, rather than proceeding with an empty (skipped)
// nonce — closing the replay window (B1's OIDC-nonce major).
func TestAuthCallbackRejectsMissingNonce(t *testing.T) {
	h, _ := authAPI(t)
	login := httptest.NewRecorder()
	h.ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	state := cookieValue(login.Result().Cookies(), "trstctl_oidc_state")
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=good-code&state="+state, nil)
	for _, name := range []string{"trstctl_oidc_prelogin", "trstctl_oidc_state", "trstctl_oidc_pkce"} {
		req.AddCookie(&http.Cookie{Name: name, Value: cookieValue(login.Result().Cookies(), name)})
	}
	// Deliberately NO trstctl_oidc_nonce cookie.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusFound {
		t.Fatalf("callback without a nonce cookie returned 302 (it must be rejected): %s", rec.Header().Get("Location"))
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-trstctl_session" && c.Value != "" {
			t.Fatal("callback without a nonce cookie established a session")
		}
	}
}
