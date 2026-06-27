package api_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/breakglass"
	"trstctl.com/trstctl/internal/crypto"
)

func TestBreakglassAdminLoginDisabledIs404Invisible(t *testing.T) {
	h := api.New(nil, nil, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/breakglass/login", bytes.NewReader([]byte(`{"actor_id":"admin","password":"pw"}`))))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled breakglass admin login = %d, want 404", rec.Code)
	}
}

func TestBreakglassAdminLoginIssuesAdminSession(t *testing.T) {
	sessions := auth.NewSessionIssuer([]byte("breakglass-session-secret-012345"), time.Hour)
	svc := breakglass.NewAdminService(breakglass.AdminConfig{
		Enabled: true, TenantID: testTenant, Sessions: sessions,
		Params:      crypto.Argon2idParams{MemoryKiB: 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32},
		MaxFailures: 3, Lockout: time.Minute,
	})
	if err := svc.SetPassword("admin-1", []byte("correct horse battery staple")); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	h := api.New(nil, nil, nil, api.WithBreakglassAdmin(svc))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/breakglass/login",
		bytes.NewReader([]byte(`{"actor_id":"admin-1","password":"correct horse battery staple"}`)))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("breakglass admin login = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	tok := cookieValue(rec.Result().Cookies(), "__Host-trstctl_session")
	if tok == "" {
		t.Fatal("breakglass admin login did not set session cookie")
	}
	sess, err := sessions.Verify(tok)
	if err != nil {
		t.Fatalf("session verify: %v", err)
	}
	if sess.Subject != "admin-1" || sess.TenantID != testTenant {
		t.Fatalf("session = %+v", sess)
	}
}
