// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auth"
)

// TestDirectorySignInIsFreshA277: a directory sign-in verifies the password
// the person just typed, so its browser session carries that moment as its
// sign-in time and can start a high-risk session.
func TestDirectorySignInIsFreshA277(t *testing.T) {
	cfg, sessions := authConfig()
	cfg.LDAPEnabled = true
	cfg.VerifyLDAPLogin = func(_ context.Context, username string, _ []byte) (auth.Claims, error) {
		return auth.Claims{Subject: username, Email: username + "@example.test"}, nil
	}
	h := api.New(nil, nil, nil, api.WithAuth(cfg))
	before := time.Now().Add(-time.Second).Unix()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/ldap/login", bytes.NewReader([]byte(`{"username":"alice","password":"correct horse"}`)))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("POST /auth/ldap/login = %d: %s", rec.Code, rec.Body.String())
	}
	var token string
	for _, c := range rec.Result().Cookies() {
		if c.HttpOnly && c.Value != "" && c.Name != "trstctl_csrf" {
			token = c.Value
		}
	}
	sess, err := sessions.VerifyContext(context.Background(), token)
	if err != nil || sess.AuthTime < before || sess.AuthTime > time.Now().Unix() {
		t.Fatalf("directory session sign-in time %d (%v), want the bind moment", sess.AuthTime, err)
	}
}
