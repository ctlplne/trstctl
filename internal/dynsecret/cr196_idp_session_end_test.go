// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/infratest"
)

// A password reset does not invalidate a session that the released admin
// opened earlier. Retirement must call the IdP's session and token API.
func TestCR196OktaRetirementEndsSessionsAndTokens(t *testing.T) {
	const account = "breakglass@corp.example"
	var mu sync.Mutex
	sessions, tokens := true, true
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/users/"+account:
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/users/"+account+"/sessions" && r.URL.Query().Get("oauthTokens") == "true":
			sessions, tokens = false, false
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	b, err := NewIdPAdminBackend(IdPAdminConfig{Vendor: "okta-user", Endpoint: srv.URL,
		APIToken: []byte("fixture-admin-token"), AllowInsecureLoopback: true, HTTPClient: http.DefaultClient,
		RoleAccounts: map[string]string{"idp/breakglass": account}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx := context.Background()
	if _, _, err := b.CreateCredential(ctx, GenerateRequest{Role: "idp/breakglass", LeaseID: "new", Static: true}); err != nil {
		t.Fatal(err)
	}
	if err := b.Revoke(ctx, account+"/old"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if sessions || tokens {
		t.Fatalf("retirement left a prior IdP session or OAuth token active; calls: %s", strings.Join(calls, ", "))
	}
}

func TestCR196RetirementEndsProviderSessionsAndTokens(t *testing.T) {
	const account = "breakglass@corp.example"
	okta := infratest.StartOkta("fixture-okta-admin")
	defer okta.Close()
	entra := infratest.StartEntra("fixture-app", "fixture-app-secret")
	defer entra.Close()
	google, err := infratest.StartGoogle("rotator@corp-iam.iam.gserviceaccount.com", "admin@corp.example")
	if err != nil {
		t.Fatal(err)
	}
	defer google.Close()
	cases := []struct {
		name string
		idp  *infratest.IdP
		cfg  IdPAdminConfig
	}{
		{"okta", okta, IdPAdminConfig{Vendor: "okta-user", Endpoint: okta.URL(), APIToken: []byte("fixture-okta-admin")}},
		{"entra", entra, IdPAdminConfig{Vendor: "entra-user", Endpoint: entra.URL(), AuthorityHost: entra.URL(),
			ClientID: "fixture-app", ClientSecret: []byte("fixture-app-secret"), AzureTenant: "corp-tenant"}},
		{"google", google, IdPAdminConfig{Vendor: "google-workspace-user", Endpoint: google.URL(), AuthorityHost: google.URL() + "/token",
			ServiceAccountEmail: "rotator@corp-iam.iam.gserviceaccount.com", ServiceAccountKeyPEM: google.ServiceAccountKeyPEM(),
			Subject: "admin@corp.example"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			tc.idp.AddUser(account, "initial-password-1!", false)
			cfg := tc.cfg
			cfg.AllowInsecureLoopback, cfg.HTTPClient = true, http.DefaultClient
			cfg.RoleAccounts = map[string]string{"idp/breakglass": account}
			b, err := NewIdPAdminBackend(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			if _, _, err := b.CreateCredential(ctx, GenerateRequest{Role: "idp/breakglass", LeaseID: "new", Static: true}); err != nil {
				t.Fatal(err)
			}
			tc.idp.OpenUserSession(account)
			tc.idp.GrantUserToken(account, "app-one")
			tc.idp.GrantUserToken(account, "app-two")
			if err := b.Revoke(ctx, account+"/old"); err != nil {
				t.Fatal(err)
			}
			if sessions, grants := tc.idp.ActiveUserAccess(account); sessions != 0 || grants != 0 {
				t.Fatalf("retired administrator still has %d sessions and %d OAuth grants", sessions, grants)
			}
			tc.idp.OpenUserSession(account)
			tc.idp.GrantUserToken(account, "app-three")
			if err := b.RetireStaticRotationSessions(ctx, "wrong-role", account+"/new"); err == nil {
				t.Fatal("a different role retired the bound administrator's sessions")
			}
			tc.idp.RefuseNextSessionEnds(1)
			if err := b.RetireStaticRotationSessions(ctx, "idp/breakglass", account+"/new"); err == nil {
				t.Fatal("provider refused session revocation but retirement reported success")
			}
			if sessions, grants := tc.idp.ActiveUserAccess(account); sessions != 1 || grants != 1 {
				t.Fatalf("refused revocation unexpectedly changed access: %d sessions, %d grants", sessions, grants)
			}
			if err := b.RetireStaticRotationSessions(ctx, "idp/breakglass", account+"/new"); err != nil {
				t.Fatal("retirement retry:", err)
			}
			if sessions, grants := tc.idp.ActiveUserAccess(account); sessions != 0 || grants != 0 {
				t.Fatalf("retirement retry left %d sessions and %d grants", sessions, grants)
			}
			// A failed rotation may restore the predecessor password. That
			// reset must also end access opened with the abandoned successor.
			tc.idp.OpenUserSession(account)
			tc.idp.GrantUserToken(account, "abandoned-successor")
			predecessor, _ := json.Marshal(map[string]string{"username": account, "password": "initial-password-1!"})
			tc.idp.RefuseNextSessionEnds(1)
			if err := b.RestoreStaticCredential(ctx, "idp/breakglass", account+"/old", predecessor); err == nil {
				t.Fatal("rollback reported success while the successor's sessions remained active")
			}
			if sessions, grants := tc.idp.ActiveUserAccess(account); sessions != 1 || grants != 1 {
				t.Fatalf("refused rollback revocation changed access: %d sessions, %d grants", sessions, grants)
			}
			if err := b.RestoreStaticCredential(ctx, "idp/breakglass", account+"/old", predecessor); err != nil {
				t.Fatal("restore predecessor:", err)
			}
			if sessions, grants := tc.idp.ActiveUserAccess(account); sessions != 0 || grants != 0 {
				t.Fatalf("rollback left %d successor sessions and %d OAuth grants", sessions, grants)
			}
		})
	}
}
