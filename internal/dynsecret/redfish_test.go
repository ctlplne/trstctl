// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/infratest"
)

// TestRedfishRotationA271: the bound account's password changes through a
// Redfish session, the new password opens a session and the old one does
// not; a controller that answers but keeps the old password fails
// verification and is restored; every session is logged out; discovery lists
// each account with its RoleId and never a password.
func TestRedfishRotationA271(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	bmc := infratest.StartRedfish("Administrator", "admin-password-1")
	defer bmc.Close()
	bmc.AddAccount("ops", "ops-password-1", "Operator")
	bmc.AddAccount("monitor", "monitor-password-1", "ReadOnly")
	b, err := NewRedfishBackend(RedfishConfig{Endpoint: bmc.URL(), HTTPClient: bmc.Client(), AdminUser: "Administrator",
		AdminPassword: []byte("admin-password-1"), RoleAccounts: map[string]string{"bmc/ops": "ops"}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := NewRedfishBackend(RedfishConfig{Endpoint: bmc.URL(), HTTPClient: bmc.Client(), AdminUser: "Administrator",
		AdminPassword: []byte("x"), RoleAccounts: map[string]string{"bmc/admin": "Administrator"}}); err == nil {
		t.Fatal("a role bound to the administrator was accepted")
	}
	ref, credential, err := b.CreateCredential(ctx, GenerateRequest{Role: "bmc/ops", LeaseID: "lease-1", Static: true})
	if err != nil {
		t.Fatal(err)
	}
	var issued struct{ Username, Password string }
	if err = json.Unmarshal(credential, &issued); err != nil || issued.Username != "ops" || ref != "ops/lease-1" || string(bmc.Password("ops")) != issued.Password {
		t.Fatalf("credential %q %v", ref, err)
	}
	if err = b.VerifyCredential(ctx, credential); err != nil || !bmc.SignsIn("ops", issued.Password) || bmc.SignsIn("ops", "ops-password-1") {
		t.Fatal("the account did not move to the new password alone:", err)
	}
	bmc.DropNextChanges(1)
	_, next, err := b.CreateCredential(ctx, GenerateRequest{Role: "bmc/ops", LeaseID: "lease-2", Static: true})
	if err != nil {
		t.Fatal(err)
	}
	if b.VerifyCredential(ctx, next) == nil {
		t.Fatal("a change the controller did not take verified")
	}
	if err = b.RestoreStaticCredential(ctx, "bmc/ops", ref, credential); err != nil || !bmc.SignsIn("ops", issued.Password) {
		t.Fatal("rollback:", err)
	}
	accounts, err := b.DiscoverPrivilegedAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, a := range accounts {
		found[a.Name] = a.Privileges[0]
	}
	if found["ops"] != "role Operator" || found["monitor"] != "role ReadOnly" || found["Administrator"] != "role Administrator" {
		t.Fatalf("discovered %v", found)
	}
	if bmc.Sessions() != 0 {
		t.Fatalf("%d sessions were left open", bmc.Sessions())
	}
}

// A271-D2: a controller that answers a new session with any success carrying
// X-Auth-Token opens a session (DMTF's reference mockup answers 204, real
// controllers 201); a success without a token, or a refusal, does not.
func TestRedfishSessionAcceptsAnySuccessCarryingAToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, tc := range []struct {
		name   string
		status int
		token  string
		opens  bool
	}{
		{"201 Created with a token", http.StatusCreated, "token-201", true},
		{"204 No Content with a token (DMTF's mockup)", http.StatusNoContent, "token-204", true},
		{"200 OK with a token", http.StatusOK, "token-200", true},
		{"204 No Content without a token", http.StatusNoContent, "", false},
		{"401 Unauthorized with a token", http.StatusUnauthorized, "token-401", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var deleted []string
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/redfish/v1/SessionService/Sessions":
					if tc.token != "" {
						w.Header().Set("X-Auth-Token", tc.token)
					}
					w.Header().Set("Location", "/redfish/v1/SessionService/Sessions/1")
					w.WriteHeader(tc.status)
				case r.Method == http.MethodDelete && r.URL.Path == "/redfish/v1/SessionService/Sessions/1":
					mu.Lock()
					deleted = append(deleted, r.Header.Get("X-Auth-Token"))
					mu.Unlock()
					w.WriteHeader(http.StatusNoContent)
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			b, err := NewRedfishBackend(RedfishConfig{Endpoint: srv.URL, HTTPClient: srv.Client(), AdminUser: "Administrator",
				AdminPassword: []byte("admin-password-1"), RoleAccounts: map[string]string{"bmc/ops": "ops"}})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			err = b.VerifyCredential(ctx, []byte(`{"username":"ops","password":"ops-password-1"}`))
			if opened := err == nil; opened != tc.opens {
				t.Fatalf("session opened = %v (%v), want %v", opened, err, tc.opens)
			}
			mu.Lock()
			defer mu.Unlock()
			if tc.opens && (len(deleted) != 1 || deleted[0] != tc.token) {
				t.Fatalf("the session was not ended with its own token: %v", deleted)
			}
		})
	}
}
