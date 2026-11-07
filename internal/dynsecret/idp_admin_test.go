// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/infratest"
)

// TestIdPAdminRotationA272: each identity provider's administration API sets
// the bound super administrator's password; Okta and Entra prove it with one
// non-interactive sign-in (an MFA step after the right password still proves
// it, and Okta's pending transaction is cancelled), Google cannot prove it;
// a wrong password is refused without retries, so the lockout counter only
// moves by the attempts made and a right password resets it; a change the
// provider keeps out is restored.
func TestIdPAdminRotationA272(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	okta := infratest.StartOkta("okta-api-token-1")
	defer okta.Close()
	entra := infratest.StartEntra("app-client-1", "app-secret-1")
	defer entra.Close()
	google, err := infratest.StartGoogle("rotator@corp-iam.iam.gserviceaccount.com", "admin@corp.example")
	if err != nil {
		t.Fatal(err)
	}
	defer google.Close()
	for _, tc := range []struct {
		name string
		idp  *infratest.IdP
		cfg  IdPAdminConfig
		mfa  bool
		self bool
	}{
		{"okta", okta, IdPAdminConfig{Vendor: "okta-user", Endpoint: okta.URL(), APIToken: []byte("okta-api-token-1")}, true, true},
		{"entra", entra, IdPAdminConfig{Vendor: "entra-user", Endpoint: entra.URL(), AuthorityHost: entra.URL(), ClientID: "app-client-1",
			ClientSecret: []byte("app-secret-1"), AzureTenant: "corp-tenant"}, true, true},
		{"google", google, IdPAdminConfig{Vendor: "google-workspace-user", Endpoint: google.URL(), AuthorityHost: google.URL() + "/token",
			ServiceAccountEmail: "rotator@corp-iam.iam.gserviceaccount.com", ServiceAccountKeyPEM: google.ServiceAccountKeyPEM(),
			Subject: "admin@corp.example"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.idp.AddUser("breakglass@corp.example", "initial-password-1!", tc.mfa)
			cfg := tc.cfg
			cfg.AllowInsecureLoopback, cfg.HTTPClient = true, http.DefaultClient
			cfg.RoleAccounts = map[string]string{"idp/breakglass": "breakglass@corp.example"}
			b, err := NewIdPAdminBackend(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			ref, credential, err := b.CreateCredential(ctx, GenerateRequest{Role: "idp/breakglass", LeaseID: "lease-1", Static: true})
			if err != nil {
				t.Fatal(err)
			}
			var issued struct{ Username, Password string }
			if err = json.Unmarshal(credential, &issued); err != nil || ref != "breakglass@corp.example/lease-1" || string(tc.idp.Password("breakglass@corp.example")) != issued.Password {
				t.Fatalf("credential %q %v", ref, err)
			}
			verify := b.VerifyCredential(ctx, credential)
			if tc.self && verify != nil {
				t.Fatal("the new password was not proved:", verify)
			}
			if !tc.self && !errors.Is(verify, ErrNoSelfProof) {
				t.Fatal("a provider with no sign-in check claimed a proof:", verify)
			}
			if tc.idp.Pending() != 0 {
				t.Fatal("an MFA transaction was left pending")
			}
			if tc.self {
				stale, _ := json.Marshal(map[string]string{"username": "breakglass@corp.example", "password": "initial-password-1!"})
				if b.VerifyCredential(ctx, stale) == nil || tc.idp.Failed("breakglass@corp.example") != 1 {
					t.Fatalf("the old password: failed=%d", tc.idp.Failed("breakglass@corp.example"))
				}
			}
			tc.idp.DropNextChanges(1)
			_, next, err := b.CreateCredential(ctx, GenerateRequest{Role: "idp/breakglass", LeaseID: "lease-2", Static: true})
			if err != nil {
				t.Fatal(err)
			}
			if tc.self && b.VerifyCredential(ctx, next) == nil {
				t.Fatal("a change the provider kept out was proved")
			}
			if err = b.RestoreStaticCredential(ctx, "idp/breakglass", ref, credential); err != nil || string(tc.idp.Password("breakglass@corp.example")) != issued.Password {
				t.Fatal("rollback:", err)
			}
			if tc.idp.Locked("breakglass@corp.example") || tc.idp.Failed("breakglass@corp.example") != 0 {
				t.Fatalf("lockout counter after a proved restore: failed=%d locked=%v", tc.idp.Failed("breakglass@corp.example"), tc.idp.Locked("breakglass@corp.example"))
			}
		})
	}
}
