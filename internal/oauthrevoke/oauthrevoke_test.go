// SPDX-License-Identifier: BUSL-1.1

package oauthrevoke_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/oauthrevoke"
	"trstctl.com/trstctl/internal/oauthrevoke/oauthrevoketest"
)

const a170Token = "a170-admin-token" // #nosec G101 -- fabricated fixture credential (CWE-798)

func provider(t *testing.T, s *oauthrevoketest.Server, name string, token string) oauthrevoke.Provider {
	t.Helper()
	p, closeFn, err := oauthrevoke.New(oauthrevoke.Connection{Provider: name, BaseURL: s.URL(), Token: []byte(token), Doer: s.Client()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeFn)
	return p
}

// A170/A171: each provider revokes exactly the grants one user gave one client
// and reports what it confirmed; a second revoke finds nothing left; blocking
// deactivates the app where the provider's API can, and is refused where it
// cannot.
func TestProvidersRevokeAndBlockWhatTheProviderConfirms(t *testing.T) {
	ctx := context.Background()
	s := oauthrevoketest.New(a170Token)
	t.Cleanup(s.Close)
	s.SeedOkta("00u-alice", "0oa-exfil", 2, 1, "0oa-exfil")
	s.SeedOkta("00u-bob", "0oa-exfil", 1, 0, "")
	s.SeedGraph("sp-exfil",
		oauthrevoketest.GraphGrant{ID: "g1", ClientID: "sp-exfil", PrincipalID: "user-carol"},
		oauthrevoketest.GraphGrant{ID: "g2", ClientID: "sp-exfil", PrincipalID: "user-carol"},
		oauthrevoketest.GraphGrant{ID: "g3", ClientID: "sp-exfil", PrincipalID: "user-dave"})
	s.SeedGoogle("erin@example.com", "client-exfil.apps.googleusercontent.com")

	okta := provider(t, s, "okta", a170Token)
	if got, err := okta.RevokeGrant(ctx, oauthrevoke.Grant{Principal: "00u-alice", AppID: "0oa-exfil"}); err != nil || got.Status != oauthrevoke.Confirmed {
		t.Fatalf("okta revoke = %+v %v", got, err)
	}
	if grants, tokens := s.OktaGrants("00u-alice", "0oa-exfil"); grants != 0 || tokens != 0 {
		t.Fatalf("okta left grants %d tokens %d", grants, tokens)
	}
	if grants, _ := s.OktaGrants("00u-bob", "0oa-exfil"); grants != 1 {
		t.Fatal("okta revoke touched another user's grant")
	}
	if got, err := okta.RevokeGrant(ctx, oauthrevoke.Grant{Principal: "00u-alice", AppID: "0oa-exfil"}); err != nil || got.Status != oauthrevoke.AlreadyAbsent {
		t.Fatalf("okta second revoke = %+v %v", got, err)
	}
	if got, err := okta.BlockApp(ctx, "0oa-exfil"); err != nil || got.Status != oauthrevoke.Confirmed || s.OktaAppActive("0oa-exfil") {
		t.Fatalf("okta block = %+v %v active=%v", got, err, s.OktaAppActive("0oa-exfil"))
	}

	graph := provider(t, s, "entra", a170Token)
	if got, err := graph.RevokeGrant(ctx, oauthrevoke.Grant{Principal: "user-carol", AppID: "sp-exfil"}); err != nil || got.Status != oauthrevoke.Confirmed || got.Removed != 2 {
		t.Fatalf("graph revoke = %+v %v", got, err)
	}
	if s.GraphGrants("sp-exfil", "user-carol") != 0 || s.GraphGrants("sp-exfil", "user-dave") != 1 {
		t.Fatal("graph revoke left the user's grants or took another user's")
	}
	if got, err := graph.BlockApp(ctx, "sp-exfil"); err != nil || got.Status != oauthrevoke.Confirmed || s.GraphSPEnabled("sp-exfil") {
		t.Fatalf("graph block = %+v %v", got, err)
	}

	google := provider(t, s, "google-workspace", a170Token)
	if got, err := google.RevokeGrant(ctx, oauthrevoke.Grant{Principal: "erin@example.com", AppID: "client-exfil.apps.googleusercontent.com"}); err != nil ||
		got.Status != oauthrevoke.Confirmed || s.GoogleToken("erin@example.com", "client-exfil.apps.googleusercontent.com") {
		t.Fatalf("google revoke = %+v %v", got, err)
	}
	if _, err := google.BlockApp(ctx, "client-exfil.apps.googleusercontent.com"); !errors.Is(err, oauthrevoke.ErrUnsupported) {
		t.Fatalf("google block = %v; want ErrUnsupported", err)
	}
	if s.Unauthorized() != 0 {
		t.Fatalf("unauthorized requests = %d", s.Unauthorized())
	}

	wrong := provider(t, s, "okta", "wrong-token")
	if _, err := wrong.RevokeGrant(ctx, oauthrevoke.Grant{Principal: "00u-bob", AppID: "0oa-exfil"}); err == nil {
		t.Fatal("a wrong token revoked a grant")
	}
	if _, _, err := oauthrevoke.New(oauthrevoke.Connection{Provider: "slack", BaseURL: s.URL(), Token: []byte(a170Token), Doer: s.Client()}); err == nil {
		t.Fatal("an unserved provider was accepted")
	}
}

// A170-L1: Microsoft Graph's admin consent for every user (consentType
// AllPrincipals, no principal) is its own grant. A per-user revoke never
// reaches it; the tenant-wide revoke deletes exactly it, leaving each user's
// own grants, and a second one finds nothing left. Okta and Google have no
// such grant for this action to name.
func TestGraphRevokesTheTenantWideAdminConsentA170L1(t *testing.T) {
	ctx := context.Background()
	s := oauthrevoketest.New(a170Token)
	t.Cleanup(s.Close)
	s.SeedGraph("sp-exfil",
		oauthrevoketest.GraphGrant{ID: "g-all", ClientID: "sp-exfil", ConsentType: "AllPrincipals"},
		oauthrevoketest.GraphGrant{ID: "g-carol", ClientID: "sp-exfil", PrincipalID: "user-carol"},
		oauthrevoketest.GraphGrant{ID: "g-other-app", ClientID: "sp-other", ConsentType: "AllPrincipals"})
	graph := provider(t, s, "entra", a170Token)
	if got, err := graph.RevokeGrant(ctx, oauthrevoke.Grant{Principal: "user-carol", AppID: "sp-exfil"}); err != nil || got.Removed != 1 {
		t.Fatalf("per-user revoke = %+v %v", got, err)
	}
	if s.GraphTenantWideGrants("sp-exfil") != 1 {
		t.Fatal("a per-user revoke touched the tenant-wide admin consent")
	}
	got, err := graph.RevokeGrant(ctx, oauthrevoke.Grant{AppID: "sp-exfil", TenantWide: true})
	if err != nil || got.Status != oauthrevoke.Confirmed || got.Removed != 1 {
		t.Fatalf("tenant-wide revoke = %+v %v", got, err)
	}
	if s.GraphTenantWideGrants("sp-exfil") != 0 || s.GraphTenantWideGrants("sp-other") != 1 {
		t.Fatal("the tenant-wide revoke left the admin consent or took another application's")
	}
	if again, err := graph.RevokeGrant(ctx, oauthrevoke.Grant{AppID: "sp-exfil", TenantWide: true}); err != nil || again.Status != oauthrevoke.AlreadyAbsent {
		t.Fatalf("second tenant-wide revoke = %+v %v", again, err)
	}
	for _, name := range []string{"okta", "google-workspace"} {
		if _, err := provider(t, s, name, a170Token).RevokeGrant(ctx, oauthrevoke.Grant{AppID: "app", TenantWide: true}); !errors.Is(err, oauthrevoke.ErrUnsupported) {
			t.Fatalf("%s tenant-wide revoke = %v; want ErrUnsupported", name, err)
		}
	}
}
