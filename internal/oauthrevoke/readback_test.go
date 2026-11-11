// SPDX-License-Identifier: BUSL-1.1

package oauthrevoke_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/oauthrevoke"
	"trstctl.com/trstctl/internal/oauthrevoke/oauthrevoketest"
)

// A170-L2: every action reads back what the provider confirmed. A revoke whose
// grants, tokens or token are gone, and a block whose app or service principal
// shows deactivated, carries the read back in its detail; a provider that
// acknowledges the removal but still shows the grant (or the app active) is a
// StillPresentError naming what is left, which is not retried.
func TestProviderActionsReadBackWhatTheProviderConfirmedA170L2(t *testing.T) {
	ctx := context.Background()
	seed := func(s *oauthrevoketest.Server) {
		s.SeedOkta("00u-alice", "0oa-exfil", 1, 1, "0oa-exfil")
		s.SeedGraph("sp-exfil", oauthrevoketest.GraphGrant{ID: "g1", ClientID: "sp-exfil", PrincipalID: "user-carol"})
		s.SeedGoogle("erin@example.com", "client-exfil.apps.googleusercontent.com")
	}
	connect := func(s *oauthrevoketest.Server, name string) oauthrevoke.Provider {
		t.Helper()
		p, closeFn, err := oauthrevoke.New(oauthrevoke.Connection{Provider: name, BaseURL: s.URL(), Token: []byte(a170Token), Doer: s.Client(),
			ReadBack: oauthrevoke.ReadBack{Attempts: 2, Wait: time.Millisecond}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(closeFn)
		return p
	}
	type step struct {
		name string
		run  func(oauthrevoke.Provider) (oauthrevoke.Result, error)
		prov string
	}
	steps := []step{
		{"okta revoke", func(p oauthrevoke.Provider) (oauthrevoke.Result, error) {
			return p.RevokeGrant(ctx, oauthrevoke.Grant{Principal: "00u-alice", AppID: "0oa-exfil"})
		}, "okta"},
		{"okta block", func(p oauthrevoke.Provider) (oauthrevoke.Result, error) { return p.BlockApp(ctx, "0oa-exfil") }, "okta"},
		{"graph revoke", func(p oauthrevoke.Provider) (oauthrevoke.Result, error) {
			return p.RevokeGrant(ctx, oauthrevoke.Grant{Principal: "user-carol", AppID: "sp-exfil"})
		}, "entra"},
		{"graph block", func(p oauthrevoke.Provider) (oauthrevoke.Result, error) { return p.BlockApp(ctx, "sp-exfil") }, "entra"},
		{"google revoke", func(p oauthrevoke.Provider) (oauthrevoke.Result, error) {
			return p.RevokeGrant(ctx, oauthrevoke.Grant{Principal: "erin@example.com", AppID: "client-exfil.apps.googleusercontent.com"})
		}, "google"},
	}
	honest := oauthrevoketest.New(a170Token)
	t.Cleanup(honest.Close)
	seed(honest)
	for _, st := range steps {
		got, err := st.run(connect(honest, st.prov))
		if err != nil || got.Status != oauthrevoke.Confirmed || !strings.Contains(got.Detail, "; read back: ") {
			t.Fatalf("%s = %+v %v; want confirmed with a read back", st.name, got, err)
		}
	}
	// A read the provider refuses does not undo what it confirmed.
	refusing := oauthrevoketest.New(a170Token)
	t.Cleanup(refusing.Close)
	seed(refusing)
	refusing.SetRefuseReads(true)
	if got, err := steps[0].run(connect(refusing, "okta")); err != nil || got.Status != oauthrevoke.Confirmed ||
		!strings.Contains(got.Detail, "read back refused: the provider answered status 403") {
		t.Fatalf("okta revoke with reads refused = %+v %v; want confirmed, saying the read back was refused", got, err)
	}
	sticky := oauthrevoketest.New(a170Token)
	t.Cleanup(sticky.Close)
	seed(sticky)
	sticky.SetSticky(true)
	for _, st := range steps {
		got, err := st.run(connect(sticky, st.prov))
		var still *oauthrevoke.StillPresentError
		if !errors.As(err, &still) || oauthrevoke.Retryable(err) || !strings.Contains(still.Detail, "still") {
			t.Fatalf("%s against a provider that keeps the grant = %+v %v; want a StillPresentError that is not retried", st.name, got, err)
		}
	}
}
