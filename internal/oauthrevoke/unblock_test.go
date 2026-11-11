// SPDX-License-Identifier: BUSL-1.1

package oauthrevoke_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/oauthrevoke"
	"trstctl.com/trstctl/internal/oauthrevoke/oauthrevoketest"
)

// A171-L1: an application blocked at the provider can be unblocked through the
// same admin connection: Okta reactivates the app and Graph re-enables the
// service principal, each read back; Google, whose API cannot block, cannot
// unblock either.
func TestProvidersUnblockWhatTheyBlockedA171L1(t *testing.T) {
	ctx := context.Background()
	s := oauthrevoketest.New(a170Token)
	t.Cleanup(s.Close)
	s.SeedOkta("00u-alice", "0oa-exfil", 0, 0, "0oa-exfil")
	s.SeedGraph("sp-exfil")
	for name, app := range map[string]string{"okta": "0oa-exfil", "entra": "sp-exfil"} {
		p := provider(t, s, name, a170Token)
		if _, err := p.BlockApp(ctx, app); err != nil {
			t.Fatalf("%s block: %v", name, err)
		}
		got, err := p.UnblockApp(ctx, app)
		if err != nil || got.Status != oauthrevoke.Confirmed || !strings.Contains(got.Detail, "; read back: ") {
			t.Fatalf("%s unblock = %+v %v", name, got, err)
		}
	}
	if !s.OktaAppActive("0oa-exfil") || !s.GraphSPEnabled("sp-exfil") {
		t.Fatal("the unblock did not reactivate the app or re-enable the service principal")
	}
	if got, err := provider(t, s, "okta", a170Token).UnblockApp(ctx, "0oa-missing"); err != nil || got.Status != oauthrevoke.AlreadyAbsent {
		t.Fatalf("unblocking an app the provider does not have = %+v %v", got, err)
	}
	if _, err := provider(t, s, "google-workspace", a170Token).UnblockApp(ctx, "client.apps.googleusercontent.com"); !errors.Is(err, oauthrevoke.ErrUnsupported) {
		t.Fatalf("google unblock = %v; want ErrUnsupported", err)
	}
}
