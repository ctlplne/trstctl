// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"encoding/json"
	"strings"
	"testing"
	"trstctl.com/trstctl/internal/accessdesktop"
)

func desktopADBinding() accessdesktop.Binding {
	return accessdesktop.Binding{AccountKind: "active_directory", Accounts: []accessdesktop.BoundAccount{{Reference: "CN=approved,OU=services,DC=example,DC=test", Username: "approved"}}}
}
func TestADDesktopCredentialRefusesUnreviewedPrincipal(t *testing.T) {
	binding := desktopADBinding()
	for _, raw := range []string{`{"username":"foreign","bind_dn":"CN=approved,OU=services,DC=example,DC=test","password":"owned"}`, `{"username":"approved","bind_dn":"CN=foreign,OU=services,DC=example,DC=test","password":"owned"}`, `{"username":"approved","password":"owned"}`} {
		_, held, err := parseDesktopCredentialForBinding([]byte(raw), binding)
		if held != nil {
			held.Destroy()
		}
		if err == nil || !strings.Contains(err.Error(), "reviewed account") {
			t.Fatal("unreviewed desktop principal was not refused before native sign-in")
		}
	}
	raw := []byte(`{"username":"approved","bind_dn":"CN=approved,OU=services,DC=example,DC=test","password":"owned"}`)
	username, held, err := parseDesktopCredentialForBinding(raw, binding)
	if err != nil || username != "approved" {
		t.Fatal("reviewed desktop credential refused")
	}
	held.Destroy()
}
func FuzzADDesktopCredential(f *testing.F) {
	f.Add([]byte(`{"username":"approved","bind_dn":"CN=approved,OU=services,DC=example,DC=test","password":"owned-fuzz"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		username, held, err := parseDesktopCredentialForBinding(raw, desktopADBinding())
		if err != nil {
			return
		}
		defer held.Destroy()
		if username != "approved" {
			t.Fatal("unreviewed logon name accepted")
		}
		var public struct {
			Reference string `json:"bind_dn"`
		}
		if json.Unmarshal(raw, &public) != nil || !strings.EqualFold(public.Reference, "CN=approved,OU=services,DC=example,DC=test") {
			t.Fatal("unreviewed directory reference accepted")
		}
	})
}
