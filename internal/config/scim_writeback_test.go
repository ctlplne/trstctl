// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// A73: a SCIM token's directory writeback is configured as a pair, and the
// endpoint is https, or http only to a loopback host.
func TestSCIMWritebackConfigIsAPairWithAnHTTPSEndpoint(t *testing.T) {
	base := SCIMToken{Name: "okta", TenantID: "11111111-1111-1111-1111-111111111111", TokenFile: "/etc/trstctl/scim.token"} // #nosec G101 -- fixture file paths, not credential values (CWE-798)
	for name, tc := range map[string]struct {
		token SCIMToken
		want  string
	}{
		"endpoint without token file": {SCIMToken{Name: base.Name, TenantID: base.TenantID, TokenFile: base.TokenFile, WritebackEndpoint: "https://idp.example/scim/v2"}, "set together"},
		"plain http to a remote host": {SCIMToken{Name: base.Name, TenantID: base.TenantID, TokenFile: base.TokenFile, WritebackEndpoint: "http://idp.example/scim/v2", WritebackTokenFile: "/etc/trstctl/wb.token"}, "must use https"}, // #nosec G101 -- fixture file paths, not credential values (CWE-798)
		"relative endpoint":           {SCIMToken{Name: base.Name, TenantID: base.TenantID, TokenFile: base.TokenFile, WritebackEndpoint: "scim/v2", WritebackTokenFile: "/etc/trstctl/wb.token"}, "absolute URL"},                      // #nosec G101 -- fixture file paths, not credential values (CWE-798)
	} {
		err := SCIM{Enabled: true, Tokens: []SCIMToken{tc.token}}.ValidateEnabled()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
	for _, endpoint := range []string{"https://idp.example/scim/v2", "http://127.0.0.1:8080/scim/v2", "http://localhost/scim/v2"} {
		token := SCIMToken{Name: base.Name, TenantID: base.TenantID, TokenFile: base.TokenFile, WritebackEndpoint: endpoint, WritebackTokenFile: "/etc/trstctl/wb.token"} // #nosec G101 -- fixture file paths, not credential values (CWE-798)
		if err := (SCIM{Enabled: true, Tokens: []SCIMToken{token}}).ValidateEnabled(); err != nil {
			t.Fatalf("%s: unexpected refusal %v", endpoint, err)
		}
	}
	if (SCIM{Enabled: true, Tokens: []SCIMToken{base}}).Tokens[0].WritebackConfigured() {
		t.Fatal("a token without writeback fields reads as configured")
	}
}
