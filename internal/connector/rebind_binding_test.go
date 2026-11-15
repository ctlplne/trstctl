// SPDX-License-Identifier: BUSL-1.1

package connector_test

import (
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
)

// TestRebindBindingMissingNamesEachFamilysBindingA166L2T1: each family that
// re-binds only through a target-named binding is told what its target lacks,
// and nothing once the target names it; a family that needs no binding is
// never refused here.
func TestRebindBindingMissingNamesEachFamilysBindingA166L2T1(t *testing.T) {
	for _, tc := range []struct {
		family, missing, present, field string
	}{
		{"aws-acm", `{"region":"us-east-1"}`, `{"listener_arn":"arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/web/50dc6c495c0c9188/f2f7dc8efc522ab2"}`, "listener_arn"},
		{"fortigate", `{}`, `{"bind_to":"admin"}`, "bind_to"},
		{"paloalto", `{"ssl_tls_profile":"web"}`, `{"ssl_tls_profile":"web","commit_admin":"trstctl"}`, "commit_admin"},
		{"cisco", `{}`, `{"node_hostname":"ise-1"}`, "node_hostname"},
		{"gcp-certificate-manager", `{}`, `{"certificate_map_entry":"web/www"}`, "certificate_map_entry"},
	} {
		if reason := connector.RebindBindingMissing(tc.family, json.RawMessage(tc.missing)); !strings.Contains(reason, tc.field) {
			t.Errorf("%s without %s: %q", tc.family, tc.field, reason)
		}
		if reason := connector.RebindBindingMissing(tc.family, json.RawMessage(tc.present)); reason != "" {
			t.Errorf("%s with %s: %q", tc.family, tc.field, reason)
		}
	}
	for _, family := range []string{"f5", "netscaler", "a10", "kemp", "azure-keyvault", "nginx"} {
		if reason := connector.RebindBindingMissing(family, nil); reason != "" {
			t.Errorf("%s needs no binding, got %q", family, reason)
		}
	}
}
