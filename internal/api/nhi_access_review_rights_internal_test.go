// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"strings"
	"testing"
)

// Q1-L8: a lease's rights ride on its review item as graph:rights
// references: the login, its grants (cut at a whole grant within the bound)
// and when they were read; unknown with the target's reason; or not read. A
// credential that is not a lease carries none.
func TestLeaseRightsRefsQ1L8(t *testing.T) {
	resolved := leaseRightsRefs(map[string]string{
		"credential_kind": "dynamic_secret_lease", "access_status": "resolved", "login": "trstctl_ro",
		"grants": "CONNECT on database app; SELECT on public.orders", "access_checked_at": "2026-11-14T14:50:15Z",
	})
	if strings.Join(resolved, "|") != "graph:rights-login:trstctl_ro|graph:rights:CONNECT on database app; SELECT on public.orders|graph:rights-read:2026-11-14T14:50:15Z" {
		t.Fatalf("resolved = %q", resolved)
	}
	long := make([]string, 0, 40)
	for i := 0; i < 40; i++ {
		long = append(long, "SELECT on public.table_with_a_long_name_"+string(rune('a'+i%26)))
	}
	cut := leaseRightsRefs(map[string]string{"credential_kind": "dynamic_secret_lease", "access_status": "resolved", "grants": strings.Join(long, "; ")})
	grants := cut[0]
	if len(grants) > maxRightsRef || !strings.HasSuffix(grants, "; and more") || strings.Contains(strings.TrimSuffix(grants, "; and more"), "; and") ||
		!strings.HasPrefix(grants, "graph:rights:SELECT on public.table_with_a_long_name_a") {
		t.Fatalf("a long grant list = %q (%d)", grants, len(grants))
	}
	for _, part := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(grants, "graph:rights:"), "; and more"), "; ") {
		if !strings.HasPrefix(part, "SELECT on public.table_with_a_long_name_") || len(part) != len(long[0]) {
			t.Fatalf("a grant was cut: %q", part)
		}
	}
	for name, tc := range map[string]struct {
		attrs map[string]string
		want  string
	}{
		"unknown":   {map[string]string{"credential_kind": "dynamic_secret_lease", "access_status": "unknown", "access_reason": "access_denied"}, "graph:rights-unknown:access_denied"},
		"not read":  {map[string]string{"credential_kind": "dynamic_secret_lease", "access_status": "not_read"}, "graph:rights-not-read"},
		"a session": {map[string]string{"credential_kind": "pam_session"}, ""},
	} {
		if got := strings.Join(leaseRightsRefs(tc.attrs), "|"); got != tc.want {
			t.Fatalf("%s = %q, want %q", name, got, tc.want)
		}
	}
}
