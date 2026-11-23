// SPDX-License-Identifier: BUSL-1.1

package ticketintake

import "testing"

func TestCR002SourceIdentityBindsScheduleAndNormalizedInstance(t *testing.T) {
	base, err := SourceIdentity(SystemJira, "default", "https://JIRA.example.test:443/base/")
	if err != nil {
		t.Fatal(err)
	}
	equal, err := SourceIdentity(SystemJira, "", "https://jira.example.test/base")
	if err != nil || equal != base {
		t.Fatalf("same instance was split: %q %q %v", base, equal, err)
	}
	for _, tc := range []struct{ system, schedule, endpoint string }{
		{SystemJira, "other", "https://jira.example.test/base"},
		{SystemJira, "default", "https://other.example.test/base"},
		{SystemServiceNow, "default", "https://jira.example.test/base"},
	} {
		got, err := SourceIdentity(tc.system, tc.schedule, tc.endpoint)
		if err != nil || got == base {
			t.Fatalf("distinct source aliased: %q %v", got, err)
		}
	}
	if name, ok := SourceSchedule(base, SystemJira); !ok || name != "default" {
		t.Fatalf("source schedule: %q %v", name, ok)
	}
	if _, ok := SourceSchedule(base, SystemServiceNow); ok {
		t.Fatal("Jira identity accepted as ServiceNow")
	}
	for _, bad := range []string{"https://user:pass@jira.example.test", "https://jira.example.test/#changed", "https://jira.example.test/?ignored=1", "not-a-url"} {
		if _, err := SourceIdentity(SystemJira, "default", bad); err == nil {
			t.Fatalf("unsafe instance accepted: %q", bad)
		}
	}
}
