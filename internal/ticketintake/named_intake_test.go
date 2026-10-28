// SPDX-License-Identifier: BUSL-1.1

package ticketintake_test

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ticketintake"
)

func TestNamedIntakeOwnerMappingUsesTheConfiguredMailboxOnly(t *testing.T) {
	for _, tc := range []struct{ system, field, payload, want string }{
		{"servicenow", "assigned_to.email", `{"result":[{"sys_id":"row1","u_subject":"a.example","u_profile":"tls-server","assigned_to.email":{"value":"OPS@EXAMPLE.TEST","display_value":"Ops Team"}}]}`, "ops@example.test"},
		{"servicenow", "assigned_to.email", `{"result":[{"sys_id":"row1","assigned_to":{"display_value":"ops@example.test","value":"a-sys-id"}}]}`, ""},
		{"jira", "assignee.emailAddress", `{"issues":[{"id":"1","key":"OPS-1","fields":{"assignee":{"displayName":"Ops","emailAddress":"ops@example.test","accountId":"atlassian-id"}}}],"isLast":true}`, "ops@example.test"},
		{"jira", "assignee.emailAddress", `{"issues":[{"id":"1","key":"OPS-1","fields":{"assignee":{"displayName":"ops@example.test","accountId":"atlassian-id"},"reporter":{"emailAddress":"requester@example.test"}}}],"isLast":true}`, ""},
	} {
		t.Run(tc.system+tc.want, func(t *testing.T) {
			intent := ticketintake.SyncIntent{Schedule: "operations", System: tc.system, InstanceURL: "https://tickets.example.test", SNTable: "incident", JiraProject: "OPS", SubjectField: "u_subject", ProfileField: "u_profile", OwnerField: tc.field, PageLimit: 100}
			endpoint, err := ticketintake.Endpoint(intent)
			if err != nil {
				t.Fatal(err)
			}
			parsed, _ := url.Parse(endpoint)
			if tc.system == "servicenow" && !strings.Contains(parsed.Query().Get("sysparm_fields"), tc.field) {
				t.Fatal("dot-walked email was not requested")
			}
			if tc.system == "jira" && !strings.Contains(parsed.Query().Get("fields"), "assignee") {
				t.Fatal("Jira parent was not requested")
			}
			page, err := ticketintake.ParsePage(strings.NewReader(tc.payload), intent)
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Tickets) != 1 || page.Tickets[0].OwnerEmail != tc.want {
				t.Fatalf("owner mapping %+v want %q", page.Tickets, tc.want)
			}
		})
	}
}

func TestNamedIntakeReportCannotAdvanceAnotherSchedule(t *testing.T) {
	intent := ticketintake.SyncIntent{Schedule: "operations", System: "jira", SweepID: "a2250000-0000-4000-8000-000000000001", PageLimit: 100}
	report := ticketintake.SyncReport{Schedule: "operations", System: intent.System, SweepID: intent.SweepID, ObservedAt: time.Now(), Complete: true}
	if err := ticketintake.ValidateReport(intent, report); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"finance", "", "../operations"} {
		report.Schedule = name
		if err := ticketintake.ValidateReport(intent, report); err == nil {
			t.Fatalf("accepted schedule %q for operations", name)
		}
	}
	intent.Schedule = ""
	report.Schedule = "default"
	if err := ticketintake.ValidateReport(intent, report); err != nil {
		t.Fatalf("legacy default: %v", err)
	}
}
