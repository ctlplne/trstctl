// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"testing"

	"trstctl.com/trstctl/internal/store"
)

// A103: a schedule's dispatch is canonicalized before it is recorded:
// channel IDs as the notification API spells them, deduplicated and bounded,
// and one ServiceNow ticket with a normalized instance URL and table.
func TestNormalizeComplianceReportDispatch(t *testing.T) {
	got, err := normalizeComplianceReportDispatch(&store.ComplianceReportDispatch{
		Channels: []string{" Webhook ", "webhook", "Microsoft Teams"},
		Ticket:   &store.ComplianceReportTicket{Provider: "ServiceNow", InstanceURL: "https://grc.service-now.example.test/", TokenRef: " secret://itsm/grc "}, // #nosec G101 -- fabricated fixture reference; no value is real (CWE-798)
	})
	if err != nil || len(got.Channels) != 2 || got.Channels[0] != "webhook" || got.Channels[1] != "msteams" ||
		got.Ticket.Provider != "servicenow" || got.Ticket.InstanceURL != "https://grc.service-now.example.test" ||
		got.Ticket.Table != "incident" || got.Ticket.TokenRef != "secret://itsm/grc" {
		t.Fatalf("normalized = %+v ticket=%+v err=%v", got, got.Ticket, err)
	}
	if got, err := normalizeComplianceReportDispatch(&store.ComplianceReportDispatch{}); err != nil || got != nil {
		t.Fatalf("an empty dispatch = %+v, %v; want archive only", got, err)
	}
	for name, bad := range map[string]*store.ComplianceReportDispatch{
		"channel with spaces": {Channels: []string{"web hook!"}},
		"nine channels":       {Channels: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}},
		"jira":                {Ticket: &store.ComplianceReportTicket{Provider: "jira", InstanceURL: "https://x.example.test", TokenRef: "r"}},
		"url with query":      {Ticket: &store.ComplianceReportTicket{Provider: "servicenow", InstanceURL: "https://x.example.test/?token=1", TokenRef: "r"}},
		"bad table":           {Ticket: &store.ComplianceReportTicket{Provider: "servicenow", InstanceURL: "https://x.example.test", Table: "problem", TokenRef: "r"}},
		"no token ref":        {Ticket: &store.ComplianceReportTicket{Provider: "servicenow", InstanceURL: "https://x.example.test"}},
	} {
		if _, err := normalizeComplianceReportDispatch(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
