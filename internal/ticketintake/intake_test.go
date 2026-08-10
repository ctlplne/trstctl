// SPDX-License-Identifier: MPL-2.0

package ticketintake_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/ticketintake"
)

func TestServiceNowEndpointAndReportParsingAreBounded(t *testing.T) {
	intent := ticketintake.SyncIntent{
		InstanceURL: "https://example.service-now.com/root",
		TokenRef:    "secret://itsm/token", SNTable: "sc_req_item", Query: "state=1",
		SubjectField: "u_subject", ProfileField: "u_profile",
		RequesterField: "opened_by", JustificationField: "short_description",
		PageLimit: 100,
	}
	endpoint, err := ticketintake.Endpoint(intent)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(endpoint, "/api/now/table/sc_req_item?") ||
		!strings.Contains(endpoint, "sysparm_limit=100") ||
		!strings.Contains(endpoint, "sysparm_query=state%3D1") {
		t.Fatalf("bounded endpoint = %q", endpoint)
	}

	rows, err := ticketintake.Parse(strings.NewReader(`{"result":[
		{"sys_id":"tick-1","u_subject":"payments.example.test","u_profile":"tls-server",
		 "opened_by":{"display_value":"Dana Ops","value":"sys-user-1"},
		 "short_description":"rotate the listener"}
	]}`), intent)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].SysID != "tick-1" || rows[0].Requester != "Dana Ops" {
		t.Fatalf("parsed tickets = %+v", rows)
	}
}

func TestServiceNowEndpointRejectsUnboundedTableAndLimit(t *testing.T) {
	for _, intent := range []ticketintake.SyncIntent{
		{InstanceURL: "https://example.test", SNTable: "sys_user_password", PageLimit: 100},
		{InstanceURL: "https://example.test", SNTable: "incident", PageLimit: 101},
	} {
		if _, err := ticketintake.Endpoint(intent); err == nil {
			t.Fatalf("Endpoint(%+v) accepted an unbounded ticket read", intent)
		}
	}
}
