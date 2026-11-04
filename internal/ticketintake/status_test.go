// SPDX-License-Identifier: BUSL-1.1

package ticketintake

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func statusIntent() StatusIntent {
	return StatusIntent{Schedule: "changes", StatusID: "6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b",
		InstanceURL: "https://corp.service-now.example", TokenRef: "secret://servicenow/intake", SNTable: StatusTable,
		SourceRefs: []string{"a1b2c3", "d4e5f6"}}
}

// P13: the approval read names exactly the change requests asked for and
// nothing else.
func TestStatusEndpointReadsOnlyTheNamedChangeRequestsP13(t *testing.T) {
	endpoint, err := StatusEndpoint(statusIntent())
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Path != "/api/now/table/change_request" || q.Get("sysparm_query") != "sys_idINa1b2c3,d4e5f6" ||
		q.Get("sysparm_fields") != "sys_id,number,approval,state" || q.Get("sysparm_limit") != "2" {
		t.Fatalf("endpoint = %s", endpoint)
	}
	for name, mutate := range map[string]func(*StatusIntent){
		"another table":     func(i *StatusIntent) { i.SNTable = "incident" },
		"no tickets":        func(i *StatusIntent) { i.SourceRefs = nil },
		"a query in a ref":  func(i *StatusIntent) { i.SourceRefs = []string{"a1^ORsys_id!=x"} },
		"a repeated ticket": func(i *StatusIntent) { i.SourceRefs = []string{"a1", "a1"} },
		"an inline token":   func(i *StatusIntent) { i.TokenRef = "abc123" },
		"no read id":        func(i *StatusIntent) { i.StatusID = "" },
	} {
		intent := statusIntent()
		mutate(&intent)
		if _, err := StatusEndpoint(intent); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestParseStatusPageKeepsToTheAskedTicketsP13(t *testing.T) {
	intent := statusIntent()
	got, err := ParseStatusPage(strings.NewReader(`{"result":[
		{"sys_id":"a1b2c3","number":"CHG0030001","approval":"approved","state":"-1"},
		{"sys_id":"d4e5f6","number":"CHG0030002","approval":"Rejected","state":"4"}]}`), intent)
	if err != nil || len(got) != 2 || got[0].Approval != ApprovalApproved || got[1].Approval != ApprovalRejected || got[1].Number != "CHG0030002" {
		t.Fatalf("parsed = %+v %v", got, err)
	}
	for name, body := range map[string]string{
		"a ticket not asked for": `{"result":[{"sys_id":"zzz","approval":"approved"}]}`,
		"one ticket twice":       `{"result":[{"sys_id":"a1b2c3","approval":"approved"},{"sys_id":"a1b2c3","approval":"approved"}]}`,
		"an unexpected value":    `{"result":[{"sys_id":"a1b2c3","approval":"approved; DROP"}]}`,
	} {
		if _, err := ParseStatusPage(strings.NewReader(body), intent); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	report := StatusReport{Schedule: "changes", StatusID: intent.StatusID, ObservedAt: time.Now(), Tickets: got}
	if err := ValidateStatusReport(intent, report); err != nil {
		t.Fatal(err)
	}
	report.StatusID = "7f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b"
	if err := ValidateStatusReport(intent, report); err == nil {
		t.Fatal("a report for another read was accepted")
	}
}
