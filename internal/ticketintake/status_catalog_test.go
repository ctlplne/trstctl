// SPDX-License-Identifier: BUSL-1.1

package ticketintake

import (
	"net/url"
	"testing"
)

// P13-L2: a status read may name catalog requested items and requests as
// well as change requests, each on its own table; any other table is
// refused, and a decision's reason names the ticket by its kind.
func TestStatusReadsCatalogRequestsP13L2(t *testing.T) {
	for table, noun := range map[string]string{"change_request": "change", "sc_req_item": "requested item", "sc_request": "request"} {
		intent := StatusIntent{Schedule: "catalog", StatusID: "8f2e7c5a-1b2c-4d3e-8f4a-5b6c7d8e9f01",
			InstanceURL: "https://corp.service-now.example", TokenRef: "secret://servicenow/intake", SNTable: table, SourceRefs: []string{"a1b2c3"}} // #nosec G101 -- credential reference, no credential value present (CWE-798)
		endpoint, err := StatusEndpoint(intent)
		if err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		u, _ := url.Parse(endpoint)
		if u.Path != "/api/now/table/"+table || u.Query().Get("sysparm_query") != "sys_idINa1b2c3" {
			t.Fatalf("%s endpoint = %s", table, endpoint)
		}
		if StatusTicketNoun(table) != noun {
			t.Fatalf("%s is named %q", table, StatusTicketNoun(table))
		}
	}
	other := StatusIntent{Schedule: "users", StatusID: "8f2e7c5a-1b2c-4d3e-8f4a-5b6c7d8e9f01", InstanceURL: "https://corp.service-now.example",
		TokenRef: "secret://servicenow/intake", SNTable: "incident", SourceRefs: []string{"a1b2c3"}} // #nosec G101 -- credential reference, no credential value present (CWE-798)
	if _, err := StatusEndpoint(other); err == nil {
		t.Fatal("an incident's approval decided a request")
	}
}
