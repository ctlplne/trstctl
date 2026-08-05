// SPDX-License-Identifier: MPL-2.0

package ownership

import (
	"strings"
	"testing"
)

// A ServiceNow reference field is an object, and reading it wrong puts a sys_id
// where an owner name belongs.
//
// This is the single most likely way a CMDB integration produces garbage that
// still looks like success: every owner field fills in, every value is a 32-char
// hex string, and nobody notices until an expiry notice needs a human.
func TestReferenceFieldsResolveToSomethingAHumanCanActOn(t *testing.T) {
	t.Parallel()
	const body = `{"result":[{
		"sys_id":"ci-1","name":"payments-api",
		"owned_by":{"value":"6816f79cc0a8016401c5a33be04be441","display_value":"Payments Platform"},
		"u_application":{"value":"app-9","display_value":"APP-123"},
		"used_for":"production"
	}]}`
	recs, unattributed, err := ParseCMDB(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(unattributed) != 0 {
		t.Fatalf("unattributed = %v, want none — the CI names an owner", unattributed)
	}
	if len(recs) != 1 {
		t.Fatalf("records = %+v, want 1", recs)
	}
	if recs[0].OwnerName != "Payments Platform" {
		t.Fatalf("owner = %q, want the display value. A sys_id in an owner column is a value "+
			"nobody can route an expiry notice to, and it fills the field so the gap looks closed",
			recs[0].OwnerName)
	}
	if recs[0].ApplicationID != "APP-123" {
		t.Errorf("application = %q, want the display value", recs[0].ApplicationID)
	}
	if recs[0].SourceRef != "ci-1" {
		t.Errorf("source ref = %q, want the CI sys_id so a conflict traces back", recs[0].SourceRef)
	}
}

// A CI nobody owns is a finding, not a row to drop.
func TestUnownedCIsAreReportedNotSilentlySkipped(t *testing.T) {
	t.Parallel()
	const body = `{"result":[
		{"sys_id":"ci-1","name":"payments-api","owned_by":"Payments Platform"},
		{"sys_id":"ci-2","name":"orphan-host"}
	]}`
	recs, unattributed, err := ParseCMDB(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("records = %+v, want only the attributable one", recs)
	}
	if len(unattributed) != 1 || unattributed[0] != "orphan-host" {
		t.Fatalf("unattributed = %v, want the unowned CI named. A reconciliation that drops these "+
			"reports success on an estate it did not cover — and an asset nobody is accountable for "+
			"is exactly the thing this epic exists to surface", unattributed)
	}
}

// The owner preference order is a stated decision, not an accident of map
// iteration.
func TestOwnedByOutranksAssignedToOutranksSupportGroup(t *testing.T) {
	t.Parallel()
	all := CMDBRecord{OwnedBy: "owns", AssignedTo: "assigned", SupportGroup: "rota"}
	if got, field := cmdbOwner(all); got != "owns" || field != "owned_by" {
		t.Fatalf("owner = %q from %q, want owned_by to win: who the asset belongs to outranks "+
			"who is currently handling it", got, field)
	}
	noOwner := CMDBRecord{AssignedTo: "assigned", SupportGroup: "rota"}
	if got, _ := cmdbOwner(noOwner); got != "assigned" {
		t.Fatalf("owner = %q, want assigned_to when owned_by is empty", got)
	}
	onlyRota := CMDBRecord{SupportGroup: "rota"}
	if got, _ := cmdbOwner(onlyRota); got != "rota" {
		t.Fatalf("owner = %q, want support_group as the last resort", got)
	}
	if len(CMDBOwnerFields) != 3 || CMDBOwnerFields[0] != "owned_by" {
		t.Fatalf("CMDBOwnerFields = %v; the order is a product decision and must stay visible",
			CMDBOwnerFields)
	}
}

// Blank CMDB fields must reach Reconcile as silence, so the two halves compose
// into "a CMDB may fill in what nobody recorded and may not erase it".
func TestACMDBSilenceDoesNotEraseRecordedOwnership(t *testing.T) {
	t.Parallel()
	recs, _, err := ParseCMDB(strings.NewReader(
		`{"result":[{"sys_id":"ci-1","owned_by":"Payments Platform","used_for":"production"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	plan := Reconcile(recs[0], Existing{OwnerID: "o1", ApplicationID: "APP-123", Attested: false},
		SourceCMDB, observed)
	for _, u := range plan.Apply {
		if u.Field == "application_id" {
			t.Fatalf("a CI that said nothing about the application erased one: %+v", u)
		}
	}
}

// A CMDB answering with an unbounded body must not be able to exhaust this
// process through an integration operators think of as read-only.
func TestAnOversizedCMDBResponseIsBounded(t *testing.T) {
	t.Parallel()
	if cmdbResponseLimit <= 0 || cmdbResponseLimit > 64<<20 {
		t.Fatalf("cmdbResponseLimit = %d; an unbounded read from a remote instance is a denial of "+
			"service the operator never opted into", cmdbResponseLimit)
	}
	huge := `{"result":[{"sys_id":"ci-1","name":"` + strings.Repeat("a", cmdbResponseLimit) + `"}]}`
	if _, _, err := ParseCMDB(strings.NewReader(huge)); err == nil {
		t.Fatal("a response larger than the limit parsed successfully; the limit is not enforced")
	}
}
