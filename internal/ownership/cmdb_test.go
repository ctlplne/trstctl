// SPDX-License-Identifier: BUSL-1.1

package ownership

import (
	"net/url"
	"reflect"
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

// AUD-46: a page number is not a stable continuation. If ci-10 disappears
// while page two is waiting, OFFSET 500 moves ci-501 into page one and page two
// skips it. A sys_id keyset does not move: the next read starts strictly after
// the last row the prior signed report actually carried.
func TestCMDBPageEndpointUsesAStableKeysetCursorAUD46(t *testing.T) {
	t.Parallel()
	endpoint, err := CMDBPageEndpoint("https://example.service-now.com/root", "active=true", 500, "ci-0500")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Path != "/root/api/now/table/cmdb_ci" {
		t.Fatalf("path = %q, want the fixed read-only cmdb_ci table", parsed.Path)
	}
	query := parsed.Query()
	if got := query.Get("sysparm_query"); got != "active=true^sys_id>ci-0500^ORDERBYsys_id" {
		t.Fatalf("sysparm_query = %q, want the operator filter, strict continuation, and stable order", got)
	}
	if got := query.Get("sysparm_limit"); got != "500" {
		t.Fatalf("sysparm_limit = %q, want 500", got)
	}
	if got := query.Get("sysparm_offset"); got != "" {
		t.Fatalf("sysparm_offset = %q; offset pagination skips rows when the CMDB changes mid-sweep", got)
	}
	if got := query.Get("sysparm_suppress_pagination_header"); got != "false" {
		t.Fatalf("pagination header flag = %q, want false so the report can carry an honest denominator", got)
	}
}

// The continuation is derived from EVERY returned CI, including a row with no
// owner. Deriving it only from ownership.Record would repeat or skip an unowned
// tail row and make the coverage count disagree with the CMDB response.
func TestParseCMDBPageCarriesEveryOrderedSourceReferenceAUD46(t *testing.T) {
	t.Parallel()
	page, err := ParseCMDBPage(strings.NewReader(`{"result":[
		{"sys_id":"ci-0501","name":"owned","owned_by":"payments"},
		{"sys_id":"ci-0502","name":"orphan"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := page.SourceRefs, []string{"ci-0501", "ci-0502"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("source refs = %v, want %v", got, want)
	}
	if len(page.Records) != 1 || page.Records[0].SourceRef != "ci-0501" {
		t.Fatalf("records = %+v, want the attributable CI", page.Records)
	}
	if len(page.Unattributed) != 1 || page.Unattributed[0] != "orphan" {
		t.Fatalf("unattributed = %v, want the unowned CI represented", page.Unattributed)
	}
	if page.NextCursor != "ci-0502" {
		t.Fatalf("next cursor = %q, want the final raw CI even though it has no owner", page.NextCursor)
	}
}

func TestParseCMDBPageRejectsMissingOrUnorderedContinuationKeysAUD46(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"missing sys_id":    `{"result":[{"name":"api","owned_by":"payments"}]}`,
		"duplicate sys_id":  `{"result":[{"sys_id":"ci-1"},{"sys_id":"ci-1"}]}`,
		"descending sys_id": `{"result":[{"sys_id":"ci-2"},{"sys_id":"ci-1"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCMDBPage(strings.NewReader(body)); err == nil {
				t.Fatal("page parsed without a strict ordered key; a next cursor derived from it can duplicate or skip CIs")
			}
		})
	}
}

func FuzzParseCMDBPageNeverInventsContinuationAUD46(f *testing.F) {
	f.Add(`{"result":[]}`)
	f.Add(`{"result":[{"sys_id":"ci-0001","owned_by":"payments"},{"sys_id":"ci-0002","name":"orphan"}]}`)
	f.Add(`{"result":[{"sys_id":"ci-0002"},{"sys_id":"ci-0001"}]}`)
	f.Fuzz(func(t *testing.T, body string) {
		page, err := ParseCMDBPage(strings.NewReader(body))
		if err != nil {
			return
		}
		if len(page.Records)+len(page.Unattributed) != len(page.SourceRefs) {
			t.Fatalf("accepted page classified %d owned + %d unowned rows but carried %d continuation keys",
				len(page.Records), len(page.Unattributed), len(page.SourceRefs))
		}
		if len(page.SourceRefs) == 0 {
			if page.NextCursor != "" {
				t.Fatalf("empty accepted page invented cursor %q", page.NextCursor)
			}
			return
		}
		for i := 1; i < len(page.SourceRefs); i++ {
			if page.SourceRefs[i] <= page.SourceRefs[i-1] {
				t.Fatalf("accepted page is not strictly ordered: %q then %q", page.SourceRefs[i-1], page.SourceRefs[i])
			}
		}
		if want := page.SourceRefs[len(page.SourceRefs)-1]; page.NextCursor != want {
			t.Fatalf("accepted page cursor = %q, want final raw key %q", page.NextCursor, want)
		}
	})
}
