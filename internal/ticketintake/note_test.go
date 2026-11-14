// SPDX-License-Identifier: BUSL-1.1

package ticketintake

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

// P13-L1: a work note names one ServiceNow ticket on a request-shaped table
// through its intake schedule's token reference; its read finds the note's
// marker, its write adds the text with the marker, and a report must answer
// for the same note.
func TestTicketNoteIntentIsBoundToOneTicketP13L1(t *testing.T) {
	intent := NoteIntent{Schedule: "changes", NoteID: NoteID("t", "r", "approved"), InstanceURL: "https://example.service-now.test/",
		TokenRef: "secret://itsm/servicenow", SNTable: "change_request", SourceRef: "a1b2c3", Text: "trstctl approved certificate request r."} // #nosec G101 -- credential reference, no credential value present (CWE-798)
	if NoteID("t", "r", "approved") != intent.NoteID || NoteID("t", "r", "denied") == intent.NoteID || NoteID("t2", "r", "approved") == intent.NoteID {
		t.Fatal("note IDs are not one per tenant, request and decision")
	}
	read, write, err := NoteEndpoints(intent)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := url.Parse(read)
	if r.Path != "/api/now/table/change_request/a1b2c3" || r.Query().Get("sysparm_fields") != "work_notes" || r.Query().Get("sysparm_display_value") != "true" ||
		write != "https://example.service-now.test/api/now/table/change_request/a1b2c3" {
		t.Fatalf("endpoints = %s %s", read, write)
	}
	body, err := NoteBody(intent)
	if err != nil {
		t.Fatal(err)
	}
	var patch map[string]string
	if json.Unmarshal(body, &patch) != nil || !strings.HasSuffix(patch["work_notes"], NoteMarker(intent.NoteID)) || !strings.HasPrefix(patch["work_notes"], intent.Text) {
		t.Fatalf("body = %s", body)
	}
	if present, err := NoteAlreadyPresent([]byte(`{"result":{"work_notes":"earlier note\n`+NoteMarker(intent.NoteID)+`"}}`), intent.NoteID); err != nil || !present {
		t.Fatalf("a ticket with the note: %v %v", present, err)
	}
	if present, err := NoteAlreadyPresent([]byte(`{"result":{"work_notes":""}}`), intent.NoteID); err != nil || present {
		t.Fatalf("a ticket without it: %v %v", present, err)
	}
	for name, bad := range map[string]func(*NoteIntent){
		"a table that is not request-shaped": func(i *NoteIntent) { i.SNTable = "sys_user" },
		"a path in the sys_id":               func(i *NoteIntent) { i.SourceRef = "a1/../b" },
		"a table prefix in the sys_id":       func(i *NoteIntent) { i.SourceRef = "change_request:a1b2c3" },
		"an inline token":                    func(i *NoteIntent) { i.TokenRef = "bearer-value" }, // #nosec G101 -- a refused non-reference, not a credential (CWE-798)
		"no text":                            func(i *NoteIntent) { i.Text = " " },
		"control characters":                 func(i *NoteIntent) { i.Text = "approved\x1b[2J" },
		"a text past the bound":              func(i *NoteIntent) { i.Text = strings.Repeat("x", MaxNoteText+1) },
		"no note ID":                         func(i *NoteIntent) { i.NoteID = "" },
	} {
		i := intent
		bad(&i)
		if ValidateNoteIntent(i) == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	report := NoteReport{Schedule: "changes", NoteID: intent.NoteID, Outcome: NoteAdded, ObservedAt: time.Now()}
	if err := ValidateNoteReport(intent, report); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]NoteReport{
		"another note":    {Schedule: "changes", NoteID: NoteID("t", "r", "denied"), Outcome: NoteAdded, ObservedAt: time.Now()},
		"another outcome": {Schedule: "changes", NoteID: intent.NoteID, Outcome: "deleted", ObservedAt: time.Now()},
		"no time":         {Schedule: "changes", NoteID: intent.NoteID, Outcome: NotePresent},
	} {
		if ValidateNoteReport(intent, bad) == nil {
			t.Fatalf("a report of %s was accepted", name)
		}
	}
}
