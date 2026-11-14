// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/ticketintake"
)

// P13-L1: the relay reads the ticket's work notes with the redeemed intake
// token, adds the note only when its marker is not there, and reports which;
// a ticket that refuses the token fails the job with nothing written.
func TestRelayTicketNoteIsAddedOnceP13L1(t *testing.T) {
	const tokenRef = "secret://itsm/servicenow/p13l1" // #nosec G101 -- credential reference, no credential value present (CWE-798)
	const token = "p13l1-servicenow-token"            // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
	var mu sync.Mutex
	notes := ""
	var calls []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, r.Method)
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/now/table/change_request/a1b2c3" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]string{"work_notes": notes}})
		case http.MethodPatch:
			raw, _ := io.ReadAll(r.Body)
			var body map[string]string
			_ = json.Unmarshal(raw, &body)
			notes = body["work_notes"] + "\n" + notes
			_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]string{"sys_id": "a1b2c3"}})
		}
	}))
	t.Cleanup(srv.Close)
	intent := ticketintake.NoteIntent{Schedule: "changes", NoteID: ticketintake.NoteID("t", "r", "approved"), InstanceURL: srv.URL,
		TokenRef: tokenRef, SNTable: "change_request", SourceRef: "a1b2c3", Text: "trstctl approved certificate request r."}
	run := func(material string) (string, string, []string) {
		t.Helper()
		mu.Lock()
		calls = nil
		mu.Unlock()
		payload, _ := json.Marshal(intent)
		ch := &fakeChannel{jobs: []relay.Job{{JobID: 31, Kind: relay.KindTicketNote, Attempt: 1, Payload: payload}},
			material: map[string][]byte{tokenRef: []byte(material)}}
		if _, err := relay.RunOnce(t.Context(), ch, srv.Client(), 4, 30); err != nil || len(ch.reports) != 1 {
			t.Fatalf("relay = %v; reports %+v", err, ch.reports)
		}
		mu.Lock()
		defer mu.Unlock()
		return ch.reports[0].outcome, ch.reports[0].detail, append([]string(nil), calls...)
	}
	outcome, detail, got := run(token)
	var report ticketintake.NoteReport
	if outcome != relay.OutcomeExecuted || json.Unmarshal([]byte(detail), &report) != nil || report.Outcome != ticketintake.NoteAdded ||
		strings.Join(got, ",") != "GET,PATCH" || !strings.Contains(notes, ticketintake.NoteMarker(intent.NoteID)) {
		t.Fatalf("the first run = %s %s %v; notes %q", outcome, detail, got, notes)
	}
	outcome, detail, got = run(token)
	if outcome != relay.OutcomeExecuted || json.Unmarshal([]byte(detail), &report) != nil || report.Outcome != ticketintake.NotePresent ||
		strings.Join(got, ",") != "GET" || strings.Count(notes, ticketintake.NoteMarker(intent.NoteID)) != 1 {
		t.Fatalf("the replayed run = %s %s %v; notes %q", outcome, detail, got, notes)
	}
	if outcome, detail, got = run("wrong-token"); outcome != relay.OutcomeFailed || !strings.Contains(detail, "status 401") || strings.Join(got, ",") != "GET" {
		t.Fatalf("a refused token = %s %s %v", outcome, detail, got)
	}
}
