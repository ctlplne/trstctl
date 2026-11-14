// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/ticketintake"
)

// p13l1Tickets is a ServiceNow stand-in for work notes: a change request's
// work notes read with sysparm_display_value, and a PATCH that adds one.
type p13l1Tickets struct {
	mu      sync.Mutex
	notes   map[string]string
	patches int
}

func (s *p13l1Tickets) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		id := strings.TrimPrefix(r.URL.Path, "/api/now/table/change_request/")
		if _, ok := s.notes[id]; !ok || id == r.URL.Path {
			t.Errorf("unexpected ServiceNow call: %s %s", r.Method, r.URL.String())
			http.Error(w, "unexpected", http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]string{"work_notes": s.notes[id]}})
		case http.MethodPatch:
			raw, _ := io.ReadAll(r.Body)
			var body map[string]string
			_ = json.Unmarshal(raw, &body)
			s.patches++
			s.notes[id] = body["work_notes"] + "\n\n" + s.notes[id]
			_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]string{"sys_id": id}})
		default:
			http.Error(w, "unexpected", http.StatusMethodNotAllowed)
		}
	})
}

// P13-L1: every trstctl decision on a request ServiceNow intake opened goes
// back to its ticket as a work note. Approving one change's request and
// denying another's queues one note each, through the intake schedule's
// token, for a network relay; the production relay adds each note to its
// change once, with the decision, the decider and the reason; a request
// opened in trstctl itself queues none.
func TestServedTrstctlDecisionsAreWorkNotesOnTheirTicketsP13L1(t *testing.T) {
	sn := &p13l1Tickets{notes: map[string]string{"c0ffee1": "", "c0ffee2": ""}}
	stand := httptest.NewTLSServer(sn.handler(t))
	t.Cleanup(stand.Close)
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{relay.KindTicketNote})
	ctx := t.Context()
	const tokenName = "p13l1-intake-token" // #nosec G101 -- the name of a test-only secret, not a credential (CWE-798)
	sealed, err := h.srv.sealTenantSecretForTest(ctx, h.tenant, tokenName, []byte("servicenow-intake-token"))
	if err != nil {
		t.Fatal(err)
	}
	seedApplicationSecretFixture(t, h.store, h.tenant, tokenName, sealed)
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write")
	if status, out := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/issuance-requests/intake-schedule", tok, "p13l1-intake",
		map[string]any{"system": "servicenow", "name": "changes", "instance_url": stand.URL, "token_ref": "secret://" + tokenName,
			"sn_table": "change_request", "subject_field": "u_subject", "profile_field": "u_profile", "requester_field": "requested_by",
			"interval_seconds": 3600, "enabled": true}); status != http.StatusOK {
		t.Fatalf("configure intake: %d %s", status, out)
	}
	sched, found, err := h.store.GetTicketIntakeSchedule(ctx, h.tenant, "servicenow", "changes")
	if err != nil || !found {
		t.Fatalf("schedule: %v %v", found, err)
	}
	intent := ticketSyncIntent(sched)
	expected := 2
	if _, err := h.srv.ingestTicketReport(ctx, h.tenant, "p13l1-sync", intent, ticketintake.SyncReport{
		Schedule: "changes", System: "servicenow", SweepID: intent.SweepID, ObservedAt: time.Now().UTC(),
		SourceRefs: []string{"c0ffee1", "c0ffee2"}, ReadCount: 2, ExpectedCount: &expected, Complete: true,
		Tickets: []ticketintake.Ticket{
			{SourceRef: "c0ffee1", Subject: "orders.example.test", Profile: "tls-server", Requester: "dana@example.test"},
			{SourceRef: "c0ffee2", Subject: "old-billing.example.test", Profile: "tls-server", Requester: "lee@example.test"},
		}}); err != nil {
		t.Fatal(err)
	}
	approve, found, err := h.store.IssuanceRequestByTicket(ctx, h.tenant, "change_request:c0ffee1")
	if err != nil || !found {
		t.Fatalf("request for c0ffee1: %v %v", found, err)
	}
	deny, found, err := h.store.IssuanceRequestByTicket(ctx, h.tenant, "change_request:c0ffee2")
	if err != nil || !found {
		t.Fatalf("request for c0ffee2: %v %v", found, err)
	}
	if _, err := h.srv.orch.DecideIssuanceRequest(ctx, h.tenant, approve.ID, "approved", "reviewer@example.test", "matches the change plan", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.DecideIssuanceRequest(ctx, h.tenant, deny.ID, "denied", "reviewer@example.test", "the service is being retired", ""); err != nil {
		t.Fatal(err)
	}
	// A request opened in trstctl itself has no ticket to write to.
	own, err := h.srv.orch.OpenIssuanceRequest(ctx, h.tenant, projections.IssuanceRequestOpened{Subject: "own.example.test", Profile: "tls-server",
		Requester: "dana@example.test", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.DecideIssuanceRequest(ctx, h.tenant, own.ID, "approved", "reviewer@example.test", "fine", ""); err != nil {
		t.Fatal(err)
	}
	notesQueued := func() int {
		t.Helper()
		var n int
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = 'ticket.note'`, h.tenant).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := notesQueued(); n != 2 {
		t.Fatalf("%d ticket notes queued; want one for each intake-opened request's decision", n)
	}

	channel := &sshCollectionServedChannel{t: t, h: h}
	if count, err := relay.RunOnce(ctx, channel, stand.Client(), 2, 120); err != nil || count != 2 {
		for _, r := range channel.reports {
			t.Logf("report: %s %s", r.Outcome, r.Detail)
		}
		t.Fatalf("production relay = %d %v", count, err)
	}
	sn.mu.Lock()
	approvedNotes, deniedNotes, patches := sn.notes["c0ffee1"], sn.notes["c0ffee2"], sn.patches
	sn.mu.Unlock()
	if patches != 2 ||
		!strings.Contains(approvedNotes, "trstctl approved certificate request "+approve.ID) || !strings.Contains(approvedNotes, "reviewer@example.test") ||
		!strings.Contains(approvedNotes, "matches the change plan") ||
		!strings.Contains(approvedNotes, ticketintake.NoteMarker(ticketintake.NoteID(h.tenant, approve.ID, "approved"))) {
		t.Fatalf("the approved change's notes = %q (%d writes)", approvedNotes, patches)
	}
	if !strings.Contains(deniedNotes, "trstctl denied certificate request "+deny.ID) || !strings.Contains(deniedNotes, "the service is being retired") {
		t.Fatalf("the denied change's notes = %q", deniedNotes)
	}
	t.Logf("P13L1_WORK_NOTES_OK approved=%s denied=%s notes=%d", approve.ID, deny.ID, patches)
}
