// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/orchestrator"
)

// CR-008 (design D5): a ServiceNow ticket or incident closure was matched to an
// operator binding when it was queued. The workers match it again against the
// bindings as they are now, as the API matches: the normalized instance URL, the
// trimmed token reference, a binding that is not relay_only and the same
// allow_private_endpoint. A withdrawn or changed binding no longer serves a queued
// row, and a private row reaches only the CIDRs its binding grants now.
func TestQueuedServiceNowRowsFollowTheOperatorsCurrentBindingsCR008(t *testing.T) {
	const (
		ref        = "env:TRSTCTL_CR008_SERVICENOW_TOKEN" // #nosec G101 -- fabricated fixture reference; no value is real (CWE-798)
		otherRef   = "env:TRSTCTL_CR008_OTHER_TOKEN"      // #nosec G101 -- fabricated fixture reference; no value is real (CWE-798)
		closeNotes = "Closed in trstctl (incident cr008-incident): rotated"
	)
	t.Setenv("TRSTCTL_CR008_SERVICENOW_TOKEN", "cr008-servicenow-token")
	t.Setenv("TRSTCTL_CR008_OTHER_TOKEN", "cr008-other-token")
	sink := newRematchServiceNowSink(t, closeNotes)
	sinkCIDR := serviceNowSinkCIDR(t, sink.server.URL)
	queuedUnder := api.ServiceNowBinding{InstanceURL: sink.server.URL, TokenRef: ref, AllowPrivateEndpoint: true, PrivateEgressCIDRs: []string{sinkCIDR}}
	changed := func(change func(*api.ServiceNowBinding)) []api.ServiceNowBinding {
		b := queuedUnder
		b.PrivateEgressCIDRs = append([]string(nil), queuedUnder.PrivateEgressCIDRs...)
		change(&b)
		return []api.ServiceNowBinding{b}
	}
	const rematch = "no longer matches an operator-approved binding"
	for _, tc := range []struct {
		name       string
		bindings   []api.ServiceNowBinding
		rowPrivate bool
		sent       bool
		refusal    string
		// dialed: the refusal comes from the egress guard at dial time, which
		// sends nothing but cannot prove that to the outbox, so the row retries.
		dialed bool
	}{
		{name: "the binding it was queued under", bindings: []api.ServiceNowBinding{queuedUnder}, rowPrivate: true, sent: true},
		{name: "the same binding written differently, CIDRs reordered", rowPrivate: true, sent: true,
			bindings: changed(func(b *api.ServiceNowBinding) {
				b.InstanceURL += "/"
				b.TokenRef = "  " + ref + " "
				b.PrivateEgressCIDRs = []string{"192.0.2.0/24", sinkCIDR}
			})},
		{name: "a withdrawn binding", rowPrivate: true, refusal: rematch,
			bindings: []api.ServiceNowBinding{{InstanceURL: "https://cr008.service-now.example", TokenRef: ref}}},
		{name: "no bindings at all", rowPrivate: true, refusal: rematch},
		{name: "a narrowed private grant", rowPrivate: true, refusal: "refusing to connect to a non-public address", dialed: true,
			bindings: changed(func(b *api.ServiceNowBinding) { b.PrivateEgressCIDRs = []string{"192.0.2.0/24"} })},
		{name: "a binding made relay-only", rowPrivate: true, refusal: rematch,
			bindings: changed(func(b *api.ServiceNowBinding) { b.RelayOnly = true })},
		{name: "a binding that names another token", rowPrivate: true, refusal: rematch,
			bindings: changed(func(b *api.ServiceNowBinding) { b.TokenRef = otherRef })},
		{name: "a private binding made public", rowPrivate: true, refusal: rematch,
			bindings: changed(func(b *api.ServiceNowBinding) { b.AllowPrivateEndpoint = false; b.PrivateEgressCIDRs = nil })},
		{name: "a public row under a binding made private", rowPrivate: false, refusal: rematch,
			bindings: []api.ServiceNowBinding{queuedUnder}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &issuanceDispatcher{serviceNowBindings: tc.bindings}
			var cidrs []string
			if tc.rowPrivate {
				cidrs = []string{sinkCIDR}
			}
			ticket, err := json.Marshal(orchestrator.ServiceNowTicketRequest{ID: "cr008-ticket", InstanceURL: sink.server.URL,
				Table: "incident", TokenRef: ref, ShortDescription: "CR-008 re-match", AllowPrivateEndpoint: tc.rowPrivate,
				PrivateEgressCIDRs: cidrs})
			if err != nil {
				t.Fatal(err)
			}
			closure, err := json.Marshal(orchestrator.ServiceNowCloseRequest{IncidentID: "cr008-incident", InstanceURL: sink.server.URL,
				Table: "incident", TokenRef: ref, CorrelationID: orchestrator.IncidentCorrelationID("cr008-incident"),
				CloseNotes: closeNotes, AllowPrivateEndpoint: tc.rowPrivate, PrivateEgressCIDRs: cidrs})
			if err != nil {
				t.Fatal(err)
			}
			for _, worker := range []struct {
				name   string
				handle func() error
			}{
				{"ticket", func() error {
					return d.handleServiceNowTicket(t.Context(), orchestrator.Message{TenantID: servedTestTenant,
						IdempotencyKey: "cr008-ticket", Payload: ticket})
				}},
				{"incident close", func() error {
					return d.handleServiceNowClose(t.Context(), orchestrator.Message{TenantID: servedTestTenant,
						IdempotencyKey: "cr008-close", Payload: closure})
				}},
			} {
				before := sink.count()
				err := worker.handle()
				sent := sink.count() - before
				if tc.sent {
					if err != nil || sent == 0 {
						t.Fatalf("%s worker: err %v after %d requests; the row should still be served", worker.name, err, sent)
					}
					if got := sink.lastAuthorization(); got != "Bearer cr008-servicenow-token" {
						t.Fatalf("%s worker sent Authorization %q", worker.name, got)
					}
					continue
				}
				if err == nil || sent != 0 {
					t.Fatalf("%s worker: err %v after %d requests; the row should be refused with nothing sent", worker.name, err, sent)
				}
				if !tc.dialed && !orchestrator.IsDefiniteNoEffect(err) {
					t.Fatalf("%s worker refusal is not a definite no-effect: %v", worker.name, err)
				}
				if !strings.Contains(err.Error(), tc.refusal) {
					t.Fatalf("%s worker refusal = %v, want it to say %q", worker.name, err, tc.refusal)
				}
				if strings.Contains(err.Error(), "TRSTCTL_CR008") {
					t.Fatalf("%s worker refusal quotes the token reference: %v", worker.name, err)
				}
			}
		})
	}
}

type rematchServiceNowSink struct {
	server   *httptest.Server
	mu       sync.Mutex
	requests int
	auth     string
}

// newRematchServiceNowSink answers a ticket POST with a created record and an
// incident query with one incident already resolved with closeNotes, so both
// workers finish after one request each.
func newRematchServiceNowSink(t *testing.T, closeNotes string) *rematchServiceNowSink {
	t.Helper()
	sink := &rematchServiceNowSink{}
	sink.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sink.mu.Lock()
		sink.requests++
		sink.auth = r.Header.Get("Authorization")
		sink.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{"result": []map[string]string{{"sys_id": "cr008", "state": "6", "close_notes": closeNotes}}})
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"result":{"sys_id":"cr008"}}`))
	}))
	t.Cleanup(sink.server.Close)
	return sink
}

func (s *rematchServiceNowSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

func (s *rematchServiceNowSink) lastAuthorization() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.auth
}
