// SPDX-License-Identifier: MPL-2.0

package relay_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/ticketintake"
)

func TestRelayTicketSyncRedeemsReadsParsesAndReports(t *testing.T) {
	var method, authorization string
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, authorization = r.Method, r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"result":[{"sys_id":"tick-1","u_subject":"api.example.test","u_profile":"tls-server"}]}`))
	}))
	defer sink.Close()
	intent := ticketintake.SyncIntent{
		InstanceURL: sink.URL, TokenRef: "secret://itsm/token", SNTable: "incident",
		SubjectField: "u_subject", ProfileField: "u_profile", PageLimit: 100,
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	ch := &fakeChannel{
		jobs:     []relay.Job{{JobID: 31, Kind: relay.KindTicketSync, Attempt: 1, Payload: payload}},
		material: map[string][]byte{"secret://itsm/token": []byte("jit-token")},
	}
	if executed, err := relay.RunOnce(t.Context(), ch, sink.Client(), 1, 30); err != nil || executed != 1 {
		t.Fatalf("executed=%d err=%v reports=%+v", executed, err, ch.reports)
	}
	if method != http.MethodGet || authorization != "Bearer jit-token" || ch.redeemed != 1 {
		t.Fatalf("method=%q authorization=%q redemptions=%d", method, authorization, ch.redeemed)
	}
	var report ticketintake.SyncReport
	if err := json.Unmarshal([]byte(ch.reports[0].detail), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Tickets) != 1 || report.Tickets[0].Subject != "api.example.test" {
		t.Fatalf("report = %+v", report)
	}
}
