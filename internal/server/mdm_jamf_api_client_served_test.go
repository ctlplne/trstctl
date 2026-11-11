// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/mdm"
)

// A156-L1: a Jamf poll schedule names a Jamf Pro API client instead of a
// hand-rotated bearer. The schedule stores and serves only the client ID and
// refuses one on an Intune schedule, a malformed ID, or a base its secret
// would cross in clear text. The production relay then redeems the client
// secret, exchanges it at the Jamf Pro stand-in for an access token, reads the
// inventory with it, and later pushes an approved device check-in with a
// token from a fresh exchange: the stand-in answers only the exchanged token,
// and the secret is sent nowhere but the token endpoint.
func TestServedJamfScheduleReadsAndChecksInThroughAnAPIClientA156L1(t *testing.T) {
	const (
		clientID = "00000000-0000-4000-8000-00000000a15c"
		secret   = "a156l1-served-client-secret" // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
		access   = "a156l1-served-access-token"
	)
	var mu sync.Mutex
	var calls []string
	stand := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/oauth/token":
			if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "client_credentials" ||
				r.PostForm.Get("client_id") != clientID || r.PostForm.Get("client_secret") != secret {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"` + access + `","scope":"api-role:2","token_type":"Bearer","expires_in":299}`))
		case r.Header.Get("Authorization") != "Bearer "+access:
			w.WriteHeader(http.StatusUnauthorized)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/computers-inventory":
			_, _ = w.Write([]byte(`{"results":[{"id":"417","general":{"name":"mac-a156l1","lastContactTime":"2026-11-11T09:00:00Z"},"hardware":{"serialNumber":"SER-A156L1"}}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/JSSResource/computercommands/command/BlankPush/id/417":
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer stand.Close()
	standCalls := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), calls...)
	}

	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{relay.KindMDMCheckIn, agentJobKindMDMSync}, func(d *Deps) {
		d.RequiredApprovals = 1
	})
	ctx := t.Context()
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "a156l1", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	sealed, err := h.srv.sealTenantSecretForTest(ctx, h.tenant, "a156l1-jamf-client-secret", []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	seedApplicationSecretFixture(t, h.store, h.tenant, "a156l1-jamf-client-secret", sealed)
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "a156l1-requester", "certs:write", "certs:read")
	reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "a156l1-reviewer", "certs:issue")
	call := func(token, method, path, key string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h.servedHarness, method, path, token, key, body)
		if status != want {
			t.Fatalf("%s %s = %d, want %d: %s", method, path, status, want, raw)
		}
		return raw
	}
	schedule := func(changes map[string]any) map[string]any {
		body := map[string]any{"mdm": "jamf", "base_url": stand.URL, "token_ref": "secret://a156l1-jamf-client-secret",
			"interval_seconds": 3600, "enabled": true, "execution": "relay", "required_agent_id": agentRowID(h.tenant, h.agent),
			"jamf_api_client": map[string]any{"client_id": clientID}}
		for k, v := range changes {
			body[k] = v
		}
		return body
	}
	for name, body := range map[string]map[string]any{
		"an API client on Intune":  schedule(map[string]any{"mdm": "intune", "base_url": "https://graph.microsoft.com"}),
		"a malformed client ID":    schedule(map[string]any{"jamf_api_client": map[string]any{"client_id": "jamf-client"}}),
		"a plain http Jamf server": schedule(map[string]any{"base_url": "http://jamf.internal.example"}),
	} {
		call(requester, http.MethodPut, "/api/v1/mdm/poll-schedule", "a156l1-bad-"+name, body, http.StatusBadRequest)
	}
	var saved struct {
		JamfAPIClient *mdm.JamfAPIClient `json:"jamf_api_client"`
		Guidance      string             `json:"guidance"`
	}
	if err := json.Unmarshal(call(requester, http.MethodPut, "/api/v1/mdm/poll-schedule", "a156l1-schedule", schedule(nil), http.StatusOK), &saved); err != nil ||
		saved.JamfAPIClient == nil || saved.JamfAPIClient.ClientID != clientID || !strings.Contains(saved.Guidance, "jamf_api_client") {
		t.Fatalf("the saved schedule = %+v (%v); want the API client's ID served", saved, err)
	}
	if listed := string(call(requester, http.MethodGet, "/api/v1/mdm/poll-schedule", "", nil, http.StatusOK)); !strings.Contains(listed, clientID) || strings.Contains(listed, secret) {
		t.Fatalf("the schedule list = %s; want the client ID and never the secret", listed)
	}

	runRelay := func(what string) {
		t.Helper()
		channel := &sshCollectionServedChannel{t: t, h: h}
		if count, err := relay.RunOnce(ctx, channel, stand.Client(), 1, 120); err != nil || count != 1 || len(channel.reports) != 1 {
			for _, r := range channel.reports {
				t.Logf("report: %s %s", r.Outcome, r.Detail)
			}
			t.Fatalf("%s: production relay = %d %v; Jamf calls %q", what, count, err, standCalls())
		}
	}
	// The read: one exchange, one inventory read with the exchanged token.
	sched, found, err := h.store.GetMDMPollSchedule(ctx, h.tenant, mdm.MDMJamf)
	if err != nil || !found {
		t.Fatalf("stored schedule: found=%v err=%v", found, err)
	}
	h.srv.dispatchMDMSyncJob(ctx, h.tenant, sched)
	runRelay("the inventory read")
	if got := standCalls(); len(got) != 2 || got[0] != "POST /api/oauth/token" || got[1] != "GET /api/v1/computers-inventory" {
		t.Fatalf("Jamf calls for the read = %v", got)
	}
	devices := string(call(requester, http.MethodGet, "/api/v1/mdm/devices", "", nil, http.StatusOK))
	if !strings.Contains(devices, "mac-a156l1") || !strings.Contains(devices, "SER-A156L1") {
		t.Fatalf("devices after the read = %s; want the computer the API client's token read", devices)
	}

	// The check-in: approved, then one fresh exchange and one blank push.
	type approval struct {
		ID     string `json:"approval_request_id"`
		Digest string `json:"approval_intent_digest"`
	}
	var a approval
	if err := json.Unmarshal(call(requester, http.MethodPost, "/api/v1/mdm/jamf/devices/417/check-in/approval-requests", "a156l1-ask",
		map[string]any{"reason": "renewed SCEP profile"}, http.StatusCreated), &a); err != nil || a.ID == "" {
		t.Fatalf("approval request = %+v %v", a, err)
	}
	call(reviewer, http.MethodPost, "/api/v1/approval-requests/"+a.ID+"/approvals", "a156l1-approve",
		map[string]any{"intent_digest": a.Digest, "reason": "checked the device"}, http.StatusOK)
	var queued struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(call(requester, http.MethodPost, "/api/v1/mdm/jamf/devices/417/check-ins", "a156l1-check-in",
		map[string]any{"approval_request_id": a.ID, "approval_intent_digest": a.Digest}, http.StatusCreated), &queued); err != nil || queued.ID == "" {
		t.Fatalf("queued check-in = %+v %v", queued, err)
	}
	runRelay("the check-in")
	if got := standCalls(); len(got) != 4 || got[2] != "POST /api/oauth/token" || got[3] != "POST /JSSResource/computercommands/command/BlankPush/id/417" {
		t.Fatalf("Jamf calls for the check-in = %v", got)
	}
	var list struct {
		Items []struct {
			ID             string `json:"id"`
			DeviceID       string `json:"device_id"`
			Status         string `json:"status"`
			ProviderStatus int    `json:"provider_status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(call(requester, http.MethodGet, "/api/v1/mdm/jamf/check-ins", "", nil, http.StatusOK), &list); err != nil {
		t.Fatal(err)
	}
	checkedIn := false
	for _, c := range list.Items {
		if c.ID == queued.ID {
			checkedIn = c.DeviceID == "417" && c.Status == "checked_in" && c.ProviderStatus == http.StatusCreated
		}
	}
	if !checkedIn {
		t.Fatalf("Jamf check-ins = %+v; want check-in %s checked in with Jamf's 201", list.Items, queued.ID)
	}
}
