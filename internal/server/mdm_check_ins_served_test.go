// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/mdm"
)

// N9: an MDM device check-in behind approval. The requester asks for one
// device trstctl has read from its MDM, another reviewer approves, and the
// requester's execution queues one job for the MDM schedule's relay, which
// makes the one bodiless call — Graph's syncDevice or a Jamf blank push — with
// the schedule's token redeemed for that attempt. The MDM's answer is what
// the check-in records.
func TestServedMDMDeviceCheckInBehindApprovalN9(t *testing.T) {
	const intuneDevice = "0f7c2a4e-3b1d-4e5f-9a8b-7c6d5e4f3a2b"
	var mu sync.Mutex
	var calls []string
	// N9-L3: the MDM throttles the first push to computer 417.
	pushes417 := 0
	// One TLS stand-in serves both MDMs: Graph under /graph, Jamf Pro under
	// /jamf. Jamf computer 418 was deleted at the MDM after trstctl read it.
	stand := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization")+" "+strconv.Itoa(len(body)))
		mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/graph/v1.0/deviceManagement/managedDevices/"+intuneDevice+"/syncDevice":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/jamf/JSSResource/computercommands/command/BlankPush/id/417":
			mu.Lock()
			pushes417++
			throttled := pushes417 == 1
			mu.Unlock()
			if throttled {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer stand.Close()
	mdmCalls := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), calls...)
	}

	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{relay.KindMDMCheckIn, agentJobKindMDMSync}, func(d *Deps) {
		d.RequiredApprovals = 1
	})
	ctx := t.Context()
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "n9", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"n9-graph-token": "graph-test-token", "n9-jamf-token": "jamf-test-token"} {
		sealed, err := h.srv.sealTenantSecretForTest(ctx, h.tenant, name, []byte(value))
		if err != nil {
			t.Fatal(err)
		}
		seedApplicationSecretFixture(t, h.store, h.tenant, name, sealed)
	}
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "mdm-requester", "certs:write", "certs:read")
	reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "mdm-reviewer", "certs:issue")
	call := func(token, method, path, key string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h.servedHarness, method, path, token, key, body)
		if status != want {
			t.Fatalf("%s %s = %d, want %d: %s", method, path, status, want, raw)
		}
		return raw
	}
	schedule := func(provider, base, tokenName string, enabled bool) {
		t.Helper()
		call(requester, http.MethodPut, "/api/v1/mdm/poll-schedule", "n9-schedule-"+provider+"-"+strconv.FormatBool(enabled), map[string]any{
			"mdm": provider, "base_url": base, "token_ref": "secret://" + tokenName, "interval_seconds": 3600,
			"enabled": enabled, "execution": "relay", "required_agent_id": agentRowID(h.tenant, h.agent),
		}, http.StatusOK)
	}
	schedule(mdm.MDMIntune, stand.URL+"/graph", "n9-graph-token", true)
	schedule(mdm.MDMJamf, stand.URL+"/jamf", "n9-jamf-token", true)
	// The devices as the schedule's reads recorded them.
	if err := h.srv.correlateMDMDevices(ctx, h.tenant, []mdm.Device{
		{MDM: mdm.MDMIntune, MDMDeviceID: intuneDevice, Name: "laptop-n9", SerialNumber: "SER-N9-1", InstallState: mdm.OutcomeUnknown},
		{MDM: mdm.MDMJamf, MDMDeviceID: "417", Name: "mac-417", SerialNumber: "SER-N9-2", InstallState: mdm.OutcomeUnknown},
		{MDM: mdm.MDMJamf, MDMDeviceID: "418", Name: "mac-418", SerialNumber: "SER-N9-3", InstallState: mdm.OutcomeUnknown},
	}); err != nil {
		t.Fatal(err)
	}

	type approval struct {
		ID     string `json:"approval_request_id"`
		Digest string `json:"approval_intent_digest"`
		Name   string `json:"device_name"`
	}
	ask := func(provider, device string) approval {
		t.Helper()
		var a approval
		if err := json.Unmarshal(call(requester, http.MethodPost, "/api/v1/mdm/"+provider+"/devices/"+device+"/check-in/approval-requests",
			"n9-ask-"+provider+"-"+device, map[string]any{"reason": "renewed SCEP profile for " + device}, http.StatusCreated), &a); err != nil {
			t.Fatal(err)
		}
		if a.ID == "" || a.Digest == "" {
			t.Fatalf("approval request = %+v", a)
		}
		return a
	}
	approve := func(a approval, key string) {
		t.Helper()
		call(reviewer, http.MethodPost, "/api/v1/approval-requests/"+a.ID+"/approvals", key,
			map[string]any{"intent_digest": a.Digest, "reason": "checked the device"}, http.StatusOK)
	}
	execute := func(provider, device string, a approval, key string, want int) []byte {
		t.Helper()
		return call(requester, http.MethodPost, "/api/v1/mdm/"+provider+"/devices/"+device+"/check-ins", key,
			map[string]any{"approval_request_id": a.ID, "approval_intent_digest": a.Digest}, want)
	}
	runRelay := func(executed int) {
		t.Helper()
		channel := &sshCollectionServedChannel{t: t, h: h}
		if count, err := relay.RunOnce(ctx, channel, stand.Client(), 1, 120); err != nil || count != executed || len(channel.reports) != 1 {
			for _, r := range channel.reports {
				t.Logf("report: %s %s", r.Outcome, r.Detail)
			}
			t.Fatalf("production relay = %d %v; MDM calls %q", count, err, mdmCalls())
		}
	}
	type checkInView struct {
		ID             string `json:"id"`
		DeviceID       string `json:"device_id"`
		DeviceName     string `json:"device_name"`
		Status         string `json:"status"`
		ProviderStatus int    `json:"provider_status"`
		Failure        string `json:"failure"`
		RequestedBy    string `json:"requested_by"`
	}
	checkIns := func(provider string) map[string]checkInView {
		t.Helper()
		var list struct {
			Items []checkInView `json:"items"`
		}
		if err := json.Unmarshal(call(requester, http.MethodGet, "/api/v1/mdm/"+provider+"/check-ins", "", nil, http.StatusOK), &list); err != nil {
			t.Fatal(err)
		}
		out := map[string]checkInView{}
		for _, c := range list.Items {
			out[c.DeviceID] = c
		}
		return out
	}

	// A device trstctl never read from that MDM is not checked in.
	call(requester, http.MethodPost, "/api/v1/mdm/jamf/devices/999/check-in/approval-requests", "n9-unknown",
		map[string]any{"reason": "x"}, http.StatusNotFound)

	// Intune: nothing reaches the MDM before another reviewer approves, and the
	// requester cannot approve their own check-in.
	ai := ask(mdm.MDMIntune, intuneDevice)
	if ai.Name != "laptop-n9" {
		t.Fatalf("approval names device %q", ai.Name)
	}
	execute(mdm.MDMIntune, intuneDevice, ai, "n9-exec-intune-early", http.StatusConflict)
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+ai.ID+"/approvals", requester,
		"n9-self-approve", map[string]any{"intent_digest": ai.Digest, "reason": "my own"}); status < 400 {
		t.Fatalf("the requester approved their own check-in: %d", status)
	}
	if got := mdmCalls(); len(got) != 0 {
		t.Fatalf("the MDM was called before approval: %q", got)
	}
	// The reviewer finds the request in their review list.
	var pending struct {
		Items []struct {
			ID           string `json:"id"`
			ResourceKind string `json:"resource_kind"`
		} `json:"items"`
	}
	if err := json.Unmarshal(call(reviewer, http.MethodGet, "/api/v1/approval-requests?status=pending", "", nil, http.StatusOK), &pending); err != nil {
		t.Fatal(err)
	}
	listed := false
	for _, item := range pending.Items {
		listed = listed || (item.ID == ai.ID && item.ResourceKind == "mdm_device")
	}
	if !listed {
		t.Fatalf("the check-in approval is not in the reviewer's list: %+v", pending.Items)
	}
	approve(ai, "n9-review-intune")
	// An approval for one device cannot check in another.
	execute(mdm.MDMJamf, "417", ai, "n9-exec-wrong-device", http.StatusConflict)
	var queued checkInView
	if err := json.Unmarshal(execute(mdm.MDMIntune, intuneDevice, ai, "n9-exec-intune", http.StatusCreated), &queued); err != nil {
		t.Fatal(err)
	}
	if queued.Status != "queued" || queued.RequestedBy != "mdm-requester" || queued.DeviceName != "laptop-n9" {
		t.Fatalf("queued check-in = %+v", queued)
	}
	// The approval is spent on exactly one relay job.
	execute(mdm.MDMIntune, intuneDevice, ai, "n9-exec-intune-again", http.StatusCreated)
	if n := mdmCheckInJobs(t, h); n != 1 {
		t.Fatalf("%d check-in jobs for one approval, want 1", n)
	}
	runRelay(1)
	if c := checkIns(mdm.MDMIntune)[intuneDevice]; c.Status != "checked_in" || c.ProviderStatus != http.StatusNoContent || c.ID != queued.ID {
		t.Fatalf("Intune check-in = %+v", c)
	}

	// Jamf: a blank push to computer 417. The MDM throttles the first push;
	// the relay asks again in the same job, under the same approval (N9-L3).
	a417 := ask(mdm.MDMJamf, "417")
	approve(a417, "n9-review-417")
	execute(mdm.MDMJamf, "417", a417, "n9-exec-417", http.StatusCreated)
	runRelay(1)
	if c := checkIns(mdm.MDMJamf)["417"]; c.Status != "checked_in" || c.ProviderStatus != http.StatusCreated {
		t.Fatalf("Jamf check-in = %+v", c)
	}
	if n := mdmCheckInJobs(t, h); n != 2 {
		t.Fatalf("%d check-in jobs for two approvals, want 2: the throttled push was retried in its own job", n)
	}

	// Jamf computer 418 is gone at the MDM: the check-in fails with its answer.
	a418 := ask(mdm.MDMJamf, "418")
	approve(a418, "n9-review-418")
	execute(mdm.MDMJamf, "418", a418, "n9-exec-418", http.StatusCreated)
	runRelay(0)
	if c := checkIns(mdm.MDMJamf)["418"]; c.Status != "failed" || !strings.Contains(c.Failure, "status 404") {
		t.Fatalf("check-in of a deleted device = %+v", c)
	}

	// Only the three approved check-ins reached the MDMs: one bodiless POST
	// each, and the throttled one asked again, with the schedule's redeemed
	// token.
	want := []string{
		"POST /graph/v1.0/deviceManagement/managedDevices/" + intuneDevice + "/syncDevice Bearer graph-test-token 0",
		"POST /jamf/JSSResource/computercommands/command/BlankPush/id/417 Bearer jamf-test-token 0",
		"POST /jamf/JSSResource/computercommands/command/BlankPush/id/417 Bearer jamf-test-token 0",
		"POST /jamf/JSSResource/computercommands/command/BlankPush/id/418 Bearer jamf-test-token 0",
	}
	if got := mdmCalls(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("MDM calls = %q, want %q", got, want)
	}

	// A disabled schedule sends nothing to its MDM.
	schedule(mdm.MDMJamf, stand.URL+"/jamf", "n9-jamf-token", false)
	call(requester, http.MethodPost, "/api/v1/mdm/jamf/devices/417/check-in/approval-requests", "n9-disabled",
		map[string]any{"reason": "again"}, http.StatusConflict)
}

// mdmCheckInJobs counts the check-in jobs queued in the harness's tenant.
func mdmCheckInJobs(t *testing.T, h *roleHarness) int {
	t.Helper()
	var n int
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2`,
			h.tenant, relay.KindMDMCheckIn).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}
