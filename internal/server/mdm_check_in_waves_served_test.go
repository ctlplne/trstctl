// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/mdm"
)

// TestServedMDMCheckInWaveUnderOneApprovalN9L2 is N9-L2: every device of a
// renewal wave checks in under one approval. The requester names the devices;
// a device trstctl never read is refused; nothing reaches the MDM before
// another reviewer approves exactly that set; executing a different set with
// the approval is refused; executing it queues one check-in and one relay job
// per device, once however often it is executed; each device's check-in is
// recorded from the MDM's own answer, and the wave counts them.
func TestServedMDMCheckInWaveUnderOneApprovalN9L2(t *testing.T) {
	const (
		devA = "1a1a1a1a-0000-4000-8000-00000000000a"
		devB = "1b1b1b1b-0000-4000-8000-00000000000b"
		devC = "1c1c1c1c-0000-4000-8000-00000000000c" // deleted at the MDM after trstctl read it
	)
	var mu sync.Mutex
	var calls []string
	stand := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		mu.Unlock()
		switch r.URL.Path {
		case "/graph/v1.0/deviceManagement/managedDevices/" + devA + "/syncDevice", "/graph/v1.0/deviceManagement/managedDevices/" + devB + "/syncDevice":
			w.WriteHeader(http.StatusNoContent)
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
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "n9l2", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	sealed, err := h.srv.sealTenantSecretForTest(ctx, h.tenant, "n9l2-graph-token", []byte("graph-wave-token"))
	if err != nil {
		t.Fatal(err)
	}
	seedApplicationSecretFixture(t, h.store, h.tenant, "n9l2-graph-token", sealed)
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "wave-requester", "certs:write", "certs:read")
	reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "wave-reviewer", "certs:issue")
	call := func(token, method, path, key string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h.servedHarness, method, path, token, key, body)
		if status != want {
			t.Fatalf("%s %s = %d, want %d: %s", method, path, status, want, raw)
		}
		return raw
	}
	call(requester, http.MethodPut, "/api/v1/mdm/poll-schedule", "n9l2-schedule", map[string]any{ // #nosec G101 -- a secret:// reference name, not a credential (CWE-798)
		"mdm": mdm.MDMIntune, "base_url": stand.URL + "/graph", "token_ref": "secret://n9l2-graph-token", "interval_seconds": 3600,
		"enabled": true, "execution": "relay", "required_agent_id": agentRowID(h.tenant, h.agent),
	}, http.StatusOK)
	if err := h.srv.correlateMDMDevices(ctx, h.tenant, []mdm.Device{
		{MDM: mdm.MDMIntune, MDMDeviceID: devA, Name: "laptop-a", SerialNumber: "SER-N9L2-A", InstallState: mdm.OutcomeUnknown},
		{MDM: mdm.MDMIntune, MDMDeviceID: devB, Name: "laptop-b", SerialNumber: "SER-N9L2-B", InstallState: mdm.OutcomeUnknown},
		{MDM: mdm.MDMIntune, MDMDeviceID: devC, Name: "laptop-c", SerialNumber: "SER-N9L2-C", InstallState: mdm.OutcomeUnknown},
	}); err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/mdm/intune/check-in-waves"
	wave := []string{devC, devA, devB, devA}

	// A device trstctl never read from that MDM cannot be in a wave.
	call(requester, http.MethodPost, base+"/approval-requests", "n9l2-unknown",
		map[string]any{"device_ids": []string{devA, "9f9f9f9f-0000-4000-8000-000000000009"}, "reason": "x"}, http.StatusNotFound)

	var approval struct {
		ID      string `json:"approval_request_id"`
		Digest  string `json:"approval_intent_digest"`
		Devices []struct {
			DeviceID   string `json:"device_id"`
			DeviceName string `json:"device_name"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(call(requester, http.MethodPost, base+"/approval-requests", "n9l2-ask",
		map[string]any{"device_ids": wave, "reason": "renewed SCEP profile, wave 7"}, http.StatusCreated), &approval); err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, d := range approval.Devices {
		names = append(names, d.DeviceName)
	}
	if approval.ID == "" || len(approval.Devices) != 3 || !sort.StringsAreSorted([]string{approval.Devices[0].DeviceID, approval.Devices[1].DeviceID, approval.Devices[2].DeviceID}) {
		t.Fatalf("wave approval = %+v", approval)
	}
	run := func(key string, devices []string, want int) []byte {
		t.Helper()
		return call(requester, http.MethodPost, base, key,
			map[string]any{"approval_request_id": approval.ID, "approval_intent_digest": approval.Digest, "device_ids": devices}, want)
	}
	// Nothing reaches the MDM before another reviewer approves.
	run("n9l2-run-early", wave, http.StatusConflict)
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+approval.ID+"/approvals", requester,
		"n9l2-self", map[string]any{"intent_digest": approval.Digest, "reason": "mine"}); status < 400 {
		t.Fatalf("the requester approved their own wave: %d", status)
	}
	call(reviewer, http.MethodPost, "/api/v1/approval-requests/"+approval.ID+"/approvals", "n9l2-review",
		map[string]any{"intent_digest": approval.Digest, "reason": "checked the wave's devices"}, http.StatusOK)
	if got := mdmCalls(); len(got) != 0 {
		t.Fatalf("the MDM was called before the wave ran: %q", got)
	}
	// The approval names exactly its devices.
	run("n9l2-run-other", []string{devA, devB}, http.StatusConflict)

	var queued struct {
		ID          string `json:"id"`
		DeviceCount int    `json:"device_count"`
		Queued      int    `json:"queued"`
	}
	if err := json.Unmarshal(run("n9l2-run", wave, http.StatusCreated), &queued); err != nil {
		t.Fatal(err)
	}
	if queued.ID == "" || queued.DeviceCount != 3 || queued.Queued != 3 {
		t.Fatalf("queued wave = %+v", queued)
	}
	var again struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(run("n9l2-run-again", []string{devB, devA, devC}, http.StatusCreated), &again); err != nil || again.ID != queued.ID {
		t.Fatalf("running the wave again = %+v %v", again, err)
	}
	var jobs int
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2`, h.tenant, relay.KindMDMCheckIn).Scan(&jobs)
	}); err != nil || jobs != 3 {
		t.Fatalf("relay jobs for one wave = %d %v, want 3", jobs, err)
	}

	for i := 0; i < 3; i++ {
		channel := &sshCollectionServedChannel{t: t, h: h}
		if _, err := relay.RunOnce(ctx, channel, stand.Client(), 1, 120); err != nil || len(channel.reports) != 1 {
			t.Fatalf("relay pass %d: %v reports %d", i, err, len(channel.reports))
		}
	}
	var waves struct {
		Items []struct {
			ID          string `json:"id"`
			DeviceCount int    `json:"device_count"`
			CheckedIn   int    `json:"checked_in"`
			Failed      int    `json:"failed"`
			Queued      int    `json:"queued"`
		} `json:"items"`
	}
	if err := json.Unmarshal(call(requester, http.MethodGet, base, "", nil, http.StatusOK), &waves); err != nil || len(waves.Items) != 1 {
		t.Fatalf("waves = %+v %v", waves, err)
	}
	if w := waves.Items[0]; w.ID != queued.ID || w.CheckedIn != 2 || w.Failed != 1 || w.Queued != 0 {
		t.Fatalf("wave after the relay = %+v; want 2 checked in and the deleted device failed", w)
	}
	got := mdmCalls()
	if len(got) != 3 {
		t.Fatalf("MDM calls = %q, want one per device", got)
	}
	for _, c := range got {
		if !strings.HasPrefix(c, "POST /graph/v1.0/deviceManagement/managedDevices/") || !strings.HasSuffix(c, "/syncDevice Bearer graph-wave-token") {
			t.Fatalf("MDM call = %q", c)
		}
	}
	if strings.Join(names, ",") == "" {
		t.Fatal("the approval named no devices")
	}
}
