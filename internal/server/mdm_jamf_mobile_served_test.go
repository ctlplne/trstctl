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

// N9-L1: a Jamf poll schedule can have the relay read Jamf's mobile device
// inventory as well as its computers. The setting is Jamf's alone, is served
// back, and the production relay then reads the mobile devices from a Jamf
// Pro stand-in (built from Jamf's API reference) with the same token after
// the computers; computer 12 and mobile device 12 stay two devices, and the
// mobile device is listed with its serial. A check-in asked for the mobile
// device is refused with the reason, while the computer's is accepted.
func TestServedJamfScheduleReadsMobileDevicesN9L1(t *testing.T) {
	const bearer = "n9l1-served-jamf-bearer" // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
	var mu sync.Mutex
	var calls []string
	stand := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch {
		case r.Header.Get("Authorization") != "Bearer "+bearer:
			w.WriteHeader(http.StatusUnauthorized)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/computers-inventory":
			_, _ = w.Write([]byte(`{"results":[{"id":"12","general":{"name":"mac-n9l1","lastContactTime":"2026-11-13T08:00:00Z"},"hardware":{"serialNumber":"MAC-N9L1"}}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/mobile-devices/detail":
			_, _ = w.Write([]byte(`{"totalCount":1,"results":[{"mobileDeviceId":"12","deviceType":"iOS",
				"general":{"displayName":"ipad-n9l1","lastContactDate":"2026-11-13T09:30:00Z"},"hardware":{"serialNumber":"IPAD-N9L1"}}]}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer stand.Close()

	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{relay.KindMDMCheckIn, agentJobKindMDMSync}, func(d *Deps) {
		d.RequiredApprovals = 1
	})
	ctx := t.Context()
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "n9l1", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	sealed, err := h.srv.sealTenantSecretForTest(ctx, h.tenant, "n9l1-jamf-bearer", []byte(bearer))
	if err != nil {
		t.Fatal(err)
	}
	seedApplicationSecretFixture(t, h.store, h.tenant, "n9l1-jamf-bearer", sealed)
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "n9l1-requester", "certs:write", "certs:read")
	call := func(method, path, key string, body any, want int) []byte {
		t.Helper()
		status, raw := secretsReqKey(t, h.servedHarness, method, path, requester, key, body)
		if status != want {
			t.Fatalf("%s %s = %d, want %d: %s", method, path, status, want, raw)
		}
		return raw
	}
	schedule := func(changes map[string]any) map[string]any {
		body := map[string]any{"mdm": "jamf", "base_url": stand.URL, "token_ref": "secret://n9l1-jamf-bearer", // #nosec G101 -- credential reference, no credential value present (CWE-798)
			"interval_seconds": 3600, "enabled": true, "execution": "relay", "required_agent_id": agentRowID(h.tenant, h.agent),
			"jamf_mobile_devices": true}
		for k, v := range changes {
			body[k] = v
		}
		return body
	}
	call(http.MethodPut, "/api/v1/mdm/poll-schedule", "n9l1-intune", schedule(map[string]any{"mdm": "intune", "base_url": "https://graph.microsoft.com"}), http.StatusBadRequest)
	var saved struct {
		JamfMobileDevices bool   `json:"jamf_mobile_devices"`
		Guidance          string `json:"guidance"`
	}
	if err := json.Unmarshal(call(http.MethodPut, "/api/v1/mdm/poll-schedule", "n9l1-schedule", schedule(nil), http.StatusOK), &saved); err != nil ||
		!saved.JamfMobileDevices || !strings.Contains(saved.Guidance, "jamf_mobile_devices") {
		t.Fatalf("the saved schedule = %+v (%v); want it to read mobile devices", saved, err)
	}
	if listed := string(call(http.MethodGet, "/api/v1/mdm/poll-schedule", "", nil, http.StatusOK)); !strings.Contains(listed, `"jamf_mobile_devices":true`) {
		t.Fatalf("the schedule list = %s; want the setting served", listed)
	}

	sched, found, err := h.store.GetMDMPollSchedule(ctx, h.tenant, mdm.MDMJamf)
	if err != nil || !found || !sched.JamfMobileDevices {
		t.Fatalf("stored schedule = %+v found=%v err=%v", sched, found, err)
	}
	h.srv.dispatchMDMSyncJob(ctx, h.tenant, sched)
	channel := &sshCollectionServedChannel{t: t, h: h}
	if count, err := relay.RunOnce(ctx, channel, stand.Client(), 1, 120); err != nil || count != 1 || len(channel.reports) != 1 {
		for _, r := range channel.reports {
			t.Logf("report: %s %s", r.Outcome, r.Detail)
		}
		t.Fatalf("production relay = %d %v", count, err)
	}
	mu.Lock()
	got := strings.Join(calls, ",")
	mu.Unlock()
	if got != "GET /api/v1/computers-inventory,GET /api/v2/mobile-devices/detail" {
		t.Fatalf("Jamf calls = %s; want the computers, then the mobile devices", got)
	}
	var devices struct {
		Items []struct {
			MDMDeviceID  string `json:"mdm_device_id"`
			DeviceName   string `json:"device_name"`
			SerialNumber string `json:"serial_number"`
			InstallState string `json:"install_state"`
		} `json:"items"`
	}
	if err := json.Unmarshal(call(http.MethodGet, "/api/v1/mdm/devices", "", nil, http.StatusOK), &devices); err != nil {
		t.Fatal(err)
	}
	byID := map[string]string{}
	for _, d := range devices.Items {
		byID[d.MDMDeviceID] = d.DeviceName + " " + d.SerialNumber
	}
	if byID["12"] != "mac-n9l1 MAC-N9L1" || byID["mobile-12"] != "ipad-n9l1 IPAD-N9L1" {
		t.Fatalf("devices = %+v; want computer 12 and mobile device 12 apart", devices.Items)
	}

	// The mobile device is read, not checked in; the computer still can be.
	if refused := string(call(http.MethodPost, "/api/v1/mdm/jamf/devices/mobile-12/check-in/approval-requests", "n9l1-mobile-ask",
		map[string]any{"reason": "renewed profile"}, http.StatusConflict)); !strings.Contains(refused, "not checked in") {
		t.Fatalf("a mobile device's check-in ask = %s", refused)
	}
	call(http.MethodPost, "/api/v1/mdm/jamf/devices/12/check-in/approval-requests", "n9l1-computer-ask",
		map[string]any{"reason": "renewed profile"}, http.StatusCreated)
	t.Logf("N9L1_JAMF_MOBILE_OK devices=%d calls=%s", len(devices.Items), got)
}
