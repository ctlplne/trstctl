// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/mdm"
	"trstctl.com/trstctl/internal/store"
)

// I5's producer, end to end: the schedule is configured over HTTP, the poller
// reads a (fake) Intune, the correlation joins devices to identities by exact
// serial, and the served device list carries the offline-renewal verdicts.
// Before this loop existed every ingredient was in the tree and the table the
// console reads was written only by tests.

// servedMDMTokenRef is a credential REFERENCE the poller resolves at run time.
const servedMDMTokenRef = "env:TRSTCTL_TEST_GRAPH_TOKEN" // #nosec G101 -- credential reference (env: pointer), no credential value present (CWE-798)

// servedMDMSecretRef is the secret-store reference relay-mode schedules carry.
const servedMDMSecretRef = "secret://mdm/graph-token" // #nosec G101 -- credential reference (secret store pointer), no credential value present (CWE-798)

func TestServedMDMPollerCorrelatesAndFlagsOfflineRenewals(t *testing.T) {
	intune := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("MDM saw %s; the poll may only ever GET", r.Method)
		}
		_, _ = w.Write([]byte(`{"value":[
			{"id":"dev-1","deviceName":"laptop-1","serialNumber":"SER-ENROLLED"},
			{"id":"dev-2","deviceName":"laptop-2","serialNumber":"SER-UNKNOWN"}
		]}`))
	}))
	defer intune.Close()
	t.Setenv("TRSTCTL_TEST_GRAPH_TOKEN", "graph-test-token")

	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write", "owners:write", "owners:read",
		string(authz.PrivateEgress))

	// An identity whose NAME is the device serial — the Intune SCEP
	// convention — expiring INSIDE the renewal window, with the device's only
	// MDM observation predating the window: the at-risk case.
	owner, err := h.store.CreateOwner(t.Context(), store.Owner{TenantID: h.tenant, Kind: store.OwnerTeam, Name: "endpoints"})
	if err != nil {
		t.Fatal(err)
	}
	notAfter := time.Now().UTC().Add(10 * 24 * time.Hour)
	ident, err := h.store.CreateIdentity(t.Context(), store.Identity{
		TenantID: h.tenant, OwnerID: owner.ID, Kind: "x509", Name: "SER-ENROLLED", NotAfter: &notAfter,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Relay mode with an env: ref must refuse — the relay cannot read the
	// control plane's environment.
	status, out := secretsReqKey(t, h, http.MethodPut, "/api/v1/mdm/poll-schedule", tok,
		"mdm-sched-bad", map[string]any{
			"mdm": "intune", "base_url": intune.URL, "token_ref": servedMDMTokenRef,
			"interval_seconds": 3600, "enabled": true, "execution": "relay",
		})
	if status != http.StatusBadRequest || !strings.Contains(string(out), "secret://") {
		t.Fatalf("relay execution with an env: ref = %d %s", status, out)
	}

	status, out = secretsReqKey(t, h, http.MethodPut, "/api/v1/mdm/poll-schedule", tok,
		"mdm-sched-1", map[string]any{
			"mdm": "intune", "base_url": intune.URL, "token_ref": servedMDMTokenRef,
			"interval_seconds": 3600, "enabled": true,
			"allow_private_endpoint": true,
			"private_egress_cidrs":   []string{serviceNowSinkCIDR(t, intune.URL)},
		})
	if status != http.StatusOK {
		t.Fatalf("configure schedule: %d %s", status, out)
	}
	sched, found, err := h.store.GetMDMPollSchedule(t.Context(), h.tenant, mdm.MDMIntune)
	if err != nil || !found {
		t.Fatalf("schedule not persisted: found=%v err=%v", found, err)
	}

	h.srv.runMDMPollOnce(t.Context(), h.tenant, sched)

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/mdm/devices", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list devices: %d %s", status, body)
	}
	var list struct {
		Items []struct {
			MDMDeviceID   string `json:"mdm_device_id"`
			SerialNumber  string `json:"serial_number"`
			IdentityID    string `json:"identity_id"`
			RenewalAtRisk bool   `json:"renewal_at_risk"`
			RenewalDetail string `json:"renewal_detail"`
		} `json:"items"`
		RenewalAtRisk int `json:"renewal_at_risk"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 2 {
		t.Fatalf("devices = %d, want both — the unmatched device is one of the two gaps this "+
			"surface exists to show: %s", len(list.Items), body)
	}
	byID := map[string]int{}
	for i, item := range list.Items {
		byID[item.MDMDeviceID] = i
	}
	enrolled := list.Items[byID["dev-1"]]
	if enrolled.IdentityID != ident.ID {
		t.Fatalf("dev-1 joined identity %q, want %q — the join is exact serial-to-name equality",
			enrolled.IdentityID, ident.ID)
	}
	if !enrolled.RenewalAtRisk || !strings.Contains(enrolled.RenewalDetail, "renewal") {
		t.Fatalf("dev-1 at_risk=%v detail=%q; its certificate is inside the renewal window and the "+
			"MDM observation predates the window — the silently-missing-renewal case this check "+
			"exists for", enrolled.RenewalAtRisk, enrolled.RenewalDetail)
	}
	unknown := list.Items[byID["dev-2"]]
	if unknown.IdentityID != "" || unknown.RenewalAtRisk {
		t.Fatalf("dev-2 = %+v; a device with no certificate gets NO verdict — scoring it would "+
			"flood the list with devices this check cannot say anything about", unknown)
	}
	if list.RenewalAtRisk != 1 {
		t.Fatalf("renewal_at_risk = %d, want 1", list.RenewalAtRisk)
	}

	sched2, _, err := h.store.GetMDMPollSchedule(t.Context(), h.tenant, mdm.MDMIntune)
	if err != nil || sched2.LastRunAt == nil || sched2.LastError != "" {
		t.Fatalf("poll not stamped: %+v err=%v", sched2, err)
	}
}

func TestServedMDMRelayModeDispatchesOneJobAndIngestsTheReport(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write")

	status, out := secretsReqKey(t, h, http.MethodPut, "/api/v1/mdm/poll-schedule", tok,
		"mdm-relay-1", map[string]any{
			"mdm": "jamf", "base_url": "https://jamf.internal.example", "token_ref": servedMDMSecretRef,
			"interval_seconds": 3600, "enabled": true, "execution": "relay",
		})
	if status != http.StatusOK {
		t.Fatalf("configure relay schedule: %d %s", status, out)
	}
	sched, _, err := h.store.GetMDMPollSchedule(t.Context(), h.tenant, mdm.MDMJamf)
	if err != nil {
		t.Fatal(err)
	}

	h.srv.dispatchMDMSyncJob(t.Context(), h.tenant, sched)
	var jobs int
	var role string
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(),
			`SELECT count(*), max(required_agent_role) FROM outbox
			  WHERE tenant_id = $1 AND destination = 'mdm.sync'`, h.tenant).Scan(&jobs, &role)
	}); err != nil {
		t.Fatal(err)
	}
	if jobs != 1 || role != "network" {
		t.Fatalf("dispatch produced %d jobs with role %q, want one network-stamped job", jobs, role)
	}

	// One in flight: the second due tick stamps the waiting state, no stack.
	h.srv.dispatchMDMSyncJob(t.Context(), h.tenant, sched)
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(),
			`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = 'mdm.sync'`, h.tenant).Scan(&jobs)
	}); err != nil {
		t.Fatal(err)
	}
	if jobs != 1 {
		t.Fatalf("second tick stacked a job: %d in queue", jobs)
	}
	sched2, _, err := h.store.GetMDMPollSchedule(t.Context(), h.tenant, mdm.MDMJamf)
	if err != nil || !strings.Contains(sched2.LastError, "waiting") {
		t.Fatalf("waiting state not stamped: %q err=%v", sched2.LastError, err)
	}

	// The relay's report lands through the shared correlation core.
	report, err := json.Marshal(MDMSyncReport{MDM: mdm.MDMJamf, Devices: []mdm.Device{
		{MDM: mdm.MDMJamf, MDMDeviceID: "j-9", Name: "mac-9", SerialNumber: "SER-J9",
			InstallState: mdm.OutcomeUnknown, ObservedAt: time.Now().UTC()},
	}})
	if err != nil {
		t.Fatal(err)
	}
	h.srv.recordMDMSync(t.Context(), h.tenant, "relay-1", "idem-9", string(report))

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/mdm/devices?mdm=jamf", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list devices: %d %s", status, body)
	}
	if !strings.Contains(string(body), "j-9") {
		t.Fatalf("the relay's reported device never reached the served surface: %s", body)
	}
	sched3, _, err := h.store.GetMDMPollSchedule(t.Context(), h.tenant, mdm.MDMJamf)
	if err != nil || sched3.LastError != "" {
		t.Fatalf("after a successful relay report the schedule still carries error %q", sched3.LastError)
	}
}
