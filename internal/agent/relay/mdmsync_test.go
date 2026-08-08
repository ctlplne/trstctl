// SPDX-License-Identifier: MPL-2.0

package relay_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/mdm"
)

// The relay half of I5's read: fetch from the vantage, parse there, report
// devices — never the raw response, never a decision.

// relayMDMTokenRef is a credential REFERENCE the relay redeems per attempt.
const relayMDMTokenRef = "secret://mdm/token" // #nosec G101 -- credential reference (secret store pointer), no credential value present (CWE-798)

func mdmJob(t *testing.T, intent mdm.SyncIntent) relay.Job {
	t.Helper()
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	return relay.Job{JobID: 21, Kind: relay.KindMDMSync, Attempt: 1, Payload: payload}
}

func TestRelayMDMSyncReadsParsesAndReportsDevices(t *testing.T) {
	var seenAuth, seenMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth, seenMethod = r.Header.Get("Authorization"), r.Method
		_, _ = w.Write([]byte(`{"value":[
			{"id":"dev-1","deviceName":"laptop-9","serialNumber":"SER9","managedDeviceOwnerType":"company"}
		]}`))
	}))
	defer srv.Close()

	ch := &fakeChannel{
		jobs:     []relay.Job{mdmJob(t, mdm.SyncIntent{MDM: mdm.MDMIntune, BaseURL: srv.URL, TokenRef: relayMDMTokenRef})},
		material: map[string][]byte{relayMDMTokenRef: []byte("graph-token")},
	}
	executed, err := relay.RunOnce(t.Context(), ch, srv.Client(), 4, 30)
	if err != nil || executed != 1 {
		t.Fatalf("executed = %d, %v; reports: %+v", executed, err, ch.reports)
	}
	if seenMethod != http.MethodGet {
		t.Fatalf("method = %q; the MDM read may only ever GET — a bad write pushes a profile to real laptops", seenMethod)
	}
	if seenAuth != "Bearer graph-token" {
		t.Fatalf("Authorization = %q; the token must come from THIS attempt's redemption", seenAuth)
	}
	var report struct {
		MDM     string       `json:"mdm"`
		Devices []mdm.Device `json:"devices"`
	}
	if err := json.Unmarshal([]byte(ch.reports[0].detail), &report); err != nil {
		t.Fatalf("report detail is not a devices document: %v", err)
	}
	if report.MDM != mdm.MDMIntune || len(report.Devices) != 1 || report.Devices[0].SerialNumber != "SER9" {
		t.Fatalf("report = %+v; the relay ships parsed structure, not raw bytes", report)
	}
}

func TestRelayMDMSyncRefusesAnUnknownMDM(t *testing.T) {
	ch := &fakeChannel{jobs: []relay.Job{mdmJob(t, mdm.SyncIntent{MDM: "airwatch", BaseURL: "https://x.example", TokenRef: "secret://t"})}}
	if _, err := relay.RunOnce(t.Context(), ch, http.DefaultClient, 4, 30); err != nil {
		t.Fatal(err)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeFailed ||
		!strings.Contains(ch.reports[0].detail, "unknown mdm") {
		t.Fatalf("reports = %+v; a vendor this build does not carry must be refused by name, and "+
			"never fall through to a generic fetch against an endpoint shape it guessed", ch.reports)
	}
}
