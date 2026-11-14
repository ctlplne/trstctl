// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/mdm"
)

// N9-L1: a Jamf read whose schedule asks for mobile devices reads the mobile
// device inventory after the computers, with the same token, and reports
// each mobile device under its prefixed ID. Without the setting the mobile
// inventory is never asked for; with it, a refused mobile read fails the job
// with the reason instead of leaving the mobile devices silently out.
func TestRelayMDMSyncReadsJamfMobileDevicesN9L1(t *testing.T) {
	const bearerRef = "secret://mdm/jamf/n9l1-bearer" // #nosec G101 -- credential reference, no credential value present (CWE-798)
	const bearer = "n9l1-jamf-bearer"                 // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
	var mu sync.Mutex
	var calls []string
	mobileStatus := http.StatusOK
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		status := mobileStatus
		mu.Unlock()
		switch {
		case r.Header.Get("Authorization") != "Bearer "+bearer:
			w.WriteHeader(http.StatusUnauthorized)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/computers-inventory":
			_, _ = w.Write([]byte(`{"results":[{"id":"12","general":{"name":"mac-12","lastContactTime":"2026-11-13T08:00:00Z"},"hardware":{"serialNumber":"MAC-N9L1"}}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/mobile-devices/detail" && status == http.StatusOK:
			_, _ = w.Write([]byte(`{"totalCount":1,"results":[{"mobileDeviceId":"12","deviceType":"iOS",
				"general":{"displayName":"ipad-12","lastContactDate":"2026-11-13T09:30:00Z"},"hardware":{"serialNumber":"IPAD-N9L1"}}]}`))
		case r.URL.Path == "/api/v2/mobile-devices/detail":
			w.WriteHeader(status)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	run := func(mobile bool) (string, string, []string) {
		t.Helper()
		mu.Lock()
		calls = nil
		mu.Unlock()
		intent := mdm.SyncIntent{MDM: mdm.MDMJamf, BaseURL: srv.URL, TokenRef: bearerRef, JamfMobileDevices: mobile}
		ch := &fakeChannel{jobs: []relay.Job{mdmJob(t, intent)}, material: map[string][]byte{bearerRef: []byte(bearer)}}
		if _, err := relay.RunOnce(t.Context(), ch, srv.Client(), 4, 30); err != nil || len(ch.reports) != 1 {
			t.Fatalf("relay = %v; reports %+v", err, ch.reports)
		}
		mu.Lock()
		defer mu.Unlock()
		return ch.reports[0].outcome, ch.reports[0].detail, append([]string(nil), calls...)
	}

	outcome, detail, got := run(true)
	var report struct {
		Devices []mdm.Device `json:"devices"`
	}
	if outcome != relay.OutcomeExecuted || json.Unmarshal([]byte(detail), &report) != nil || len(report.Devices) != 2 {
		t.Fatalf("with mobile devices: %s %s", outcome, detail)
	}
	if mac, ipad := report.Devices[0], report.Devices[1]; mac.MDMDeviceID != "12" || mac.SerialNumber != "MAC-N9L1" ||
		ipad.MDMDeviceID != "mobile-12" || ipad.SerialNumber != "IPAD-N9L1" || ipad.Name != "ipad-12" {
		t.Fatalf("devices = %+v; want computer 12 and mobile device 12 apart", report.Devices)
	}
	if strings.Join(got, ",") != "GET /api/v1/computers-inventory,GET /api/v2/mobile-devices/detail" {
		t.Fatalf("Jamf calls = %v", got)
	}

	outcome, detail, got = run(false)
	if outcome != relay.OutcomeExecuted || json.Unmarshal([]byte(detail), &report) != nil || len(report.Devices) != 1 || strings.Join(got, ",") != "GET /api/v1/computers-inventory" {
		t.Fatalf("without mobile devices: %s %s; calls %v", outcome, detail, got)
	}

	mu.Lock()
	mobileStatus = http.StatusForbidden
	mu.Unlock()
	outcome, detail, _ = run(true)
	if outcome != relay.OutcomeFailed || !strings.Contains(detail, "status 403") || !strings.Contains(detail, "Read Mobile Devices") {
		t.Fatalf("a refused mobile read = %s %q", outcome, detail)
	}
}
