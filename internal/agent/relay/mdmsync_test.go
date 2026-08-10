// SPDX-License-Identifier: MPL-2.0

package relay_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
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

func TestRelayMDMSyncCarriesExactIntuneCertificateEvidence(t *testing.T) {
	archive := relayIntuneCertificateZIP(t,
		"DeviceId,PolicyId,SerialNumber,CertificateStatus,ValidTo\n"+
			"dev-9,profile-9,00A7,Active,2030-01-01T00:00:00Z\n")
	client := &http.Client{Transport: relayRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		response := func(body io.Reader) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(body), Request: request}, nil
		}
		switch {
		case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/v1.0/deviceManagement/managedDevices"):
			return response(strings.NewReader(`{"value":[{"id":"dev-9","deviceName":"laptop-9","serialNumber":"SER9"}]}`))
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/beta/deviceManagement/reports/exportJobs"):
			return response(strings.NewReader(`{"id":"job-9","status":"notStarted"}`))
		case request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/beta/deviceManagement/reports/exportJobs("):
			return response(strings.NewReader(`{"id":"job-9","status":"completed","url":"https://download.example.test/report.zip"}`))
		case request.Method == http.MethodGet && request.URL.Host == "download.example.test":
			if request.Header.Get("Authorization") != "" {
				t.Fatal("Graph bearer token crossed onto the signed report-download authority")
			}
			return response(bytes.NewReader(archive))
		default:
			t.Fatalf("unexpected relay MDM operation: %s %s", request.Method, request.URL)
			return nil, nil
		}
	})}
	ch := &fakeChannel{
		jobs: []relay.Job{mdmJob(t, mdm.SyncIntent{
			MDM: mdm.MDMIntune, BaseURL: "https://graph.microsoft.com", TokenRef: relayMDMTokenRef,
			SCEPProfileIDs: []string{"profile-9"},
		})},
		material: map[string][]byte{relayMDMTokenRef: []byte("graph-token")},
	}
	if executed, err := relay.RunOnce(t.Context(), ch, client, 4, 30); err != nil || executed != 1 {
		t.Fatalf("relay exact evidence: executed=%d err=%v reports=%+v", executed, err, ch.reports)
	}
	var report struct {
		Devices []mdm.Device `json:"devices"`
	}
	if err := json.Unmarshal([]byte(ch.reports[0].detail), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Devices) != 1 || !report.Devices[0].InstallObserved || len(report.Devices[0].Certificates) != 1 || report.Devices[0].Certificates[0].SerialNumber != "00A7" {
		t.Fatalf("relay report lost exact certificate evidence: %+v", report.Devices)
	}
}

type relayRoundTripFunc func(*http.Request) (*http.Response, error)

func (f relayRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func relayIntuneCertificateZIP(t *testing.T, contents string) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	entry, err := writer.Create("CertificatesByRAPolicy.csv")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(entry, contents); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
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
