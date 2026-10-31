// SPDX-License-Identifier: BUSL-1.1

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
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/v1.0/deviceManagement/reports/exportJobs"):
			return response(strings.NewReader(`{"id":"job-9","status":"notStarted"}`))
		case request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/v1.0/deviceManagement/reports/exportJobs("):
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

// A156: an Intune read configured with an app registration exchanges the
// redeemed client secret for a Graph token (OAuth client-credentials grant)
// and reads with that token; a refused secret is a named failure that carries
// neither the secret nor a token.
func TestRelayMDMSyncExchangesTheClientSecretForAGraphToken(t *testing.T) {
	const (
		directory = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
		clientID  = "1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e"
		secretRef = "secret://mdm/intune/client-secret" // #nosec G101 -- credential reference, no credential value present (CWE-798)
		clientKey = "stand-in client secret"            // #nosec G101 -- a stand-in fixture value, not a credential (CWE-798)
		exchanged = "graph-token-from-exchange"
	)
	tokenCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/"+directory+"/oauth2/v2.0/token":
			tokenCalls++
			if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "client_credentials" ||
				r.PostForm.Get("client_id") != clientID || r.PostForm.Get("scope") != mdm.GraphApplicationScope {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"unauthorized_client"}`))
				return
			}
			if r.PostForm.Get("client_secret") != clientKey {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
				return
			}
			_, _ = w.Write([]byte(`{"token_type":"Bearer","expires_in":3599,"access_token":"` + exchanged + `"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1.0/deviceManagement/managedDevices":
			if r.Header.Get("Authorization") != "Bearer "+exchanged {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"value":[{"id":"dev-1","deviceName":"laptop-9","serialNumber":"SER9","managedDeviceOwnerType":"company"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	intent := mdm.SyncIntent{MDM: mdm.MDMIntune, BaseURL: srv.URL, TokenRef: secretRef,
		ClientCredentials: &mdm.ClientCredentials{Authority: srv.URL, DirectoryTenantID: directory, ClientID: clientID}}

	ch := &fakeChannel{jobs: []relay.Job{mdmJob(t, intent)}, material: map[string][]byte{secretRef: []byte(clientKey)}}
	executed, err := relay.RunOnce(t.Context(), ch, srv.Client(), 4, 30)
	if err != nil || executed != 1 || tokenCalls != 1 {
		t.Fatalf("executed = %d, %v, token calls %d; reports: %+v", executed, err, tokenCalls, ch.reports)
	}
	var report struct {
		Devices []mdm.Device `json:"devices"`
	}
	if err := json.Unmarshal([]byte(ch.reports[0].detail), &report); err != nil || len(report.Devices) != 1 || report.Devices[0].SerialNumber != "SER9" {
		t.Fatalf("report = %q; want the device read with the exchanged token", ch.reports[0].detail)
	}

	refused := &fakeChannel{jobs: []relay.Job{mdmJob(t, intent)}, material: map[string][]byte{secretRef: []byte("wrong secret")}}
	if executed, _ := relay.RunOnce(t.Context(), refused, srv.Client(), 4, 30); executed != 0 || len(refused.reports) != 1 {
		t.Fatalf("a refused secret executed = %d; reports %+v", executed, refused.reports)
	}
	detail := refused.reports[0].detail
	if detail != "the identity platform refused the client ID or client secret" ||
		strings.Contains(detail, "wrong secret") || strings.Contains(detail, exchanged) {
		t.Fatalf("refusal detail = %q; want the named refusal with no secret or token", detail)
	}
}
