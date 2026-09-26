// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/mdm"
	"trstctl.com/trstctl/internal/protocols/scep"
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

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func mdmJobPayload(t *testing.T, provider string) []byte {
	t.Helper()
	return []byte(mustJSON(t, mdm.SyncIntent{
		MDM: provider, BaseURL: "https://mdm.internal.example", TokenRef: servedMDMSecretRef,
	}))
}

func TestServedMDMPollerProvesExactIntuneCertificateInstallation(t *testing.T) {
	reportArchive := servedIntuneCertificateReportZIP(t,
		"DeviceId,PolicyId,SerialNumber,CertificateStatus,ValidTo\n"+
			"dev-exact,profile-9,00A7,Active,2030-01-01T00:00:00Z\n"+
			"dev-wrong,profile-9,00DEAD,Active,2030-01-01T00:00:00Z\n")
	var intune *httptest.Server
	intune = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer graph-test-token" && !strings.HasSuffix(r.URL.Path, "/report.zip") {
			t.Errorf("Intune API Authorization = %q", got)
		}
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1.0/deviceManagement/managedDevices"):
			_, _ = io.WriteString(w, `{"value":[
				{"id":"dev-exact","deviceName":"laptop-exact","serialNumber":"SER-EXACT","lastSyncDateTime":"2026-08-09T21:00:00Z"},
				{"id":"dev-wrong","deviceName":"laptop-wrong","serialNumber":"SER-WRONG","lastSyncDateTime":"2026-08-09T21:00:00Z"}
			]}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/beta/deviceManagement/reports/exportJobs"):
			requestBody, _ := io.ReadAll(r.Body)
			if !bytes.Contains(requestBody, []byte(`"reportName":"CertificatesByRAPolicy"`)) {
				t.Errorf("report export body does not select certificate evidence: %s", requestBody)
			}
			_, _ = io.WriteString(w, `{"id":"job-57","status":"notStarted"}`)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/beta/deviceManagement/reports/exportJobs("):
			_, _ = io.WriteString(w, `{"id":"job-57","status":"completed","url":"`+intune.URL+`/report.zip"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/report.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(reportArchive)
		default:
			t.Errorf("unexpected Intune operation: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", http.StatusBadRequest)
		}
	}))
	defer intune.Close()
	t.Setenv("TRSTCTL_TEST_GRAPH_TOKEN", "graph-test-token")

	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write", "issuers:read", "issuers:write", string(authz.PrivateEgress))
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/mdm/scep/policies", tok, map[string]any{
		"name": "Intune exact readback", "provider": "intune", "scep_profile": "profile-9",
		"scep_endpoint": "/scep", "challenge_mode": "intune-jws", "enabled": true,
	})
	if status != http.StatusCreated {
		t.Fatalf("create SCEP policy: %d %s", status, body)
	}
	for _, fact := range []struct {
		serial, transaction, certificate string
	}{
		{"SER-EXACT", "txn-exact", "a7"},
		{"SER-WRONG", "txn-wrong", "b8"},
	} {
		for _, event := range []struct {
			typ     string
			outcome scep.AttemptEvidence
		}{
			{scep.EventRequestObserved, scep.AttemptEvidence{TransactionID: fact.transaction, DeviceSerial: fact.serial, Profile: "profile-9", Outcome: "ok"}},
			{scep.EventIssuanceObserved, scep.AttemptEvidence{TransactionID: fact.transaction, DeviceSerial: fact.serial, Profile: "profile-9", Outcome: "ok", CertificateSerial: fact.certificate, CertificateFingerprint: "fingerprint-" + fact.certificate, CertificateNotAfter: time.Now().UTC().Add(90 * 24 * time.Hour)}},
		} {
			payload, err := json.Marshal(event.outcome)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.log.Append(t.Context(), events.Event{Type: event.typ, TenantID: h.tenant, Data: payload}); err != nil {
				t.Fatal(err)
			}
		}
	}

	status, body = secretsReqKey(t, h, http.MethodPut, "/api/v1/mdm/poll-schedule", tok,
		"mdm-exact-report", map[string]any{
			"mdm": "intune", "base_url": intune.URL, "token_ref": servedMDMSecretRef,
			"interval_seconds": 3600, "enabled": true, "execution": "relay",
		})
	if status != http.StatusOK {
		t.Fatalf("configure schedule: %d %s", status, body)
	}
	_, found, err := h.store.GetMDMPollSchedule(t.Context(), h.tenant, mdm.MDMIntune)
	if err != nil || !found {
		t.Fatalf("load schedule: found=%v err=%v", found, err)
	}
	if err := h.srv.recordMDMSync(t.Context(), h.tenant, "relay-1", "mdm-exact-report", mdmJobPayload(t, mdm.MDMIntune), mustJSON(t, MDMSyncReport{
		ObservedAt: time.Now().UTC(), MDM: mdm.MDMIntune, Devices: []mdm.Device{
			{MDM: mdm.MDMIntune, MDMDeviceID: "dev-exact", Name: "laptop-exact", SerialNumber: "SER-EXACT", InstallObserved: true,
				Certificates: []mdm.CertificateObservation{{MDMDeviceID: "dev-exact", PolicyID: "profile-9", SerialNumber: "00A7", Status: "Active"}}, ObservedAt: time.Now().UTC()},
			{MDM: mdm.MDMIntune, MDMDeviceID: "dev-wrong", Name: "laptop-wrong", SerialNumber: "SER-WRONG", InstallObserved: true,
				Certificates: []mdm.CertificateObservation{{MDMDeviceID: "dev-wrong", PolicyID: "profile-9", SerialNumber: "00DEAD", Status: "Active"}}, ObservedAt: time.Now().UTC()},
		},
	})); err != nil {
		t.Fatal(err)
	}

	exact, err := h.store.GetMDMDeviceCorrelation(t.Context(), h.tenant, mdm.MDMIntune, "dev-exact")
	if err != nil {
		t.Fatal(err)
	}
	if exact.TransactionID != "txn-exact" || exact.InstallState != string(mdm.OutcomeOK) || !strings.Contains(exact.InstallDetail, "exact issued serial") {
		t.Fatalf("exact correlation = %+v; want immutable transaction plus exact active certificate evidence", exact)
	}
	wrong, err := h.store.GetMDMDeviceCorrelation(t.Context(), h.tenant, mdm.MDMIntune, "dev-wrong")
	if err != nil {
		t.Fatal(err)
	}
	if wrong.TransactionID != "txn-wrong" || wrong.InstallState != string(mdm.OutcomeFailed) || !strings.Contains(wrong.InstallDetail, "did not contain") {
		t.Fatalf("wrong-serial correlation = %+v; a different active certificate must not prove this issuance", wrong)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/mdm/intune/devices/dev-exact/trace", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("exact trace: %d %s", status, body)
	}
	confirmed := map[string]bool{"requested": false, "issued": false, "installed": false}
	for _, step := range decodeMDMTraceSteps(t, body) {
		if _, tracked := confirmed[step.Stage]; tracked && step.Outcome == "ok" {
			confirmed[step.Stage] = true
		}
	}
	for stage, ok := range confirmed {
		if !ok {
			t.Errorf("exact served trace did not prove %s=ok: %s", stage, body)
		}
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/mdm/intune/devices/dev-wrong/trace", tok, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"broke_at":"installed"`)) {
		t.Fatalf("wrong serial trace must break at installation: %d %s", status, body)
	}
}

func TestServedMDMPollerProvesJamfCertificateInstallationAndFailure(t *testing.T) {
	jamf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/computers-inventory" {
			t.Errorf("unexpected Jamf operation: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		sections := strings.Join(r.URL.Query()["section"], ",")
		for _, required := range []string{"GENERAL", "HARDWARE", "CERTIFICATES"} {
			if !strings.Contains(sections, required) {
				t.Errorf("Jamf inventory sections = %q; missing %s", sections, required)
			}
		}
		_, _ = io.WriteString(w, `{"results":[
			{"id":"jamf-active","general":{"name":"mac-active","lastContactTime":"2026-08-09T21:00:00Z"},"hardware":{"serialNumber":"MAC-ACTIVE"},"certificates":[{"serialNumber":"00C7","certificateStatus":"ACTIVE"}]},
			{"id":"jamf-revoked","general":{"name":"mac-revoked","lastContactTime":"2026-08-09T21:00:00Z"},"hardware":{"serialNumber":"MAC-REVOKED"},"certificates":[{"serialNumber":"00D8","certificateStatus":"REVOKED"}]}
		]}`)
	}))
	defer jamf.Close()
	t.Setenv("TRSTCTL_TEST_GRAPH_TOKEN", "jamf-test-token")

	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write", string(authz.PrivateEgress))
	for _, fact := range []struct {
		serial, transaction, certificate string
	}{
		{"MAC-ACTIVE", "txn-jamf-active", "c7"},
		{"MAC-REVOKED", "txn-jamf-revoked", "d8"},
	} {
		appendServedMDMSCEPAttempt(t, h, fact.serial, fact.transaction, fact.certificate, time.Now().UTC().Add(90*24*time.Hour))
	}
	status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/mdm/poll-schedule", tok,
		"mdm-jamf-exact", map[string]any{
			"mdm": "jamf", "base_url": jamf.URL, "token_ref": servedMDMSecretRef,
			"interval_seconds": 3600, "enabled": true, "execution": "relay",
		})
	if status != http.StatusOK {
		t.Fatalf("configure Jamf schedule: %d %s", status, body)
	}
	_, found, err := h.store.GetMDMPollSchedule(t.Context(), h.tenant, mdm.MDMJamf)
	if err != nil || !found {
		t.Fatalf("load Jamf schedule: found=%v err=%v", found, err)
	}
	if err := h.srv.recordMDMSync(t.Context(), h.tenant, "relay-1", "mdm-jamf-exact", mdmJobPayload(t, mdm.MDMJamf), mustJSON(t, MDMSyncReport{
		ObservedAt: time.Now().UTC(), MDM: mdm.MDMJamf, Devices: []mdm.Device{
			{MDM: mdm.MDMJamf, MDMDeviceID: "jamf-active", Name: "mac-active", SerialNumber: "MAC-ACTIVE", InstallObserved: true,
				Certificates: []mdm.CertificateObservation{{MDMDeviceID: "jamf-active", SerialNumber: "00C7", Status: "ACTIVE"}}, ObservedAt: time.Now().UTC()},
			{MDM: mdm.MDMJamf, MDMDeviceID: "jamf-revoked", Name: "mac-revoked", SerialNumber: "MAC-REVOKED", InstallObserved: true,
				Certificates: []mdm.CertificateObservation{{MDMDeviceID: "jamf-revoked", SerialNumber: "00D8", Status: "REVOKED"}}, ObservedAt: time.Now().UTC()},
		},
	})); err != nil {
		t.Fatal(err)
	}

	active, err := h.store.GetMDMDeviceCorrelation(t.Context(), h.tenant, mdm.MDMJamf, "jamf-active")
	if err != nil {
		t.Fatal(err)
	}
	if active.InstallState != string(mdm.OutcomeOK) || active.TransactionID != "txn-jamf-active" {
		t.Fatalf("Jamf active correlation = %+v", active)
	}
	revoked, err := h.store.GetMDMDeviceCorrelation(t.Context(), h.tenant, mdm.MDMJamf, "jamf-revoked")
	if err != nil {
		t.Fatal(err)
	}
	if revoked.InstallState != string(mdm.OutcomeFailed) || !strings.Contains(strings.ToLower(revoked.InstallDetail), "revoked") {
		t.Fatalf("Jamf revoked correlation = %+v; exact presence with a revoked status is not installed=ok", revoked)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/mdm/jamf/devices/jamf-revoked/trace", tok, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"broke_at":"installed"`)) {
		t.Fatalf("Jamf revoked trace must break at installed: %d %s", status, body)
	}
}

func appendServedMDMSCEPAttempt(t *testing.T, h *servedHarness, serial, transaction, certificate string, notAfter time.Time) {
	t.Helper()
	for _, event := range []struct {
		typ     string
		outcome scep.AttemptEvidence
	}{
		{scep.EventRequestObserved, scep.AttemptEvidence{TransactionID: transaction, DeviceSerial: serial, Profile: "profile-9", Outcome: "ok"}},
		{scep.EventIssuanceObserved, scep.AttemptEvidence{TransactionID: transaction, DeviceSerial: serial, Profile: "profile-9", Outcome: "ok", CertificateSerial: certificate, CertificateFingerprint: "fingerprint-" + certificate, CertificateNotAfter: notAfter}},
	} {
		payload, err := json.Marshal(event.outcome)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.log.Append(t.Context(), events.Event{Type: event.typ, TenantID: h.tenant, Data: payload}); err != nil {
			t.Fatal(err)
		}
	}
}

func servedIntuneCertificateReportZIP(t *testing.T, csvBody string) []byte {
	t.Helper()
	var output bytes.Buffer
	archive := zip.NewWriter(&output)
	entry, err := archive.Create("CertificatesByRAPolicy.csv")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(entry, csvBody); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestServedMDMPollerCorrelatesAndFlagsOfflineRenewals(t *testing.T) {
	reportArchive := servedIntuneCertificateReportZIP(t, "DeviceId,PolicyId,SerialNumber,CertificateStatus,ValidTo\n")
	var intune *httptest.Server
	intune = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1.0/deviceManagement/managedDevices"):
			_, _ = w.Write([]byte(`{"value":[
				{"id":"dev-1","deviceName":"laptop-1","serialNumber":"SER-ENROLLED"},
				{"id":"dev-2","deviceName":"laptop-2","serialNumber":"SER-UNKNOWN"}
			]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/beta/deviceManagement/reports/exportJobs"):
			requestBody, _ := io.ReadAll(r.Body)
			if !bytes.Contains(requestBody, []byte(`"reportName":"CertificatesByRAPolicy"`)) {
				t.Errorf("the sole Intune POST is not the fixed certificate report artifact: %s", requestBody)
			}
			_, _ = io.WriteString(w, `{"id":"renewal-risk-report","status":"notStarted"}`)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/beta/deviceManagement/reports/exportJobs("):
			_, _ = io.WriteString(w, `{"id":"renewal-risk-report","status":"completed","url":"`+intune.URL+`/report.zip"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/report.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(reportArchive)
		default:
			t.Errorf("unexpected or mutating Intune operation: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", http.StatusBadRequest)
		}
	}))
	defer intune.Close()
	t.Setenv("TRSTCTL_TEST_GRAPH_TOKEN", "graph-test-token")

	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write", "owners:write", "owners:read",
		"issuers:read", "issuers:write", string(authz.PrivateEgress))
	status, out := secretsReq(t, h, http.MethodPost, "/api/v1/mdm/scep/policies", tok, map[string]any{
		"name": "Renewal risk evidence", "provider": "intune", "scep_profile": "profile-renewal-risk",
		"scep_endpoint": "/scep", "challenge_mode": "intune-jws", "enabled": true,
	})
	if status != http.StatusCreated {
		t.Fatalf("create SCEP policy: %d %s", status, out)
	}

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
	status, out = secretsReqKey(t, h, http.MethodPut, "/api/v1/mdm/poll-schedule", tok,
		"mdm-sched-bad", map[string]any{
			"mdm": "intune", "base_url": intune.URL, "token_ref": servedMDMTokenRef,
			"interval_seconds": 3600, "enabled": true, "execution": "relay",
		})
	if status != http.StatusBadRequest || !strings.Contains(string(out), "secret://") {
		t.Fatalf("relay execution with an env: ref = %d %s", status, out)
	}

	status, out = secretsReqKey(t, h, http.MethodPut, "/api/v1/mdm/poll-schedule", tok,
		"mdm-sched-1", map[string]any{
			"mdm": "intune", "base_url": intune.URL, "token_ref": servedMDMSecretRef,
			"interval_seconds": 3600, "enabled": true, "execution": "relay",
		})
	if status != http.StatusOK {
		t.Fatalf("configure schedule: %d %s", status, out)
	}
	_, found, err := h.store.GetMDMPollSchedule(t.Context(), h.tenant, mdm.MDMIntune)
	if err != nil || !found {
		t.Fatalf("schedule not persisted: found=%v err=%v", found, err)
	}

	if err := h.srv.recordMDMSync(t.Context(), h.tenant, "relay-1", "mdm-sched-1", mdmJobPayload(t, mdm.MDMIntune), mustJSON(t, MDMSyncReport{
		ObservedAt: time.Now().UTC(), MDM: mdm.MDMIntune, Devices: []mdm.Device{
			{MDM: mdm.MDMIntune, MDMDeviceID: "dev-1", Name: "laptop-1", SerialNumber: "SER-ENROLLED"},
			{MDM: mdm.MDMIntune, MDMDeviceID: "dev-2", Name: "laptop-2", SerialNumber: "SER-UNKNOWN"},
		},
	})); err != nil {
		t.Fatal(err)
	}

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
	h := newOperatingServedHarness(t, config.Protocols{})
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
	if err := h.srv.recordMDMSync(t.Context(), h.tenant, "relay-1", "provider-mismatch",
		mdmJobPayload(t, mdm.MDMJamf), mustJSON(t, MDMSyncReport{ObservedAt: time.Now().UTC(), MDM: mdm.MDMIntune})); err == nil {
		t.Fatal("an Intune report was accepted for a durable Jamf job intent")
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
	report, err := json.Marshal(MDMSyncReport{ObservedAt: time.Now().UTC(), MDM: mdm.MDMJamf, Devices: []mdm.Device{
		{MDM: mdm.MDMJamf, MDMDeviceID: "j-9", Name: "mac-9", SerialNumber: "SER-J9",
			InstallState: mdm.OutcomeUnknown, ObservedAt: time.Now().UTC()},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.recordMDMSync(t.Context(), h.tenant, "relay-1", "idem-9", mdmJobPayload(t, mdm.MDMJamf), string(report)); err != nil {
		t.Fatal(err)
	}

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

func TestMDMRelayPendingBulkheadIsProviderScoped(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write")
	for _, provider := range []string{mdm.MDMIntune, mdm.MDMJamf} {
		status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/mdm/poll-schedule", tok,
			"mdm-provider-bulkhead-"+provider, map[string]any{
				"mdm": provider, "base_url": "https://" + provider + ".internal.example",
				"token_ref": servedMDMSecretRef, "interval_seconds": 3600, "enabled": true,
				"execution": "relay",
			})
		if status != http.StatusOK {
			t.Fatalf("configure %s schedule: %d %s", provider, status, body)
		}
	}

	intuneSchedule, found, err := h.store.GetMDMPollSchedule(t.Context(), h.tenant, mdm.MDMIntune)
	if err != nil || !found {
		t.Fatalf("load Intune schedule: found=%v err=%v", found, err)
	}
	jamfSchedule, found, err := h.store.GetMDMPollSchedule(t.Context(), h.tenant, mdm.MDMJamf)
	if err != nil || !found {
		t.Fatalf("load Jamf schedule: found=%v err=%v", found, err)
	}

	// A second Intune tick must see the first Intune intent and stop, while the
	// independent Jamf lane must still get one job. A tenant-wide destination
	// check incorrectly stops both providers here.
	h.srv.dispatchMDMSyncJob(t.Context(), h.tenant, intuneSchedule)
	h.srv.dispatchMDMSyncJob(t.Context(), h.tenant, intuneSchedule)
	h.srv.dispatchMDMSyncJob(t.Context(), h.tenant, jamfSchedule)
	var intuneJobs, jamfJobs int
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(t.Context(),
			`SELECT count(*) FILTER (WHERE convert_from(payload, 'UTF8')::jsonb ->> 'mdm' = 'intune'),
			        count(*) FILTER (WHERE convert_from(payload, 'UTF8')::jsonb ->> 'mdm' = 'jamf')
			   FROM outbox
			  WHERE tenant_id = $1 AND destination = 'mdm.sync'`, h.tenant).Scan(&intuneJobs, &jamfJobs)
	}); err != nil {
		t.Fatal(err)
	}
	if intuneJobs != 1 || jamfJobs != 1 {
		t.Fatalf("provider bulkheads produced Intune=%d Jamf=%d jobs, want one each; one provider must not starve the other", intuneJobs, jamfJobs)
	}

	intuneWaiting, _, err := h.store.GetMDMPollSchedule(t.Context(), h.tenant, mdm.MDMIntune)
	if err != nil || intuneWaiting.LastRunAt == nil || !strings.Contains(intuneWaiting.LastError, "waiting") {
		t.Fatalf("second Intune tick did not stamp only its waiting state: %+v err=%v", intuneWaiting, err)
	}
	intuneStamp := *intuneWaiting.LastRunAt
	if err := h.srv.recordMDMSync(t.Context(), h.tenant, "relay-jamf", "mdm-jamf-result",
		mdmJobPayload(t, mdm.MDMJamf), mustJSON(t, MDMSyncReport{ObservedAt: time.Now().UTC(), MDM: mdm.MDMJamf})); err != nil {
		t.Fatal(err)
	}
	intuneAfterJamf, _, err := h.store.GetMDMPollSchedule(t.Context(), h.tenant, mdm.MDMIntune)
	if err != nil {
		t.Fatal(err)
	}
	if intuneAfterJamf.LastRunAt == nil || !intuneAfterJamf.LastRunAt.Equal(intuneStamp) || intuneAfterJamf.LastError != intuneWaiting.LastError {
		t.Fatalf("Jamf result mutated Intune schedule: before=%+v after=%+v", intuneWaiting, intuneAfterJamf)
	}
	jamfAfterResult, _, err := h.store.GetMDMPollSchedule(t.Context(), h.tenant, mdm.MDMJamf)
	if err != nil || jamfAfterResult.LastError != "" {
		t.Fatalf("Jamf result did not stamp its own schedule successful: %+v err=%v", jamfAfterResult, err)
	}
}
