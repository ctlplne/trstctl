// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/mdm"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/protocols/scep"
)

// I5 through the running binary. The trace rules are unit-tested as pure
// functions, which proves the rules and nothing about whether a request reaches
// them.

func TestServedDeviceTraceNamesTheStepThatBroke(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	observed := time.Now().UTC()
	if err := h.srv.orch.CorrelateMDMDevice(t.Context(), h.tenant, projections.MDMDeviceCorrelated{
		MDM: "intune", MDMDeviceID: "dev-1", DeviceName: "laptop-7", SerialNumber: "S1",
		TransactionID: "txn-1", InstallState: "failed",
		InstallDetail: "Intune reports the SCEP profile failed to install: device storage full.",
		ObservedAt:    &observed,
	}); err != nil {
		t.Fatal(err)
	}

	tok := seedScopedToken(t, h.store, h.tenant, "certs:read")
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/mdm/intune/devices/dev-1/trace", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("trace: status %d body %s", status, body)
	}
	var out struct {
		Trace struct {
			BrokeAt string `json:"broke_at"`
			Summary string `json:"summary"`
			Steps   []struct {
				Stage   string `json:"stage"`
				Outcome string `json:"outcome"`
				Source  string `json:"source"`
			} `json:"steps"`
		} `json:"trace"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Trace.BrokeAt != "installed" {
		t.Fatalf("broke_at = %q, want installed. Without this an operator gets \"failed\" and has "+
			"to reconstruct which step from three systems' logs", out.Trace.BrokeAt)
	}
	if !strings.Contains(out.Trace.Summary, "storage full") {
		t.Fatalf("summary = %q; it must lead with WHAT broke", out.Trace.Summary)
	}
	if len(out.Trace.Steps) != 4 {
		t.Fatalf("trace has %d steps, want all four — a view that omits a stage cannot show where "+
			"enrollment stopped", len(out.Trace.Steps))
	}
	for _, s := range out.Trace.Steps {
		if s.Stage == "installed" && s.Source != "intune" {
			t.Errorf("the install step does not name which MDM claimed it (%q); an operator "+
				"deciding whether to trust it needs the source", s.Source)
		}
	}
}

func TestServedDeviceTraceDoesNotInferSuccessFromCorrelationIDs(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	if err := h.srv.orch.CorrelateMDMDevice(t.Context(), h.tenant, projections.MDMDeviceCorrelated{
		MDM: "intune", MDMDeviceID: "dev-no-evidence", TransactionID: "txn-only-a-label",
		IdentityID: "11111111-1111-4111-8111-111111111111", InstallState: "unknown",
	}); err != nil {
		t.Fatal(err)
	}

	tok := seedScopedToken(t, h.store, h.tenant, "certs:read")
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/mdm/intune/devices/dev-no-evidence/trace", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("trace: status %d body %s", status, body)
	}
	for _, step := range decodeMDMTraceSteps(t, body) {
		if (step.Stage == "requested" || step.Stage == "issued") && step.Outcome == "ok" {
			t.Fatalf("trace inferred %s=ok from correlation IDs alone: %s", step.Stage, body)
		}
	}
}

func TestServedDeviceTraceUsesOnlyDurableSCEPAttemptEvidenceIncludingRenewing(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	serial := "SER-DURABLE"
	for _, event := range []struct {
		typ      string
		evidence scep.AttemptEvidence
	}{
		{scep.EventRequestObserved, scep.AttemptEvidence{TransactionID: "txn-initial", DeviceSerial: serial, Outcome: "ok"}},
		{scep.EventIssuanceObserved, scep.AttemptEvidence{TransactionID: "txn-initial", DeviceSerial: serial, Outcome: "ok", CertificateSerial: "cert-initial", CertificateFingerprint: "fp-initial", CertificateNotAfter: time.Now().UTC().Add(24 * time.Hour)}},
		{scep.EventRequestObserved, scep.AttemptEvidence{TransactionID: "txn-renewal", DeviceSerial: serial, Outcome: "ok"}},
		{scep.EventIssuanceObserved, scep.AttemptEvidence{TransactionID: "txn-renewal", DeviceSerial: serial, Outcome: "ok", CertificateSerial: "cert-renewal", CertificateFingerprint: "fp-renewal", CertificateNotAfter: time.Now().UTC().Add(30 * 24 * time.Hour)}},
	} {
		payload, err := json.Marshal(event.evidence)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.log.Append(t.Context(), events.Event{Type: event.typ, TenantID: h.tenant, Data: payload}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.srv.orch.CorrelateMDMDevice(t.Context(), h.tenant, projections.MDMDeviceCorrelated{
		MDM: "intune", MDMDeviceID: "dev-with-evidence", SerialNumber: serial,
		TransactionID: "txn-renewal", InstallState: "unknown",
	}); err != nil {
		t.Fatal(err)
	}

	tok := seedScopedToken(t, h.store, h.tenant, "certs:read")
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/mdm/intune/devices/dev-with-evidence/trace", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("trace: status %d body %s", status, body)
	}
	wantOK := map[string]bool{"requested": false, "issued": false, "renewing": false}
	for _, step := range decodeMDMTraceSteps(t, body) {
		if _, tracked := wantOK[step.Stage]; tracked && step.Outcome == "ok" {
			wantOK[step.Stage] = true
		}
	}
	for stage, observed := range wantOK {
		if !observed {
			t.Errorf("trace did not derive %s=ok from its durable event: %s", stage, body)
		}
	}
}

func TestServedDeviceTraceRetainsPreIssuanceChallengeFailure(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	serial, transaction := "SER-CHALLENGE-FAILED", "txn-challenge-failed"
	for _, event := range []struct {
		typ      string
		evidence scep.AttemptEvidence
	}{
		{scep.EventRequestObserved, scep.AttemptEvidence{TransactionID: transaction, DeviceSerial: serial, Outcome: "ok", Detail: "request parsed"}},
		{scep.EventIssuanceObserved, scep.AttemptEvidence{TransactionID: transaction, DeviceSerial: serial, Outcome: "failed", Detail: "Challenge validation rejected the request; verify audience, expiry, and one-time nonce."}},
	} {
		payload, err := json.Marshal(event.evidence)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.log.Append(t.Context(), events.Event{Type: event.typ, TenantID: h.tenant, Data: payload}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.srv.correlateMDMDevices(t.Context(), h.tenant, []mdm.Device{{
		MDM: mdm.MDMIntune, MDMDeviceID: "dev-challenge-failed", SerialNumber: serial,
	}}); err != nil {
		t.Fatal(err)
	}

	tok := seedScopedToken(t, h.store, h.tenant, "certs:read")
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/mdm/intune/devices/dev-challenge-failed/trace", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("challenge-failure trace: %d %s", status, body)
	}
	steps := decodeMDMTraceSteps(t, body)
	if steps[0].Stage != "requested" || steps[0].Outcome != "ok" || steps[1].Stage != "issued" || steps[1].Outcome != "failed" || !strings.Contains(strings.ToLower(steps[1].Detail), "challenge") {
		t.Fatalf("pre-issuance failure was not retained with remediation: %s", body)
	}
	if !bytes.Contains(body, []byte(`"broke_at":"issued"`)) {
		t.Fatalf("challenge failure did not break at issued: %s", body)
	}
}

func TestServedDeviceTraceMarksOfflineRenewalAsUnknownWithRemediation(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	now := time.Now().UTC()
	serial, transaction := "SER-OFFLINE", "txn-initial-offline"
	appendServedMDMSCEPAttempt(t, h, serial, transaction, "e9", now.Add(10*24*time.Hour))
	lastSeen := now.Add(-60 * 24 * time.Hour)
	if err := h.srv.correlateMDMDevices(t.Context(), h.tenant, []mdm.Device{{
		MDM: mdm.MDMJamf, MDMDeviceID: "dev-offline", SerialNumber: serial, ObservedAt: lastSeen,
		InstallObserved: true,
		Certificates:    []mdm.CertificateObservation{{MDMDeviceID: "dev-offline", SerialNumber: "00E9", Status: "ACTIVE"}},
	}}); err != nil {
		t.Fatal(err)
	}

	tok := seedScopedToken(t, h.store, h.tenant, "certs:read")
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/mdm/jamf/devices/dev-offline/trace", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("offline trace: %d %s", status, body)
	}
	var renewal struct {
		Outcome string
		Detail  string
	}
	for _, step := range decodeMDMTraceSteps(t, body) {
		if step.Stage == "renewing" {
			renewal.Outcome, renewal.Detail = step.Outcome, step.Detail
		}
	}
	if renewal.Outcome != "unknown" || !strings.Contains(renewal.Detail, "bring the device online") || !strings.Contains(renewal.Detail, "No later SCEP renewal transaction") {
		t.Fatalf("offline renewal = %+v; want unknown with check-in remediation: %s", renewal, body)
	}
}

func decodeMDMTraceSteps(t *testing.T, body []byte) []struct {
	Stage   string `json:"stage"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail"`
} {
	t.Helper()
	var out struct {
		Trace struct {
			Steps []struct {
				Stage   string `json:"stage"`
				Outcome string `json:"outcome"`
				Detail  string `json:"detail"`
			} `json:"steps"`
		} `json:"trace"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out.Trace.Steps
}

// An unobserved device must not be served as a failure, and must be counted
// apart from one.
func TestServedUnobservedDeviceIsNotCountedAsFailed(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	observed := time.Now().UTC()
	for _, d := range []projections.MDMDeviceCorrelated{
		{MDM: "jamf", MDMDeviceID: "j1", SerialNumber: "S1", TransactionID: "t1",
			InstallState: "unknown", InstallDetail: "Jamf could not be reached.", ObservedAt: &observed},
		{MDM: "jamf", MDMDeviceID: "j2", SerialNumber: "S2", TransactionID: "t2",
			InstallState: "failed", InstallDetail: "profile rejected", ObservedAt: &observed},
	} {
		if err := h.srv.orch.CorrelateMDMDevice(t.Context(), h.tenant, d); err != nil {
			t.Fatal(err)
		}
	}
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read")
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/mdm/devices", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list: %d %s", status, body)
	}
	var out struct {
		Failed     int `json:"failed"`
		Unobserved int `json:"unobserved"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Failed != 1 || out.Unobserved != 1 {
		t.Fatalf("failed=%d unobserved=%d, want 1 and 1.\n\n"+
			"Merging them into one number sends somebody to re-push a profile that is already "+
			"installed — the MDM was simply unreachable.", out.Failed, out.Unobserved)
	}
}

// An install state the console cannot render must be refused, not stored.
func TestServedCorrelationRefusesAnUnrenderableState(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	err := h.srv.orch.CorrelateMDMDevice(t.Context(), h.tenant, projections.MDMDeviceCorrelated{
		MDM: "intune", MDMDeviceID: "d1", InstallState: "somethingElse",
	})
	if err == nil {
		t.Fatal("an unrecognised install state was stored. The console cannot render it, so the " +
			"row would be invisible — a device with a problem nobody can see")
	}
	if err := h.srv.orch.CorrelateMDMDevice(t.Context(), h.tenant, projections.MDMDeviceCorrelated{
		MDM: "intune", MDMDeviceID: "", InstallState: "ok",
	}); err == nil {
		t.Fatal("a correlation with no device id was accepted; it joins to nothing and inflates " +
			"coverage with a row that means nothing")
	}
}

// Read-only is structural: inventory is GET-only. The sole non-GET operation is
// Microsoft's fixed report-export creation, which cannot name an MDM mutation.
func TestNoMDMCodePathCanWrite(t *testing.T) {
	t.Parallel()
	// The poller and the relay executor joined the list when I5 gained its
	// producer: both FETCH from an MDM, so both are exactly where a mutating
	// verb would be a profile pushed to real laptops.
	for _, f := range []string{"../mdm/correlate.go", "../mdm/trace.go", "../mdm/renewal.go", "../mdm/install.go",
		"../api/mdm_devices.go", "mdm_poller.go", "../agent/relay/mdmsync.go"} {
		src, err := readSourceFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, verb := range []string{"MethodPost", "MethodPut", "MethodPatch", "MethodDelete"} {
			if strings.Contains(src, verb) {
				t.Fatalf("%s references http.%s.\n\n"+
					"The MDM integration is read-only by construction. A bad write to an MDM does "+
					"not corrupt a record — it pushes a profile to real laptops.", f, verb)
			}
		}
	}
	reportSource, err := readSourceFile("../mdm/intune_report.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"MethodPut", "MethodPatch", "MethodDelete"} {
		if strings.Contains(reportSource, verb) {
			t.Fatalf("Intune report reader references http.%s; report evidence must never mutate a profile or device", verb)
		}
	}
	for _, fixed := range []string{"/beta/deviceManagement/reports/exportJobs", "CertificatesByRAPolicy"} {
		if !strings.Contains(reportSource, fixed) {
			t.Fatalf("Intune report reader lost fixed artifact selector %q", fixed)
		}
	}
	for _, forbidden := range []string{"deviceConfigurations/", "/assign", "managedDevices/"} {
		if strings.Contains(reportSource, forbidden) {
			t.Fatalf("Intune report reader contains mutation-capable resource fragment %q", forbidden)
		}
	}
}
