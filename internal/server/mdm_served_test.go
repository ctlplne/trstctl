// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/projections"
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

// Read-only is structural: no MDM code may construct a non-GET request.
func TestNoMDMCodePathCanWrite(t *testing.T) {
	t.Parallel()
	// The poller and the relay executor joined the list when I5 gained its
	// producer: both FETCH from an MDM, so both are exactly where a mutating
	// verb would be a profile pushed to real laptops.
	for _, f := range []string{"../mdm/correlate.go", "../mdm/trace.go", "../mdm/renewal.go",
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
}
