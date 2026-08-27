// SPDX-License-Identifier: MPL-2.0

package featureparity

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderControlPanelUsesCanonicalCatalogOnly(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	var first bytes.Buffer
	if err := RenderControlPanel(&first, catalog, ReportOptions{
		Title:        "trstctl frontend parity control panel",
		ConsoleBase:  "http://127.0.0.1:58780",
		GeneratedAt:  "2026-08-25T09:46:14Z",
		CandidateSHA: strings.Repeat("b", 40),
	}); err != nil {
		t.Fatalf("render control panel: %v", err)
	}
	var second bytes.Buffer
	if err := RenderControlPanel(&second, catalog, ReportOptions{
		Title:        "trstctl frontend parity control panel",
		ConsoleBase:  "http://127.0.0.1:58780",
		GeneratedAt:  "2026-08-25T09:46:14Z",
		CandidateSHA: strings.Repeat("b", 40),
	}); err != nil {
		t.Fatalf("render control panel twice: %v", err)
	}
	if first.String() != second.String() {
		t.Fatal("control panel output is not deterministic")
	}

	html := first.String()
	for _, want := range []string{
		"<!doctype html>",
		"trstctl frontend parity control panel",
		"51 release blockers",
		"18 complete vertical slices",
		"Filter capabilities",
		"data-tool=\"secrets\"",
		"F66",
		"Encryption-as-a-service and KMIP",
		"Signature verification, full version history, filtered audit receipts, and KMIP status remain parity debt.",
		"http://127.0.0.1:58780/secrets/engines",
		"candidate bbbbbbbb",
		"Report candidate: <code>bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb</code>",
		"Contract evidence recorded at: <code>73b871089f46e4cc9e95ca10473b9ae5872a53cd</code>",
		"discover",
		"verify",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("control panel missing %q", want)
		}
	}
	for _, item := range catalog.Items {
		if strings.Count(html, ">"+item.FeatureID+"<") != 1 {
			t.Errorf("%s should render exactly once", item.FeatureID)
		}
	}
	if strings.Contains(html, "<script src=") || strings.Contains(html, "<link rel=\"stylesheet\"") {
		t.Fatal("control panel must be standalone and offline")
	}
}

func TestRenderControlPanelEscapesCatalogText(t *testing.T) {
	catalog := Catalog{
		SchemaVersion:     3,
		CanonicalTools:    []CanonicalTool{ToolDiscover, ToolCertificates, ToolWorkloadsMachines, ToolSecrets, ToolSoftwareTrust, ToolOperations, ToolPlatformIntegrations},
		MaturityValues:    []Maturity{MaturityAbsent, MaturityAPICLIOnly, MaturityObserveOnly, MaturityPartialWorkflow, MaturityCompleteVerticalSlice},
		StageStatusValues: []StageStatus{StageComplete, StageNotApplicable, StageIntentionalAPIOnly, StageBlocked, StageMissing},
		Items: []Item{{
			FeatureID: "F-test",
			Feature:   `<script>alert("unsafe")</script>`,
			Contract: CapabilityContract{
				Purpose:               "Plain explanation.",
				Tool:                  ToolOperations,
				Classification:        CapabilitySupporting,
				ConsoleRoute:          "/operations",
				NavigationEntrypoints: []string{"tool navigation"},
				PermissionAuthority:   "served route registry",
				Edition:               "core",
				SideEffects:           "read_only",
				SecretDataHandling:    "metadata only",
				Maturity:              MaturityCompleteVerticalSlice,
				Stages: StageSet{
					Discover:   StageRecord{Status: StageComplete, Evidence: []string{"route"}},
					Understand: StageRecord{Status: StageComplete, Evidence: []string{"copy"}},
					Configure:  StageRecord{Status: StageNotApplicable, Reason: "read only"},
					Preview:    StageRecord{Status: StageNotApplicable, Reason: "read only"},
					Execute:    StageRecord{Status: StageNotApplicable, Reason: "read only"},
					Observe:    StageRecord{Status: StageComplete, Evidence: []string{"view"}},
					Recover:    StageRecord{Status: StageNotApplicable, Reason: "read only"},
					Verify:     StageRecord{Status: StageComplete, Evidence: []string{"test"}},
					Automate:   StageRecord{Status: StageNotApplicable, Reason: "read only"},
				},
				Owner:            "operations",
				TargetCheckpoint: "maintain",
				CandidateSHA:     strings.Repeat("a", 40),
				Freshness:        "2026-08-25",
			},
		}},
	}
	var out bytes.Buffer
	if err := RenderControlPanel(&out, catalog, ReportOptions{
		Title: "Parity", GeneratedAt: "2026-08-25T00:00:00Z", CandidateSHA: strings.Repeat("b", 40),
	}); err != nil {
		t.Fatalf("render escaped panel: %v", err)
	}
	if strings.Contains(out.String(), `<script>alert("unsafe")</script>`) || !strings.Contains(out.String(), "&lt;script&gt;") {
		t.Fatalf("catalog text was not escaped: %s", out.String())
	}
}

func TestRenderControlPanelRequiresExactReportCandidate(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	for _, candidate := range []string{"", "main", strings.Repeat("a", 39), strings.Repeat("A", 40)} {
		var out bytes.Buffer
		err := RenderControlPanel(&out, catalog, ReportOptions{
			Title: "Parity", GeneratedAt: "2026-08-25T00:00:00Z", CandidateSHA: candidate,
		})
		if err == nil || !strings.Contains(err.Error(), "exact report candidate") {
			t.Errorf("candidate %q error = %v, want exact report candidate rejection", candidate, err)
		}
	}
}
