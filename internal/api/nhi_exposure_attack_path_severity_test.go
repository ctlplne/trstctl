// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"slices"
	"testing"
	"time"
)

// A167-L3: an open attack path raises the exposure finding (and the posture
// automation's facts, which policy rules act on) to at least high, to critical
// with weak authentication, adds cloud_path_open and raises the risk score; a
// blocked or unknown verdict changes nothing.
func TestOpenAttackPathRaisesExposureSeverityA167L3(t *testing.T) {
	item := func(meta map[string]any) nhiInventoryItem {
		raw, err := json.Marshal(meta)
		if err != nil {
			t.Fatal(err)
		}
		return nhiInventoryItem{ID: "finding/a167l3", Kind: "api_key", Source: "discovery", DisplayName: "partner-token", Status: "discovered",
			RiskScore: 40, Metadata: raw}
	}
	open := &nhiExposureAttackPath{Status: "open", CheckedAt: time.Now().UTC()}
	blocked := &nhiExposureAttackPath{Status: "blocked", CheckedAt: time.Now().UTC()}
	for name, tc := range map[string]struct {
		meta     map[string]any
		path     *nhiExposureAttackPath
		severity string
		risk     int
		types    []string
	}{
		"no verdict":                         {map[string]any{"public_endpoint": "https://203.0.113.9/api"}, nil, "medium", 65, []string{"internet_exposed"}},
		"blocked changes nothing":            {map[string]any{"public_endpoint": "https://203.0.113.9/api"}, blocked, "medium", 65, []string{"internet_exposed"}},
		"open raises to high":                {map[string]any{"public_endpoint": "https://203.0.113.9/api"}, open, "high", 88, []string{"internet_exposed", "cloud_path_open"}},
		"open with weak auth is critical":    {map[string]any{"public_endpoint": "https://203.0.113.9/api", "auth_mode": "none"}, open, "critical", 100, []string{"internet_exposed", "weak_authentication", "cloud_path_open"}},
		"open over plain HTTP is critical":   {map[string]any{"public_endpoint": "http://203.0.113.9/api"}, open, "critical", 100, []string{"internet_exposed", "insecure_transport", "cloud_path_open"}},
		"an unknown verdict changes nothing": {map[string]any{"public_endpoint": "https://203.0.113.9/api"}, &nhiExposureAttackPath{Status: "unknown"}, "medium", 65, []string{"internet_exposed"}},
	} {
		finding, ok := nhiExposureFindingForItem(item(tc.meta))
		if !ok {
			t.Fatalf("%s: no exposure finding", name)
		}
		nhiExposureApplyAttackPath(&finding, tc.path)
		if finding.Severity != tc.severity || finding.RiskScore != tc.risk || !slices.Equal(finding.FindingTypes, tc.types) {
			t.Errorf("%s: finding = %s %d %v; want %s %d %v", name, finding.Severity, finding.RiskScore, finding.FindingTypes, tc.severity, tc.risk, tc.types)
		}
		if tc.path == open && finding.Recommendation == nhiExposureRecommendation([]string{"internet_exposed"}) {
			t.Errorf("%s: the recommendation does not mention the confirmed cloud path", name)
		}
		facts, _, ok := nhiPostureFactsForItem(item(tc.meta), time.Now().UTC(), tc.path)
		if !ok || facts.Severity != tc.severity || facts.RiskScore < tc.risk || slices.Contains(facts.FindingTypes, "cloud_path_open") != (tc.path == open) {
			t.Errorf("%s: automation facts = %s %d %v; want %s and cloud_path_open only when open", name, facts.Severity, facts.RiskScore, facts.FindingTypes, tc.severity)
		}
	}
}
