package nhibehavior

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFindingsDetectsFiveDimensionBehaviorAnomaly(t *testing.T) {
	findings, err := Findings(json.RawMessage(`{
		"business_hours":{"start_hour":8,"end_hour":18},
		"events":[
			{"principal":"payments-api","occurred_at":"2026-06-01T10:00:00Z","ip":"198.51.100.10","geo":"us","user_agent":"payments-agent/1.0","action":"token_use","usage_count":10,"baseline":true},
			{"principal":"payments-api","occurred_at":"2026-06-02T02:15:00Z","ip":"203.0.113.9","geo":"de","user_agent":"curl/8.7","action":"token_use","usage_count":90}
		]
	}`))
	if err != nil {
		t.Fatalf("Findings returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings count = %d, want 1", len(findings))
	}
	f := findings[0]
	if f.Ref != "payments-api" || !strings.HasPrefix(f.Provenance, "nhi_behavior:payments-api:") || f.Fingerprint != f.Provenance {
		t.Fatalf("unexpected finding identity: %+v", f)
	}
	if f.RiskScore != 100 {
		t.Fatalf("risk score = %d, want capped high-risk anomaly", f.RiskScore)
	}
	reasons, ok := f.Metadata["anomaly_reasons"].([]string)
	if !ok {
		t.Fatalf("anomaly_reasons = %#v, want []string", f.Metadata["anomaly_reasons"])
	}
	want := []string{"unfamiliar_ip", "unfamiliar_geo", "unfamiliar_user_agent", "usage_spike", "off_hours"}
	if strings.Join(reasons, ",") != strings.Join(want, ",") {
		t.Fatalf("reasons = %v, want %v", reasons, want)
	}
	if f.Metadata["geo"] != "DE" {
		t.Fatalf("geo = %#v, want normalized country code", f.Metadata["geo"])
	}
}

func TestFindingsRejectsMissingBaseline(t *testing.T) {
	_, err := Findings(json.RawMessage(`{
		"events":[{"principal":"payments-api","occurred_at":"2026-06-02T02:15:00Z","ip":"203.0.113.9","geo":"DE","user_agent":"curl/8.7","usage_count":90}]
	}`))
	if err == nil || !strings.Contains(err.Error(), "baseline") {
		t.Fatalf("Findings error = %v, want missing baseline rejection", err)
	}
}
