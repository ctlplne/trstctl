// SPDX-License-Identifier: BUSL-1.1

package compromise

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFindingsDetectsCriticalStolenTokenSignal(t *testing.T) {
	findings, err := Findings(json.RawMessage(`{
		"signals":[{
			"principal":"payments-api",
			"credential_ref":"api-token:payments-ci",
			"credential_kind":"api_token",
			"provider":"github-actions",
			"detector":"honeytoken",
			"observed_at":"2026-06-03T03:15:00Z",
			"reason":"revoked token replayed from unfamiliar network",
			"confidence":"critical",
			"evidence_refs":["audit:api-token-use/evt-42","threatintel:leak/sha256"],
			"source_event_ref":"github-audit:evt-42",
			"ip":"203.0.113.44",
			"geo":"de",
			"user_agent":"curl/8.7",
			"action":"token_use",
			"owner":"platform"
		}]
	}`))
	if err != nil {
		t.Fatalf("Findings returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings count = %d, want 1", len(findings))
	}
	f := findings[0]
	if f.Ref != "api-token:payments-ci" || !strings.HasPrefix(f.Provenance, "credential_compromise:github-actions:honeytoken:") || f.Fingerprint == f.Provenance {
		t.Fatalf("unexpected finding identity: %+v", f)
	}
	if f.RiskScore != 100 {
		t.Fatalf("risk score = %d, want capped critical risk", f.RiskScore)
	}
	if f.Metadata["owasp_category"] != "NHI2" || f.Metadata["capability"] != "CAP-ITDR-02" {
		t.Fatalf("missing ITDR metadata: %+v", f.Metadata)
	}
	if f.Metadata["geo"] != "DE" {
		t.Fatalf("geo = %#v, want normalized country code", f.Metadata["geo"])
	}
	refs, ok := f.Metadata["evidence_refs"].([]string)
	if !ok || len(refs) != 2 {
		t.Fatalf("evidence_refs = %#v, want two refs", f.Metadata["evidence_refs"])
	}
}

func TestFindingsRejectsInlineSecretShape(t *testing.T) {
	_, err := Findings(json.RawMessage(`{
		"signals":[{
			"principal":"payments-api",
			"credential_ref":"api-token:payments-ci",
			"credential_kind":"api_token",
			"provider":"github-actions",
			"detector":"secret-scanner",
			"observed_at":"2026-06-03T03:15:00Z",
			"reason":"known leak",
			"confidence":"high",
			"evidence_refs":["scanner:evt-1"],
			"access_token":"raw-token-value"
		}]
	}`))
	if err == nil || !strings.Contains(err.Error(), "inline secret") {
		t.Fatalf("Findings error = %v, want inline secret rejection", err)
	}
}

func TestFindingsRequiresEvidenceReference(t *testing.T) {
	_, err := Findings(json.RawMessage(`{
		"signals":[{
			"principal":"payments-api",
			"credential_ref":"api-token:payments-ci",
			"credential_kind":"api_token",
			"provider":"github-actions",
			"detector":"idp-risk",
			"observed_at":"2026-06-03T03:15:00Z",
			"reason":"impossible travel",
			"confidence":"medium"
		}]
	}`))
	if err == nil || !strings.Contains(err.Error(), "evidence_refs") {
		t.Fatalf("Findings error = %v, want evidence reference rejection", err)
	}
}
