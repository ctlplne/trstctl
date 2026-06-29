package oauthgrant

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFindingsNormalizesOAuthGrantMetadata(t *testing.T) {
	findings, err := Findings(json.RawMessage(`{
		"grants":[
			{
				"provider":"okta",
				"app_id":"0oa-payments",
				"app_name":"Payments BI Export",
				"principal":"payments-bi-export",
				"resource":"google-workspace",
				"scopes":["drive.readonly","admin.directory.user.readonly","drive.readonly"],
				"consent_type":"admin",
				"third_party":true,
				"owner":"finance-platform",
				"redirect_uris":["https://example.invalid/callback","https://example.invalid/callback"]
			}
		]
	}`))
	if err != nil {
		t.Fatalf("Findings returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings count = %d, want 1", len(findings))
	}
	f := findings[0]
	if f.Ref != "payments-bi-export" || f.Provenance != "oauth_grant:okta:0oa-payments:google-workspace" {
		t.Fatalf("unexpected finding identity: %+v", f)
	}
	if f.Fingerprint != f.Provenance {
		t.Fatalf("fingerprint = %q, want provenance", f.Fingerprint)
	}
	if f.RiskScore < 80 {
		t.Fatalf("risk score = %d, want sensitive third-party admin grant score", f.RiskScore)
	}
	scopes, ok := f.Metadata["scopes"].([]string)
	if !ok || len(scopes) != 2 {
		t.Fatalf("scopes metadata = %#v, want deduplicated []string", f.Metadata["scopes"])
	}
	redirectURIs, ok := f.Metadata["redirect_uris"].([]string)
	if !ok || len(redirectURIs) != 1 {
		t.Fatalf("redirect_uris metadata = %#v, want deduplicated []string", f.Metadata["redirect_uris"])
	}
}

func TestFindingsRejectsMissingScopeDenominator(t *testing.T) {
	_, err := Findings(json.RawMessage(`{
		"grants":[{"provider":"okta","app_id":"0oa-payments","resource":"google-workspace"}]
	}`))
	if err == nil || !strings.Contains(err.Error(), "scope") {
		t.Fatalf("Findings error = %v, want missing scope rejection", err)
	}
}

func TestAbuseFindingsDetectsMaliciousOAuthGrant(t *testing.T) {
	findings, err := AbuseFindings(json.RawMessage(`{
		"grants":[
			{
				"provider":"entra-id",
				"app_id":"evil-consent-app",
				"app_name":"Mail Exporter",
				"principal":"legacy-mail-archive",
				"resource":"microsoft-graph",
				"scopes":["offline_access","Directory.ReadWrite.All","Mail.ReadWrite","*.default"],
				"consent_type":"admin",
				"third_party":true,
				"publisher":"Unverified Apps LLC",
				"publisher_verified":false,
				"tenant":"external-tenant",
				"observed_at":"2026-06-04T02:15:00Z",
				"redirect_uris":["http://evil.example/callback","https://*.evil.example/callback"],
				"tags":["shadow-it"],
				"threat_signals":["consent_phishing","admin_consent_from_unfamiliar_ip"],
				"evidence_refs":["entra:audit/consent-42","itdr:case/oauth-7"],
				"source_event_ref":"entra:audit/consent-42"
			},
			{
				"provider":"okta",
				"app_id":"0oa-invoice",
				"principal":"invoice-sync",
				"resource":"salesforce",
				"scopes":["api.read"],
				"consent_type":"user",
				"third_party":true,
				"owner":"revops",
				"publisher":"Trusted ISV"
			}
		]
	}`))
	if err != nil {
		t.Fatalf("AbuseFindings returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("abuse finding count = %d, want 1", len(findings))
	}
	f := findings[0]
	if f.Ref != "legacy-mail-archive" || !strings.HasPrefix(f.Provenance, "oauth_grant_abuse:entra-id:evil-consent-app:microsoft-graph:") {
		t.Fatalf("unexpected abuse finding identity: %+v", f)
	}
	if f.RiskScore < 90 {
		t.Fatalf("risk score = %d, want high-confidence abuse", f.RiskScore)
	}
	if f.Metadata["capability"] != "CAP-ITDR-03" {
		t.Fatalf("capability metadata = %#v, want CAP-ITDR-03", f.Metadata["capability"])
	}
	reasons, ok := f.Metadata["abuse_reasons"].([]string)
	if !ok {
		t.Fatalf("abuse_reasons metadata = %#v, want []string", f.Metadata["abuse_reasons"])
	}
	seen := map[string]bool{}
	for _, reason := range reasons {
		seen[reason] = true
	}
	for _, reason := range []string{"provider_threat_signal", "dangerous_wildcard_scope", "offline_access_high_privilege", "unverified_publisher_high_privilege", "suspicious_redirect_uri"} {
		if !seen[reason] {
			t.Fatalf("reason %q missing from abuse finding: %+v", reason, seen)
		}
	}
}

func TestAbuseFindingsDoesNotTreatOwnedHighRiskInventoryAsAbuse(t *testing.T) {
	findings, err := AbuseFindings(json.RawMessage(`{
		"grants":[
			{
				"provider":"okta",
				"app_id":"0oa-payments",
				"app_name":"Payments BI Export",
				"principal":"payments-bi-export",
				"resource":"google-workspace",
				"scopes":["drive.readonly","admin.directory.user.readonly"],
				"consent_type":"admin",
				"third_party":true,
				"owner":"finance-platform",
				"publisher":"Trusted ISV"
			}
		]
	}`))
	if err != nil {
		t.Fatalf("AbuseFindings returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("abuse finding count = %d, want ordinary inventory to stay CAP-OAUTH-01 only: %+v", len(findings), findings)
	}
}
