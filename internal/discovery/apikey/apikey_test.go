package apikey

import (
	"encoding/json"
	"testing"
)

func TestFindingsNormalizeAPIKeyTokenAndPATObservations(t *testing.T) {
	age := 120
	raw, err := json.Marshal(Config{Observations: []Observation{
		{
			Surface: "cloud", System: "aws-iam", ExternalID: "access-key/AKIAEXAMPLE",
			Principal: "arn:aws:iam::111111111111:user/payments", CredentialKind: "access-key",
			CredentialRef: "aws:access-key/AKIAEXAMPLE", MaskedFingerprint: "sha256:aws-key-ref",
			Scopes: []string{"iam:*"}, EvidenceRefs: []string{"aws:credential-report"}, Privileged: true,
			RotationAgeDays: &age,
		},
		{
			Surface: "saas", System: "github", ExternalID: "user/payments/pat",
			Principal: "payments-ci", CredentialKind: "pat", CredentialRef: "github:user/payments/pat",
			MaskedFingerprint: "sha256:pat-ref", EvidenceRefs: []string{"github:audit/pat"},
		},
		{
			Surface: "ci", System: "github-actions", ExternalID: "repo/payments/env/prod",
			Principal: "payments-release", CredentialKind: "refresh_token", CredentialRef: "github-actions:repo/payments/env/prod/token",
			MaskedFingerprint: "sha256:ci-token-ref", ExpiresAt: "2026-07-01T00:00:00Z", EvidenceRefs: []string{"github-actions:secret-scan"},
		},
	}})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	findings, err := Findings(raw)
	if err != nil {
		t.Fatalf("Findings returned error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("findings = %d, want 3", len(findings))
	}
	kinds := map[string]bool{}
	for _, f := range findings {
		if f.Ref == "" || f.Fingerprint == "" || f.Provenance == "" {
			t.Fatalf("finding missing identity fields: %+v", f)
		}
		if f.Metadata["capability"] != "CAP-NHI-04" {
			t.Fatalf("missing CAP-NHI-04 metadata: %+v", f.Metadata)
		}
		kinds[f.Kind] = true
	}
	for _, want := range []string{"api_key", "personal_access_token", "api_token"} {
		if !kinds[want] {
			t.Fatalf("missing normalized kind %s: %+v", want, kinds)
		}
	}
	if findings[0].RiskScore < 90 {
		t.Fatalf("privileged stale admin API key risk = %d, want high", findings[0].RiskScore)
	}
}

func TestValidateConfigRejectsInlineSecretMaterial(t *testing.T) {
	err := ValidateConfig(json.RawMessage(`{
		"observations":[{
			"surface":"saas",
			"system":"github",
			"external_id":"user/payments/pat",
			"principal":"payments-ci",
			"credential_kind":"personal_access_token",
			"credential_ref":"github:user/payments/pat",
			"token_value":"ghp_raw_secret"
		}]
	}`))
	if err == nil {
		t.Fatal("inline token material must be rejected")
	}
}

func TestValidateConfigAllowsLegacyManualFindings(t *testing.T) {
	if err := ValidateConfig(json.RawMessage(`{"findings":[{"kind":"api_key","ref":"legacy:key"}]}`)); err != nil {
		t.Fatalf("legacy manual api_key findings config was rejected: %v", err)
	}
}
