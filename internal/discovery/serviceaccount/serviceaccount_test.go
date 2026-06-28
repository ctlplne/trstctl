package serviceaccount

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFindingsRequireADAndCloudServiceAccounts(t *testing.T) {
	enabled := true
	raw, err := json.Marshal(Config{Accounts: []Account{
		{
			Surface: "active_directory", Provider: "ad", Directory: "corp.example",
			AccountID: "S-1-5-21-1000", Principal: "svc-payments@corp.example",
			Owner: "identity", Enabled: &enabled, Groups: []string{"CN=Payments,OU=Service Accounts,DC=corp,DC=example"},
			CredentialRefs: []string{"ad:corp.example:svc-payments"},
		},
		{
			Surface: "cloud", Provider: "aws-iam", Directory: "111111111111",
			AccountID: "role/payments-prod", Principal: "arn:aws:iam::111111111111:role/payments-prod",
			Owner: "platform", Privileged: true, Roles: []string{"AdministratorAccess"},
			CredentialRefs: []string{"aws:iam:role/payments-prod"},
		},
	}})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	findings, err := Findings(raw)
	if err != nil {
		t.Fatalf("service-account findings rejected valid AD+cloud config: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}
	seen := map[string]bool{}
	for _, f := range findings {
		if f.KindlessZeroValue() {
			t.Fatalf("finding has zero material: %+v", f)
		}
		if !strings.HasPrefix(f.Provenance, SourceKind+":") || f.Fingerprint != f.Provenance {
			t.Fatalf("bad provenance/fingerprint: %+v", f)
		}
		if f.Metadata["capability"] != "CAP-NHI-03" {
			t.Fatalf("capability metadata = %v", f.Metadata["capability"])
		}
		surface, _ := f.Metadata["surface"].(string)
		seen[surface] = true
	}
	for _, surface := range Surfaces() {
		if !seen[surface] {
			t.Fatalf("surface %q missing from findings: %+v", surface, seen)
		}
	}
}

func TestFindingsRejectSingleSidedServiceAccountInventory(t *testing.T) {
	raw := json.RawMessage(`{"accounts":[{"surface":"ad","provider":"ad","account_id":"svc-1","principal":"svc-1"}]}`)
	if _, err := Findings(raw); err == nil || !strings.Contains(err.Error(), "cloud account") {
		t.Fatalf("single-sided AD-only config err = %v, want cloud account requirement", err)
	}

	raw = json.RawMessage(`{"accounts":[{"surface":"cloud","provider":"gcp-iam","account_id":"svc@example.iam.gserviceaccount.com","principal":"svc@example.iam.gserviceaccount.com"}]}`)
	if _, err := Findings(raw); err == nil || !strings.Contains(err.Error(), "ad account") {
		t.Fatalf("single-sided cloud-only config err = %v, want ad account requirement", err)
	}
}

func TestFindingsRejectMalformedServiceAccounts(t *testing.T) {
	raw := json.RawMessage(`{"accounts":[
		{"surface":"ad","provider":"ad","account_id":"svc-1","principal":"svc-1"},
		{"surface":"cloud","provider":"aws-iam","account_id":"role/payments-prod"}
	]}`)
	if _, err := Findings(raw); err == nil || !strings.Contains(err.Error(), "provider, account_id, and principal") {
		t.Fatalf("malformed account err = %v, want required fields error", err)
	}

	raw = json.RawMessage(`{"accounts":[
		{"surface":"saas","provider":"github","account_id":"app-1","principal":"app-1"},
		{"surface":"cloud","provider":"aws-iam","account_id":"role/payments-prod","principal":"arn:aws:iam::111111111111:role/payments-prod"}
	]}`)
	if _, err := Findings(raw); err == nil || !strings.Contains(err.Error(), "must be one of ad, cloud") {
		t.Fatalf("unsupported surface err = %v, want surface denominator error", err)
	}
}

func (f Finding) KindlessZeroValue() bool {
	return f.Ref == "" || f.Provenance == "" || f.Fingerprint == "" || f.RiskScore <= 0 || len(f.Metadata) == 0
}
