// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"testing"

	"trstctl.com/trstctl/internal/secretsync"
)

func TestSecretSyncCatalogUsesConfiguredProviderNotTargetName(t *testing.T) {
	static := secretsync.NewConfiguredTarget("ci", "aws-secrets-manager", false, nil)
	federated := secretsync.NewConfiguredTarget("qa-federated", "aws-secrets-manager", true, nil)
	catalog := buildSecretSyncTargetCatalog("2026-10-12T00:00:00Z", map[string]*secretsync.Target{
		"ci": static, "qa-federated": federated,
	})
	byID := map[string]secretSyncTargetResponse{}
	for _, row := range catalog.Targets {
		if _, exists := byID[row.ID]; exists {
			t.Fatalf("duplicate target %q", row.ID)
		}
		byID[row.ID] = row
	}
	if row := byID["ci"]; row.Platform != "aws" || !row.Configured || row.Name != "AWS Secrets Manager (ci)" {
		t.Fatalf("configured AWS target mislabeled by its ci ID: %+v", row)
	}
	if hasCapability(byID["ci"].Capabilities, "workload-identity") {
		t.Fatal("static AWS target advertised workload identity")
	}
	if row := byID["qa-federated"]; row.Platform != "aws" || !row.Configured || !hasCapability(row.Capabilities, "workload-identity") {
		t.Fatalf("federated AWS target not selectable: %+v", row)
	}
	if row := byID["aws-secrets-manager"]; row.Configured || row.Platform != "aws" {
		t.Fatalf("template row confused with configured target: %+v", row)
	}
}

func TestSecretSyncWorkloadIdentityTargetRequiresExactConfiguredOptIn(t *testing.T) {
	cases := []struct {
		name, provider, kind string
		enabled              bool
		want                 bool
	}{
		{"matching AWS", "aws", "aws-secrets-manager", true, true},
		{"static AWS", "aws", "aws-secrets-manager", false, false},
		{"misnamed AWS", "aws", "generic-ci-json", true, false},
		{"matching GCP", "gcp", "gcp-secret-manager", true, true},
		{"matching Azure", "azure", "azure-key-vault", true, true},
		{"wrong cloud", "azure", "aws-secrets-manager", true, false},
		{"unknown cloud", "unknown", "aws-secrets-manager", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := secretsync.NewConfiguredTarget("custom-id", tc.kind, tc.enabled, nil)
			if got := secretSyncWorkloadIdentityTargetMatches(target, tc.provider); got != tc.want {
				t.Fatalf("target provider=%q kind=%q enabled=%t: got %t, want %t", tc.provider, tc.kind, tc.enabled, got, tc.want)
			}
		})
	}
	if secretSyncWorkloadIdentityTargetMatches(nil, "aws") {
		t.Fatal("missing target accepted")
	}
}

func hasCapability(capabilities []string, want string) bool {
	for _, capability := range capabilities {
		if capability == want {
			return true
		}
	}
	return false
}
