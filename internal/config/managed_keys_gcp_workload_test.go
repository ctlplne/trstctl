// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

const a169l1Audience = "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/trstctl/providers/k8s"

// A169-L1: GCP managed-key custody takes exactly one credential, the static
// bearer token (or its file) or a workload identity, and the workload identity
// is set from config or its environment mirrors.
func TestManagedKeysGCPWorkloadIdentityValidatesA169L1(t *testing.T) {
	gcp := func(mutate func(*ManagedKeysGCPKMS)) ManagedKeysGCPKMS {
		g := ManagedKeysGCPKMS{Parent: "projects/p/locations/l/keyRings/r", WorkloadIdentity: &ManagedKeysGCPWorkloadIdentity{
			Audience: a169l1Audience, SubjectTokenFile: "/var/run/secrets/gcp/tokens/gcp-identity-token", // #nosec G101 -- a token path, no credential value (CWE-798)
			ServiceAccount: "kms-signer@acme.iam.gserviceaccount.com"}}
		mutate(&g)
		return g
	}
	if errs := validateManagedKeysGCPCredential(gcp(func(*ManagedKeysGCPKMS) {})); len(errs) != 0 {
		t.Fatalf("a valid workload identity was refused: %v", errs)
	}
	for name, tc := range map[string]struct {
		mutate func(*ManagedKeysGCPKMS)
		want   string
	}{
		"both credentials":               {func(g *ManagedKeysGCPKMS) { g.BearerTokenFile = "/run/token" }, "set one, not both"},
		"neither":                        {func(g *ManagedKeysGCPKMS) { g.WorkloadIdentity = nil }, "workload_identity is required"},
		"an audience that is no pool":    {func(g *ManagedKeysGCPKMS) { g.WorkloadIdentity.Audience = "https://kms.example" }, "audience must be the workload identity pool provider"},
		"no token file":                  {func(g *ManagedKeysGCPKMS) { g.WorkloadIdentity.SubjectTokenFile = "" }, "subject_token_file is required"},
		"a service account not an email": {func(g *ManagedKeysGCPKMS) { g.WorkloadIdentity.ServiceAccount = "kms-signer" }, "service_account must be"},
		"impersonation without an sa": {func(g *ManagedKeysGCPKMS) {
			g.WorkloadIdentity.ServiceAccount, g.WorkloadIdentity.ImpersonationEndpoint = "", "https://iam.example/x"
		}, "impersonation_endpoint needs a service_account"},
		"plain http sts": {func(g *ManagedKeysGCPKMS) { g.WorkloadIdentity.STSEndpoint = "http://sts.example/v1/token" }, "sts_endpoint"},
	} {
		t.Run(name, func(t *testing.T) {
			errs := validateManagedKeysGCPCredential(gcp(tc.mutate))
			if len(errs) == 0 || !strings.Contains(errs[0].Error(), tc.want) {
				t.Fatalf("errors = %v; want one containing %q", errs, tc.want)
			}
		})
	}
	env := map[string]string{ // #nosec G101 -- a pool audience, a service account and a token path, no credential value (CWE-798)
		"TRSTCTL_MANAGED_KEYS_GCP_WORKLOAD_AUDIENCE":           a169l1Audience,
		"TRSTCTL_MANAGED_KEYS_GCP_WORKLOAD_SUBJECT_TOKEN_FILE": "/var/run/secrets/gcp/tokens/gcp-identity-token",
		"TRSTCTL_MANAGED_KEYS_GCP_WORKLOAD_SERVICE_ACCOUNT":    "kms-signer@acme.iam.gserviceaccount.com",
	}
	c := Default()
	c.applyEnv(func(key string) string { return env[key] })
	if got := c.ManagedKeys.GCP.WorkloadIdentity; got == nil || got.Audience != a169l1Audience ||
		got.SubjectTokenFile != env["TRSTCTL_MANAGED_KEYS_GCP_WORKLOAD_SUBJECT_TOKEN_FILE"] || got.ServiceAccount != env["TRSTCTL_MANAGED_KEYS_GCP_WORKLOAD_SERVICE_ACCOUNT"] {
		t.Fatalf("workload identity from the environment = %+v", got)
	}
}
