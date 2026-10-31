// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// A168: an awskms source names an account's region and read-only credential
// files; a managed_keys authority names the provider whose managed keys it
// asserts. Their fields are refused on any other kind of source, and the other
// kinds' fields on theirs.
func TestReconcileCloudKMSSourcesValidate(t *testing.T) {
	valid := func(sources ...*ReconcileAuthoritySource) *Config {
		c := Default()
		authorities := []ReconcileAuthority{}
		for i, src := range sources {
			authorities = append(authorities, ReconcileAuthority{AuthorityID: []string{"aws-kms-prod", "managed-keys-aws", "vault"}[i], Source: src})
		}
		c.Reconcile.Schedules = []ReconcileSchedule{{TenantID: "t", Authorities: authorities}}
		return c
	}
	kms := func() *ReconcileAuthoritySource {
		return &ReconcileAuthoritySource{Kind: "awskms", Region: "us-east-1", AccessKeyIDFile: "/run/aws/access", // #nosec G101 -- credential file paths only, no credential value (CWE-798)
			SecretAccessKeyFile: "/run/aws/secret", SessionTokenFile: "/run/aws/session", MaxObjects: 5000}
	}
	managed := func() *ReconcileAuthoritySource {
		return &ReconcileAuthoritySource{Kind: "managed_keys", Provider: "aws-kms"}
	}
	if err := valid(kms(), managed()).Validate(); err != nil {
		t.Fatalf("a valid awskms + managed_keys pair was refused: %v", err)
	}
	for name, tc := range map[string]struct {
		mutate func(kms, managed *ReconcileAuthoritySource)
		want   string
	}{
		"no region":           {func(k, _ *ReconcileAuthoritySource) { k.Region = "" }, "region is required"},
		"no secret file":      {func(k, _ *ReconcileAuthoritySource) { k.SecretAccessKeyFile = "" }, "secret_access_key_file is required"},
		"plain http":          {func(k, _ *ReconcileAuthoritySource) { k.Address = "http://kms.internal" }, "https URL"},
		"vault fields on kms": {func(k, _ *ReconcileAuthoritySource) { k.TokenFile = "/run/token" }, "awskms source takes"},
		"provider on kms":     {func(k, _ *ReconcileAuthoritySource) { k.Provider = "aws-kms" }, "provider belongs to a managed_keys"},
		"unknown provider":    {func(_, m *ReconcileAuthoritySource) { m.Provider = "gcp" }, "provider must be aws-kms"},
		"address on managed":  {func(_, m *ReconcileAuthoritySource) { m.Address = "https://kms.internal" }, "only provider belongs"},
		"region on managed":   {func(_, m *ReconcileAuthoritySource) { m.Region = "us-east-1" }, "belong to an awskms source"},
	} {
		t.Run(name, func(t *testing.T) {
			k, m := kms(), managed()
			tc.mutate(k, m)
			err := valid(k, m).Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v; want an error containing %q", err, tc.want)
			}
		})
	}
	vault := &ReconcileAuthoritySource{Kind: "vault", Address: "https://vault.internal", TokenFile: "/run/token", KVMounts: []string{"secret"}, Region: "us-east-1"}
	if err := valid(kms(), managed(), vault).Validate(); err == nil || !strings.Contains(err.Error(), "belong to an awskms source, not a vault one") {
		t.Fatalf("region on a vault source = %v; want it refused", err)
	}
}
