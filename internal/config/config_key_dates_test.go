// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// A168-L3: key_dates_since is an RFC 3339 time on cloud KMS sources and
// managed_keys authorities only, and every such authority in a round sets the
// same value or none — one side comparing dates alone would read every key it
// covers as disagreeing.
func TestReconcileKeyDatesSinceIsRoundWideA168L3(t *testing.T) {
	round := func(kms, managed string, extra ...ReconcileAuthority) *Config {
		c := Default()
		authorities := []ReconcileAuthority{
			{AuthorityID: "aws-kms", Source: &ReconcileAuthoritySource{Kind: "awskms", Region: "us-east-1", // #nosec G101 -- credential file paths only (CWE-798)
				AccessKeyIDFile: "/run/aws/id", SecretAccessKeyFile: "/run/aws/secret", KeyDatesSince: kms}},
			{AuthorityID: "managed-keys", Source: &ReconcileAuthoritySource{Kind: "managed_keys", Provider: "aws-kms", KeyDatesSince: managed}},
		}
		c.Reconcile.Schedules = []ReconcileSchedule{{TenantID: "t", Authorities: append(authorities, extra...)}}
		return c
	}
	const since = "2026-11-13T00:00:00Z"
	for name, c := range map[string]*Config{"both set": round(since, since), "neither set": round("", "")} {
		if err := c.Validate(); err != nil {
			t.Fatalf("%s: refused %v", name, err)
		}
	}
	vault := ReconcileAuthority{AuthorityID: "vault", Source: &ReconcileAuthoritySource{Kind: "vault", Address: "https://vault.internal",
		TokenFile: "/run/token", KVMounts: []string{"secret"}, KeyDatesSince: since}} // #nosec G101 -- a token file path, no value (CWE-798)
	for name, tc := range map[string]struct {
		cfg  *Config
		want string
	}{
		"only the cloud side":       {round(since, ""), "must set the same key_dates_since"},
		"only the inventory side":   {round("", since), "must set the same key_dates_since"},
		"two different moments":     {round(since, "2026-11-14T00:00:00Z"), "must set the same key_dates_since"},
		"not a time":                {round("yesterday", "yesterday"), "key_dates_since must be an RFC 3339 time"},
		"on a source with no dates": {round(since, since, vault), "key_dates_since belongs to awskms, gcpkms, azurekv and managed_keys"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := tc.cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v; want an error containing %q", err, tc.want)
			}
		})
	}
	src := &ReconcileAuthoritySource{KeyDatesSince: "2026-11-13T05:30:00+05:30"}
	if got, err := src.KeyDatesSinceTime(); err != nil || got.Format("2006-01-02T15:04:05Z07:00") != "2026-11-13T00:00:00Z" {
		t.Fatalf("KeyDatesSinceTime = %v %v, want UTC midnight", got, err)
	}
}
