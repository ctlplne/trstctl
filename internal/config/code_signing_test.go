// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
	"time"
)

func TestCodeSigningConfigIsTenantBoundAndFailClosed(t *testing.T) {
	valid := CodeSigning{
		Enabled: true,
		Keys: []CodeSigningKey{{
			TenantID: "00000000-0000-4000-8000-000000000001", ID: "release",
			Algorithm: "ecdsa-p256", CreateIfMissing: true,
		}},
		GitHubOIDCTenants: []CodeSigningGitHubOIDC{{
			TenantID: "00000000-0000-4000-8000-000000000001", Audience: "sigstore",
			JWKSJSON: `{"keys":[]}`, AllowedOwners: []string{"acme"},
		}},
		Rekor: CodeSigningRekor{Endpoint: "https://rekor.sigstore.dev/api/v1/log/entries", Timeout: "8s", LogPublicKeyFile: "rekor.pub"},
	}
	if errs := validateCodeSigning(valid); len(errs) != 0 {
		t.Fatalf("valid code-signing config: %v", errs)
	}
	if got, err := valid.Rekor.TimeoutDuration(); err != nil || got != 8*time.Second {
		t.Fatalf("Rekor timeout = (%v, %v), want (8s, nil)", got, err)
	}

	bad := CodeSigning{
		Enabled: true,
		Keys: []CodeSigningKey{
			{TenantID: "tenant-a", ID: "release", Handle: "shared", Algorithm: "ed25519"},
			{TenantID: "tenant-a", ID: "release", Handle: "shared"},
		},
		GitHubOIDCTenants: []CodeSigningGitHubOIDC{
			{TenantID: "tenant-a", JWKSFile: "a", JWKSJSON: "b"},
			{TenantID: "tenant-a", Audience: "sigstore", JWKSJSON: "b"},
		},
		Rekor: CodeSigningRekor{Endpoint: "http://10.0.0.8/entries", AllowInsecureHTTP: true, Timeout: "bad", AllowPrivateCIDRs: []string{"bad"}},
	}
	joined := errorsText(validateCodeSigning(bad))
	for _, want := range []string{"duplicates tenant/key", "shared by multiple", "invalid for SHA-256", "requires exactly one", "duplicates tenant", "audience", "timeout", "allow_private_cidrs", "loopback"} {
		if !strings.Contains(joined, want) {
			t.Errorf("validation errors %q do not contain %q", joined, want)
		}
	}
}

func TestCodeSigningEnvOverlaysOnlyUnambiguousScalars(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_CODE_SIGNING_ENABLED":                   "true",
		"TRSTCTL_CODE_SIGNING_EPHEMERAL_ALGORITHM":       "ecdsa-p256",
		"TRSTCTL_CODE_SIGNING_REKOR_ENDPOINT":            "http://127.0.0.1:3000/api/v1/log/entries",
		"TRSTCTL_CODE_SIGNING_REKOR_LOG_PUBLIC_KEY_FILE": "rekor.pub",
		"TRSTCTL_CODE_SIGNING_REKOR_ALLOW_PRIVATE_CIDRS": "127.0.0.0/8",
		"TRSTCTL_CODE_SIGNING_REKOR_ALLOW_INSECURE_HTTP": "true",
	}
	var cfg CodeSigning
	applyCodeSigningEnv(func(key string) string { return env[key] }, &cfg)
	if !cfg.Enabled || cfg.EphemeralAlgorithm != "ecdsa-p256" || cfg.Rekor.Endpoint == "" || cfg.Rekor.LogPublicKeyFile != "rekor.pub" || len(cfg.Rekor.AllowPrivateCIDRs) != 1 || !cfg.Rekor.AllowInsecureHTTP {
		t.Fatalf("code-signing env overlay = %+v", cfg)
	}
}
