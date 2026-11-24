// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// OD-3: a native scan webhook may be GitHub's, GitLab's or Bitbucket's;
// any other provider is refused at startup.
func TestSecretScanWebhookProvidersOD3(t *testing.T) {
	hook := func(id, provider string) SecretScanWebhook {
		return SecretScanWebhook{ID: id, TenantID: "8d0c3a4e-6a51-4c43-9b7e-5f0f5b0f4a10", Provider: provider, SecretRef: "file:/run/secrets/" + id}
	}
	if errs := validateSecretScanWebhooks([]SecretScanWebhook{hook("gh", "github"), hook("gl", "gitlab"), hook("bb", "bitbucket")}); len(errs) != 0 {
		t.Fatalf("the three providers = %v", errs)
	}
	errs := validateSecretScanWebhooks([]SecretScanWebhook{hook("other", "other-host")})
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "github, gitlab or bitbucket") {
		t.Fatalf("an unknown provider = %v", errs)
	}
}

func TestCR048NativeHookCloneCredentialRequiresPinnedOrigin(t *testing.T) {
	hook := SecretScanWebhook{
		ID: "private", TenantID: "8d0c3a4e-6a51-4c43-9b7e-5f0f5b0f4a10", Provider: "github",
		SecretRef: "file:/run/secrets/hook", CloneCredentialRef: "file:/run/secrets/clone",
	}
	for _, origin := range []string{"", "http://git.example", "https://git.example/path", "https://user@git.example", "https://git.example?next=evil"} {
		hook.CloneOrigin = origin
		if errs := validateSecretScanWebhooks([]SecretScanWebhook{hook}); len(errs) == 0 {
			t.Errorf("accepted clone_origin %q for an operator clone credential", origin)
		}
	}
	hook.CloneOrigin = "https://git.example"
	if errs := validateSecretScanWebhooks([]SecretScanWebhook{hook}); len(errs) != 0 {
		t.Fatalf("canonical origin was refused: %v", errs)
	}
}

func TestCR411NativeHookPrivateCloneNeedsPinnedOriginAndCIDR(t *testing.T) {
	hook := SecretScanWebhook{
		ID: "private", TenantID: "8d0c3a4e-6a51-4c43-9b7e-5f0f5b0f4a10", Provider: "github",
		SecretRef: "file:/run/secrets/hook", CloneCredentialRef: "file:/run/secrets/clone",
		ClonePrivateEgressCIDRs: []string{"127.0.0.1/32"},
	}
	if errs := validateSecretScanWebhooks([]SecretScanWebhook{hook}); len(errs) == 0 {
		t.Fatal("private hook clone admitted without a pinned HTTPS origin")
	}
	hook.CloneOrigin = "https://git.example"
	if errs := validateSecretScanWebhooks([]SecretScanWebhook{hook}); len(errs) != 0 {
		t.Fatalf("exact private hook clone CIDR refused: %v", errs)
	}
	hook.ClonePrivateEgressCIDRs = []string{"0.0.0.0/0"}
	if errs := validateSecretScanWebhooks([]SecretScanWebhook{hook}); len(errs) == 0 {
		t.Fatal("private hook clone admitted a wildcard egress CIDR")
	}
	hook.ClonePrivateEgressCIDRs = []string{"0.0.0.0/1"}
	if errs := validateSecretScanWebhooks([]SecretScanWebhook{hook}); len(errs) == 0 {
		t.Fatal("private hook clone admitted a public-covering egress CIDR")
	}
}
