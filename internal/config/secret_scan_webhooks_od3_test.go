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
