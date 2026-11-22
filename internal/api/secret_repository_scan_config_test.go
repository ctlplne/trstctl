// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"strings"
	"testing"
)

func TestRepositoryScanChecksStoredCloneReferenceBeforeQueueing(t *testing.T) {
	req := secretRepoScanWebhookRequest{
		Repository: "fixture/team", CloneURL: "https://fixture.example.test/team.git",
		Ref: "refs/heads/main", CredentialRef: "secret://fixture/team/%74oken",
	}
	if _, err := secretRepoScanConfig("github", req); err == nil || !strings.Contains(err.Error(), "canonical secret://") {
		t.Errorf("repository scan accepted a noncanonical stored reference: %v", err)
	}
	req.CredentialRef = "secret://fixture/team/token?version=1"
	cfg, err := secretRepoScanConfig("github", req)
	if err != nil || cfg.CredentialRef != req.CredentialRef {
		t.Errorf("repository scan did not retain the supported secret reference: %v", err)
	}
	req.CredentialRef = "file:/fixture/clone-token"
	if _, err := secretRepoScanConfig("github", req); err == nil {
		t.Error("tenant-authored repository scan accepted a control-plane file reference")
	}
	req.CredentialRef = "secret://fixture/team/token"
	for _, target := range []string{"http://fixture.example.test/team.git", "https://fixture.example.test/team.git?redirect=1", "https://fixture.example.test/team.git#fragment"} {
		req.CloneURL = target
		if _, err := secretRepoScanConfig("github", req); err == nil {
			t.Errorf("credential-bearing clone accepted unsafe URL %q", target)
		}
	}
}
