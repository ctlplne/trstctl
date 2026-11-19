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
	for _, ref := range []string{"secret://fixture/team/token?version=1", "file:/fixture/clone-token"} {
		req.CredentialRef = ref
		cfg, err := secretRepoScanConfig("github", req)
		if err != nil || cfg.CredentialRef != ref {
			t.Errorf("repository scan did not retain the supported reference form: %v", err)
		}
	}
}
