// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"testing"

	"trstctl.com/trstctl/internal/secretscan"
)

func TestProductSecretScanSourceNamesBindEveryIdentityComponent(t *testing.T) {
	const tenantID = "11111111-1111-1111-1111-111111111111"
	t.Run("repository and ref delimiter collision", func(t *testing.T) {
		left := secretscan.RepositoryScanConfig{Provider: "github", Repository: "a:b", Ref: "c"}
		right := secretscan.RepositoryScanConfig{Provider: "github", Repository: "a", Ref: "b:c"}
		leftID, rightID := secretRepoSourceID(tenantID, left), secretRepoSourceID(tenantID, right)
		if leftID == rightID {
			t.Fatal("test inputs do not have distinct source IDs")
		}
		if leftName, rightName := secretRepoSourceName(left, leftID), secretRepoSourceName(right, rightID); leftName == rightName {
			t.Fatalf("distinct repository source IDs share name %q: %s versus %s", leftName, leftID, rightID)
		}
	})
	t.Run("third-party artifact path omitted", func(t *testing.T) {
		left := secretscan.ThirdPartyScanConfig{Provider: "cicd_log", Source: "qa", Event: "push", ArtifactPath: "/qa/first.json"}
		right := secretscan.ThirdPartyScanConfig{Provider: "cicd_log", Source: "qa", Event: "push", ArtifactPath: "/qa/second.json"}
		leftID, rightID := thirdPartySecretScanSourceID(tenantID, left), thirdPartySecretScanSourceID(tenantID, right)
		if leftID == rightID {
			t.Fatal("test inputs do not have distinct source IDs")
		}
		if leftName, rightName := thirdPartySecretScanSourceName(left, leftID), thirdPartySecretScanSourceName(right, rightID); leftName == rightName {
			t.Fatalf("distinct third-party source IDs share name %q: %s versus %s", leftName, leftID, rightID)
		}
	})
}
