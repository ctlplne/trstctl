// SPDX-License-Identifier: BUSL-1.1

package license

import (
	"testing"
	"time"
)

func TestAuditComplianceIsAnInheritedEnterpriseFeature(t *testing.T) {
	const feature Feature = "audit_compliance"
	if tier := FeatureTier(feature); tier != TierEnterprise {
		t.Fatalf("audit compliance tier = %s, want Enterprise", tier)
	}
	assertFeatureRow(t, Community().Info(), feature, TierEnterprise, false, ModeOff)
	priv, pub := testKeypair(t)
	expires := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	for _, tier := range []Tier{TierEnterprise, TierProvider} {
		manager := managerAt(t, testClaims(tier, expires), priv, pub, expires.Add(-time.Hour))
		assertFeatureRow(t, manager.Info(), feature, TierEnterprise, true, ModeEnabled)
	}
}
