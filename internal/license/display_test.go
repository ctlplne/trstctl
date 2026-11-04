// SPDX-License-Identifier: BUSL-1.1

package license

import "testing"

// A253: the edition ledger names every licensed feature and right from these
// tables; a new feature or right without a display name would print its key.
func TestEveryFeatureAndRightHasADisplayName(t *testing.T) {
	for _, f := range AllFeatures() {
		if _, ok := featureDisplay[f]; !ok {
			t.Errorf("feature %s has no display name", f)
		}
	}
	for _, tier := range Tiers() {
		if TierDisplay(tier) == string(tier) {
			t.Errorf("tier %s has no display name", tier)
		}
		for _, r := range TierRights(tier) {
			if _, ok := rightDisplay[r]; !ok {
				t.Errorf("right %s has no display name", r)
			}
		}
	}
	if len(featureDisplay) != len(AllFeatures()) {
		t.Errorf("display names for %d features, table has %d", len(featureDisplay), len(AllFeatures()))
	}
}
