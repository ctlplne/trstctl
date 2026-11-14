// SPDX-License-Identifier: BUSL-1.1

package config

import "testing"

// P15-L8: the reply intake's per-source limits are 0 (the default) or within
// their bounds: at most 16 sessions at once and 600 replies a minute.
func TestACMEEmailIntakeLimitsSettingsP15L8(t *testing.T) {
	base := ACMEEmail{From: "acme@ca.example.test", Domains: []string{"example.test"}, Profile: "smime", RelayAddr: "relay.example.test:25"}
	for _, limits := range [][2]int{{0, 0}, {1, 1}, {16, 600}} {
		good := base
		good.IntakeSessionsPerSource, good.IntakeRepliesPerMinute = limits[0], limits[1]
		if errs := validateACMEEmail(good); len(errs) != 0 {
			t.Fatalf("limits %v = %v", limits, errs)
		}
	}
	for _, limits := range [][2]int{{-1, 0}, {17, 0}, {0, -1}, {0, 601}} {
		bad := base
		bad.IntakeSessionsPerSource, bad.IntakeRepliesPerMinute = limits[0], limits[1]
		if errs := validateACMEEmail(bad); len(errs) != 1 {
			t.Fatalf("limits %v gave %d errors, want 1: %v", limits, len(errs), errs)
		}
	}
}
