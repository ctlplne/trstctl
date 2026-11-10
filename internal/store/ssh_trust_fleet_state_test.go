// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"testing"
	"time"
)

// A226-L3: a rollout's headline keeps a failure in front. A host that failed
// or refused needs an operator whether or not other hosts are still queued
// past the window; execution_window_expired used to override it, so the list
// read as a timing problem while a host had failed. The expiry stays visible
// on its own (window_expired).
func TestSSHTrustFleetRolloutHeadlineKeepsAFailureInFrontA226L3(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Minute), now.Add(time.Hour)
	hosts := func(states ...string) []SSHTrustFleetHost {
		out := make([]SSHTrustFleetHost, len(states))
		for i, s := range states {
			out[i] = SSHTrustFleetHost{State: s}
		}
		return out
	}
	for _, tc := range []struct {
		name          string
		hosts         []SSHTrustFleetHost
		expires       time.Time
		state         string
		windowExpired bool
	}{
		{"failed and queued past the window", hosts("failed", "queued"), past, "attention_required", true},
		{"refused and queued past the window", hosts("refused", "queued", "verified"), past, "attention_required", true},
		{"queued past the window", hosts("verified", "queued"), past, "execution_window_expired", true},
		{"failed inside the window", hosts("failed", "queued"), future, "attention_required", false},
		{"all verified", hosts("verified", "skipped", "verified"), past, "verified", false},
		{"queued inside the window", hosts("queued"), future, "pending", false},
	} {
		state, expired := sshTrustFleetRolloutState(tc.hosts, tc.expires, now)
		if state != tc.state || expired != tc.windowExpired {
			t.Errorf("%s: %s/%v, want %s/%v", tc.name, state, expired, tc.state, tc.windowExpired)
		}
	}
}
