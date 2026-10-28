// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// A210: the replacement preview reads a host's answer as ready only when the
// profile pins a recovery action the connector runs while deploying and the
// listener is not serving the contained leaf; a check that ran before the
// containment is stale.
func TestRecoveryVerdictNeedsAPinnedDeployActionAndNoContainedLeaf(t *testing.T) {
	contained := strings.Repeat("a", 64)
	stop := store.EndpointContainmentReceipt{Fingerprint: contained, EventSequence: 50, UpdatedAt: time.Unix(500, 0)}
	pinned := store.EndpointRecoveryCheck{Recovery: "pinned", RecoveryAction: "nginx", Listener: "stopped"}
	for _, tc := range []struct {
		name   string
		change func(*store.EndpointRecoveryCheck)
		want   string
		reason string
	}{
		{"pinned and stopped", func(*store.EndpointRecoveryCheck) {}, recoveryReady, ""},
		{"serving another leaf", func(c *store.EndpointRecoveryCheck) {
			c.Listener, c.ServingFingerprint = "serving", strings.Repeat("b", 64)
		}, recoveryReady, ""},
		{"no recovery action", func(c *store.EndpointRecoveryCheck) { c.Recovery, c.RecoveryAction = "no_recovery_action", "" }, recoveryNotReady, "pins no recovery action"},
		{"no binding", func(c *store.EndpointRecoveryCheck) { c.Recovery, c.Listener = "no_binding", "none" }, recoveryNotReady, "no containment binding"},
		{"action the deploy never runs", func(c *store.EndpointRecoveryCheck) { c.RecoveryAction = "start-nginx" }, recoveryNotReady, "not one the nginx connector runs"},
		{"serving the contained leaf", func(c *store.EndpointRecoveryCheck) { c.Listener, c.ServingFingerprint = "serving", contained }, recoveryNotReady, "serving the contained certificate"},
		{"serving a revoked leaf", func(c *store.EndpointRecoveryCheck) { c.Listener = "serving_revoked" }, recoveryNotReady, "serving the contained certificate"},
		{"listener unverified", func(c *store.EndpointRecoveryCheck) { c.Listener = "unverified" }, recoveryNotReady, "could not tell"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check := pinned
			tc.change(&check)
			got, reasons := recoveryVerdict(check, stop, []string{"nginx"}, "nginx")
			if got != tc.want || (tc.reason != "" && !strings.Contains(strings.Join(reasons, " "), tc.reason)) {
				t.Fatalf("verdict = %s %v, want %s naming %q", got, reasons, tc.want, tc.reason)
			}
		})
	}
	if !checkFollowsContainment(store.EndpointRecoveryCheck{RequestSequence: 51}, stop) ||
		checkFollowsContainment(store.EndpointRecoveryCheck{RequestSequence: 49}, stop) {
		t.Fatal("a check is ordered after a containment by event sequence")
	}
	legacy := store.EndpointContainmentReceipt{UpdatedAt: time.Unix(500, 0)}
	if !checkFollowsContainment(store.EndpointRecoveryCheck{RequestedAt: time.Unix(501, 0)}, legacy) ||
		checkFollowsContainment(store.EndpointRecoveryCheck{RequestedAt: time.Unix(499, 0)}, legacy) {
		t.Fatal("a receipt without an event sequence orders the check by time")
	}
	if err := recoveryNotReadyError(&endpointRecoveryReadiness{State: recoveryUnchecked, Reasons: []string{"no check"}}); err == nil ||
		!strings.Contains(err.Error(), "recovery is unchecked: no check") {
		t.Fatalf("an unchecked recovery authorized a replacement: %v", err)
	}
	if recoveryNotReadyError(nil) != nil || recoveryNotReadyError(&endpointRecoveryReadiness{State: recoveryReady}) != nil {
		t.Fatal("a ready or absent recovery refused a replacement")
	}
}
