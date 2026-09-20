// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"errors"
	"testing"
	"time"
)

func TestStaleProbeCleanupCannotReleaseNewerAuthorityProbe(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	m := Message{TenantID: "tenant-a", Destination: "external-ca.issue", EffectLane: "external-ca.issue:authority:a"}
	o := NewOutbox(nil, WithCircuitBreaker(1, time.Minute))
	o.recordCircuitFailure(m, errors.New("first failure"), now)
	now = now.Add(2 * time.Minute)
	scope := DestinationScope{IncludePrefixes: []string{"external-ca.issue"}}
	_, old := o.reserveHalfOpenProbes(now, scope)
	if len(old) != 1 {
		t.Fatal("first probe was not reserved")
	}
	o.recordCircuitSuccess(m, now)
	o.recordCircuitFailure(m, errors.New("later failure"), now)
	now = now.Add(2 * time.Minute)
	_, current := o.reserveHalfOpenProbes(now, scope)
	if len(current) != 1 {
		t.Fatal("later probe was not reserved")
	}
	o.releaseUnclaimedHalfOpenProbes(old, circuitKey{}, now)
	blocked, reserved := o.reserveHalfOpenProbes(now, scope)
	if len(blocked) != 1 || len(reserved) != 0 {
		t.Fatal("stale cleanup allowed a competing probe against the same authority")
	}
	o.releaseUnclaimedHalfOpenProbes(current, circuitKey{}, now)
	blocked, reserved = o.reserveHalfOpenProbes(now, scope)
	if len(blocked) != 0 || len(reserved) != 1 {
		t.Fatal("current owner could not release its probe")
	}
}
