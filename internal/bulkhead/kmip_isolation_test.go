// SPDX-License-Identifier: BUSL-1.1

package bulkhead

import "testing"

// TestKMIPHasItsOwnPool is the regression guard for the cross-protocol
// starvation defect. KMIP is connection-oriented: a worker is held for an entire
// client connection, TLS handshake included, not for one request. It drew from
// the SHARED protocols pool, which has 8 workers, so a handful of TCP connects
// that never send a frame occupied every protocol worker until their 30s
// deadline — and ACME, EST, SCEP, CMP, SSH and SPIFFE, which draw from that same
// pool, stopped being served.
//
// AN-7 is explicit that one subsystem must never starve another, so the fix is a
// separate lane rather than a bigger shared one. This test pins the separation.
func TestKMIPHasItsOwnPool(t *testing.T) {
	set := Default()

	kmip := set.Pool(SubsystemKMIP)
	if kmip == nil {
		t.Fatal("no KMIP pool: KMIP would fall back to the shared protocols pool and can starve every other protocol")
	}
	protocols := set.Pool(SubsystemProtocols)
	if protocols == nil {
		t.Fatal("no protocols pool")
	}
	if kmip == protocols {
		t.Fatal("KMIP and the issuance protocols share a pool; a connection-scoped subsystem can starve request-scoped ones")
	}

	// And the isolation must hold for the API lane too — an exhausted KMIP lane
	// must not be able to take the control plane's own workers with it.
	if api := set.Pool(SubsystemAPI); api != nil && kmip == api {
		t.Fatal("KMIP shares the API pool")
	}
}

// TestDefaultPoolsAreDistinctPerSubsystem states the general property AN-7
// requires, so a future subsystem cannot quietly be added onto someone else's
// lane.
func TestDefaultPoolsAreDistinctPerSubsystem(t *testing.T) {
	set := Default()
	seen := map[*Pool]string{}
	for _, cfg := range DefaultConfigs() {
		p := set.Pool(cfg.Name)
		if p == nil {
			t.Errorf("subsystem %q has no pool", cfg.Name)
			continue
		}
		if other, dup := seen[p]; dup {
			t.Errorf("subsystems %q and %q share one pool; either can starve the other", cfg.Name, other)
		}
		seen[p] = cfg.Name
	}
}
