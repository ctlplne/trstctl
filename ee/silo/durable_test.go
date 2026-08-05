// SPDX-License-Identifier: LicenseRef-trstctl-EE

package silo

import (
	"context"
	"os"
	"strings"
	"testing"
)

// L4: silo placement must survive a restart, and the fallback must be VISIBLE.
//
// The in-memory registry reverted every tenant to the shared isolation default
// on restart, silently. A customer who bought hard isolation had it until the
// first deploy, and nothing running would have said otherwise — for a
// sovereignty feature that is the whole product failing quietly.
func TestTheDurableRegistryIsReachableAndTheFallbackIsVisible(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile("../../cmd/trstctl/ee_attach.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "eesilo.InstallDurable(") {
		t.Fatal("ee_attach.go does not call InstallDurable.\n\n" +
			"A durable registry nothing installs leaves every tenant reverting to the shared " +
			"default on the next deploy, with the fix sitting unused in the tree.")
	}
	if strings.Contains(string(src), "eesilo.InstallInMemory()") {
		t.Fatal("ee_attach.go still installs the in-memory registry; placement is still lost on " +
			"restart")
	}
	if InstallDurable(nil).Durable {
		t.Fatal("an installation with no database claimed to be durable.\n\n" +
			"A sovereignty claim that cannot survive a deploy must not report that it can.")
	}
}

// A nil store yields an EMPTY routing table, never an error and never a guess.
// Empty reads as "everything on the shared default", which is the safe reading:
// it cannot invent an isolation guarantee nothing is backing.
func TestAnUnbackedRegistrySnapshotsEmptyRatherThanGuessing(t *testing.T) {
	t.Parallel()
	got, err := (&PGRegistry{}).Snapshot(context.Background())
	if err != nil {
		t.Fatalf("an unbacked registry errored instead of reporting nothing: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("snapshot = %v, want empty. Any non-empty answer here is an isolation "+
			"guarantee invented from no data", got)
	}
}

// An unpinned tenant must not read as compliant with whatever zone was asked
// about. An absent pin is the absence of a guarantee, not a permissive one.
func TestAnUnpinnedTenantHasNoResidencyGuarantee(t *testing.T) {
	t.Parallel()
	zone, err := (&PGRegistry{}).ResidencyZone(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if zone != "" {
		t.Fatalf("residency zone = %q for an unbacked registry; anything but empty asserts a "+
			"placement nobody made", zone)
	}
}
