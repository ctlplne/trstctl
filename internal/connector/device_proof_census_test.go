// SPDX-License-Identifier: MPL-2.0

package connector_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
)

// A family may not claim device proof it does not have (epic E1).
//
// The census in device_proof.go is served to operators through the connector
// catalog, so it is a claim about this binary. Like C1a's agent capability
// census, it is only worth anything if it cannot drift from the tree: a list
// somebody edits by hand and nothing checks is a list that will eventually be
// wrong in the optimistic direction, because that is the direction nobody
// notices.
//
// The check is deliberately structural rather than clever. A family claiming
// proof must carry BOTH an emulator package and a test that drives the real
// connector against it — because either alone proves nothing. An emulator with
// no test is scaffolding; a test with no emulator is testing against nothing.

func TestEveryDeviceProvenFamilyCarriesAnEmulatorAndATest(t *testing.T) {
	t.Parallel()
	for _, family := range connector.DeviceProvenConnectors() {
		family := family
		t.Run(family, func(t *testing.T) {
			t.Parallel()
			dir := filepath.Join("..", "..", "internal", "connector", family)

			emulator := filepath.Join(dir, family+"test")
			if info, err := os.Stat(emulator); err != nil || !info.IsDir() {
				t.Fatalf("%s claims its deploy is proven against a device double, but there is no "+
					"%s package; the catalog would tell an operator this family is verified when "+
					"nothing exercises its API conversation", family, family+"test")
			}

			// The emulator must be reached by a test. An emulator nothing drives
			// is scaffolding that makes the census look satisfied.
			testFile := filepath.Join(dir, family+"_test.go")
			body, err := os.ReadFile(testFile) // #nosec G304 -- fixed in-tree path derived from the census (CWE-22)
			if err != nil {
				t.Fatalf("%s claims device proof but has no %s_test.go: %v", family, family, err)
			}
			if !strings.Contains(string(body), family+"test.") &&
				!strings.Contains(string(body), family+"test\"") {
				t.Errorf("%s_test.go does not reference the %stest emulator, so the claimed proof "+
					"does not run against a device double", family, family)
			}
		})
	}
}

// The census must not silently shrink either.
//
// Every RELAY-vantage family is an API conversation, so every one of them is a
// family whose deploy can only be proven against a device. A relay family
// missing from the census is either an unproven capability the catalog is about
// to advertise, or a census someone trimmed to make a test pass.
func TestEveryRelayVantageFamilyIsDeviceProven(t *testing.T) {
	t.Parallel()
	proven := map[string]bool{}
	for _, f := range connector.DeviceProvenConnectors() {
		proven[f] = true
	}
	// The relay-vantage families, named here rather than imported from
	// internal/agent/relay: this package must not depend on the agent runtime,
	// and a drift between the two lists is caught by the relay's own census
	// test, which checks that every kind it executes is one this package ships.
	for _, family := range []string{"a10", "cisco", "f5", "fortigate", "kemp", "netscaler", "paloalto"} {
		if !proven[family] {
			t.Errorf("relay-vantage family %q has no device proof; its entire implementation is "+
				"an API conversation, so passing the MemoryOps conformance suite says nothing "+
				"about whether the appliance would have accepted it", family)
		}
	}
}
