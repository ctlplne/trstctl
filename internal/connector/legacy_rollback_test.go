// SPDX-License-Identifier: BUSL-1.1

package connector_test

import (
	"testing"

	"trstctl.com/trstctl/internal/connector"
)

// A45: the legacy object name is the fingerprint-less derivation, so a
// pre-fingerprint deploy and a legacy re-bind can never disagree.
func TestLegacyObjectNameIsTheFingerprintlessDerivation(t *testing.T) {
	t.Parallel()
	if got := connector.LegacyObjectName("clientssl_app"); got != "clientssl_app" {
		t.Fatalf("legacy object name = %q, want the base itself", got)
	}
	if connector.DeployedObjectName("clientssl_app", "") != connector.LegacyObjectName("clientssl_app") {
		t.Fatal("a deploy with no fingerprint and the legacy re-bind name differ")
	}
	for _, name := range connector.RollbackCapableConnectors() {
		if name == "fortigate" || name == "paloalto" {
			continue
		}
		if !connector.CanTakedown(name) {
			t.Errorf("%q re-binds by name but is not in the takedown census; legacy objects there could never be cleaned up", name)
		}
	}
}
