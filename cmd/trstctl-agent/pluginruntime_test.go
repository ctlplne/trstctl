// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/pluginhost"
)

// The grant an operator types must be the grant a module runs under (epic E4).
//
// This is the seam where a capability system quietly becomes decorative. Every
// input is operator-owned on purpose — the modules, the keys, the pins, the
// capabilities — and none of it is read from the module or pushed from the
// control plane. A publisher who could widen their own grant by editing a file
// they ship would make the sandbox a formality; a vendor who could push the
// grant would be deciding what partner code may do inside somebody else's
// network.

func TestAPrefixNamingAnUngrantedCapabilityIsRefused(t *testing.T) {
	t.Parallel()
	// The operator granted fs.read and then constrained net.dial. That reads as
	// a restriction on network access and would be no restriction at all,
	// because net.dial was never granted — so the flag says something the
	// system will not do. Refusing is the only reading that cannot mislead.
	_, err := buildPluginGrant("fs.read", "net.dial=appliance.internal:443")
	if err == nil {
		t.Fatal("a prefix naming an ungranted capability was accepted; it reads as a restriction " +
			"and would silently be none")
	}
	if !strings.Contains(err.Error(), "net.dial") {
		t.Errorf("the refusal did not name the offending capability: %v", err)
	}
}

func TestAnUnknownCapabilityIsRefusedRatherThanIgnored(t *testing.T) {
	t.Parallel()
	// A typo in a capability name must not silently grant nothing and look like
	// it granted something — nor silently grant everything.
	if _, err := buildPluginGrant("fs.reed", ""); err == nil {
		t.Fatal("a misspelled capability was accepted")
	}
}

func TestNoCapabilityFlagIsRefusedRatherThanDefaulted(t *testing.T) {
	t.Parallel()
	if _, err := buildPluginGrant("", ""); err == nil {
		t.Fatal("third-party code would run under a grant nobody set")
	}
}

// The grant that comes out is the grant that went in.
func TestTheOperatorsGrantIsTheGrantThatRuns(t *testing.T) {
	t.Parallel()
	grant, err := buildPluginGrant("net.dial,fs.read", "net.dial=appliance.internal:443")
	if err != nil {
		t.Fatalf("build grant: %v", err)
	}
	if !grant.Allows(pluginhost.CapNetDial, "appliance.internal:443") {
		t.Error("the appliance the operator named was not reachable")
	}
	if grant.Allows(pluginhost.CapNetDial, "evil.example:443") {
		t.Error("a host outside the operator's constraint was reachable")
	}
	// fs.read was granted with no constraint, which is unrestricted FOR THAT
	// CAPABILITY — a visible choice on a command line rather than a default.
	if !grant.Allows(pluginhost.CapFSRead, "/anywhere") {
		t.Error("an unconstrained capability stopped being unrestricted")
	}
	// And a capability never named is not granted at all.
	if grant.Allows(pluginhost.CapFSWrite, "/etc/passwd") {
		t.Error("a capability the operator never named was granted")
	}
}

// A plugin directory with no key flag is refused before anything loads.
func TestAPluginDirectoryWithNoKeyFlagIsRefused(t *testing.T) {
	t.Parallel()
	if _, err := readPluginKeys(""); err == nil {
		t.Fatal("an agent would have loaded third-party code with no key to verify it against")
	}
}
