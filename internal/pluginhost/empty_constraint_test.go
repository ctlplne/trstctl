// SPDX-License-Identifier: MPL-2.0

package pluginhost_test

import (
	"testing"

	"trstctl.com/trstctl/internal/pluginhost"
)

// An explicit constraint that resolved to nothing must DENY.
//
// This was a live fail-open. Every appliance connector narrows its network grant
// to the one host it talks to:
//
//	pluginhost.NewGrant(CapNetDial).WithPathPrefix(CapNetDial, c.host)
//
// and c.host comes from url.Parse of an operator-supplied endpoint. A URL with
// no scheme — "appliance.example", which the config layer accepted because it
// only checked for non-emptiness — parses with the authority in Path and Host
// EMPTY. The empty constraint then reached authorityAllows, which read "" as
// "no restriction" and returned true.
//
// So the line intended to confine a connector to one appliance instead handed it
// every host it could reach, and it took a typo in a config field to get there.
// Eleven families derived their constraint this way.

func TestAnEmptyDialConstraintDeniesRatherThanAllowingEverything(t *testing.T) {
	t.Parallel()
	// A grant that TRIED to narrow and resolved to nothing.
	g := pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, "")

	for _, target := range []string{
		"appliance.internal:443",
		"169.254.169.254:80", // cloud metadata — the reason this matters
		"other-tenant.example:443",
		"",
	} {
		if g.Allows(pluginhost.CapNetDial, target) {
			t.Errorf("a grant narrowed to an empty host allowed %q; a misconfigured endpoint "+
				"would give a connector the whole network instead of one appliance", target)
		}
	}
}

func TestAnEmptyPathConstraintDeniesRatherThanAllowingEveryPath(t *testing.T) {
	t.Parallel()
	g := pluginhost.NewGrant(pluginhost.CapFSWrite).
		WithPathPrefix(pluginhost.CapFSWrite, "")

	for _, target := range []string{"/etc/shadow", "/", "/var/lib/trstctl/x.pem"} {
		if g.Allows(pluginhost.CapFSWrite, target) {
			t.Errorf("a filesystem grant narrowed to an empty path allowed %q", target)
		}
	}
}

// Granting a capability WITHOUT a constraint still means unrestricted.
//
// That distinction is the whole design: "I did not narrow this" and "I tried to
// narrow it and got nothing" are different statements, and only the second is
// evidence of a mistake. Collapsing them would either break every unconstrained
// grant or restore the fail-open.
func TestACapabilityWithNoConstraintRemainsUnrestricted(t *testing.T) {
	t.Parallel()
	g := pluginhost.NewGrant(pluginhost.CapNetDial)
	if !g.Allows(pluginhost.CapNetDial, "appliance.internal:443") {
		t.Error("a capability granted with no constraint stopped being unrestricted; callers " +
			"that legitimately do not narrow would break")
	}
}

// A real constraint still narrows to exactly its host.
func TestARealConstraintStillNarrows(t *testing.T) {
	t.Parallel()
	g := pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, "appliance.internal:443")

	if !g.Allows(pluginhost.CapNetDial, "appliance.internal:443") {
		t.Error("the granted host was denied")
	}
	if g.Allows(pluginhost.CapNetDial, "evil.example:443") {
		t.Error("a host outside the constraint was allowed")
	}
}
