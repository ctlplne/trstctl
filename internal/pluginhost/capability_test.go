// SPDX-License-Identifier: MPL-2.0

package pluginhost_test

import (
	"testing"

	"trstctl.com/trstctl/internal/pluginhost"
)

// TestGrantAllowsRequiresASeparatorBoundary is the regression tripwire for the
// containment primitive the docs sell as "write filesystem only at path X": a
// raw prefix test makes a grant for /etc/nginx/certs also cover the unrelated
// sibling directory /etc/nginx/certs-evil, and an uncleaned resource lets a
// caller walk out of the granted subtree with "..". Both must be denied.
func TestGrantAllowsRequiresASeparatorBoundary(t *testing.T) {
	g := pluginhost.NewGrant(pluginhost.CapFSWrite).
		WithPathPrefix(pluginhost.CapFSWrite, "/etc/nginx/certs")

	denied := []string{
		"/etc/nginx/certs-evil/x",             // sibling that merely shares the prefix
		"/etc/nginx/certsevil",                // no separator at the boundary at all
		"/etc/nginx/certs/../../root/x",       // traversal out of the subtree
		"/etc/nginx/certs/../certs-evil/x",    // traversal into the sibling
		"/etc/nginx/certs/./../../etc/shadow", // traversal with a no-op element
	}
	for _, r := range denied {
		if g.Allows(pluginhost.CapFSWrite, r) {
			t.Errorf("write to %q was allowed by a grant for /etc/nginx/certs", r)
		}
	}

	allowed := []string{
		"/etc/nginx/certs",             // the granted directory itself
		"/etc/nginx/certs/server.pem",  // a file directly inside it
		"/etc/nginx/certs/live/a.pem",  // a file nested inside it
		"/etc/nginx/certs//server.pem", // a redundant separator still lands inside
		"/etc/nginx/certs/./server.pem",
	}
	for _, r := range allowed {
		if !g.Allows(pluginhost.CapFSWrite, r) {
			t.Errorf("write to %q was denied by a grant for /etc/nginx/certs", r)
		}
	}

	// A grant with no constraints is unchanged: unconstrained.
	if !pluginhost.NewGrant(pluginhost.CapFSRead).Allows(pluginhost.CapFSRead, "/anywhere") {
		t.Error("an unconstrained capability must still allow any resource")
	}

	// The same boundary applies to capabilities defined outside this package
	// (the ee observation sandbox scopes "observe.*" by a resource prefix).
	obs := pluginhost.Capability("observe.list")
	scoped := pluginhost.NewGrant(obs).WithPathPrefix(obs, "vault-prod/")
	if !scoped.Allows(obs, "vault-prod/metadata/tenant-a") {
		t.Error("an in-scope observation resource must be allowed")
	}
	if scoped.Allows(obs, "vault-production/metadata") {
		t.Error("a scope that merely shares a prefix must be denied")
	}
}

// TestGrantAllowsMatchesNetDialHostsExactly pins the other half of the primitive:
// a hostname is not a path, so net.dial constraints match on the whole host, not
// on a prefix. Every connector and DNS provider in the tree grants exactly one
// management host, and a prefix test would hand a plugin holding a grant for
// "vault.internal" the attacker-registered "vault.internal.attacker.example".
func TestGrantAllowsMatchesNetDialHostsExactly(t *testing.T) {
	g := pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, "vault.internal")

	denied := []string{
		"vault.internal.attacker.example", // prefix-extended registrable domain
		"evil-vault.internal",             // suffix-extended label
		"vault.internals",                 // no label boundary
		"internal",                        // a bare parent label
		"",                                // no host at all
	}
	for _, r := range denied {
		if g.Allows(pluginhost.CapNetDial, r) {
			t.Errorf("dial to %q was allowed by a grant for vault.internal", r)
		}
	}

	allowed := []string{
		"vault.internal",
		"vault.internal:8200",  // the constraint names no port, so any port is in scope
		"VAULT.INTERNAL",       // hostnames are case-insensitive
		"vault.internal.:8200", // the trailing root dot is the same name
	}
	for _, r := range allowed {
		if !g.Allows(pluginhost.CapNetDial, r) {
			t.Errorf("dial to %q was denied by a grant for vault.internal", r)
		}
	}

	// A constraint that names a port pins the port too.
	pinned := pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, "ns.example:53")
	if !pinned.Allows(pluginhost.CapNetDial, "ns.example:53") {
		t.Error("the granted host:port must be allowed")
	}
	if pinned.Allows(pluginhost.CapNetDial, "ns.example:5353") {
		t.Error("a grant pinned to one port must not allow another port")
	}

	// IPv6 literals compare by address, brackets and port aside.
	v6 := pluginhost.NewGrant(pluginhost.CapNetDial).
		WithPathPrefix(pluginhost.CapNetDial, "[::1]:8443")
	if !v6.Allows(pluginhost.CapNetDial, "[::1]:8443") {
		t.Error("the granted IPv6 authority must be allowed")
	}
	if v6.Allows(pluginhost.CapNetDial, "[::1]:9443") {
		t.Error("a different port on the granted IPv6 address must be denied")
	}
}
