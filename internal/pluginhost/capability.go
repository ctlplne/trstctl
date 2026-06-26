package pluginhost

import "strings"

// Capability names a privileged operation a plugin may be granted. A plugin can
// only ever do what its grant permits; everything else is denied at runtime.
type Capability string

const (
	CapFSRead  Capability = "fs.read"
	CapFSWrite Capability = "fs.write"
	CapNetDial Capability = "net.dial"
)

// Grant is the set of capabilities a plugin holds, with optional per-capability
// resource constraints (for example, "write filesystem only at path X").
type Grant struct {
	caps     map[Capability]bool
	prefixes map[Capability][]string
}

// NewGrant returns a grant of the given capabilities (no resource constraints).
func NewGrant(caps ...Capability) Grant {
	g := Grant{caps: map[Capability]bool{}, prefixes: map[Capability][]string{}}
	for _, c := range caps {
		g.caps[c] = true
	}
	return g
}

// WithPathPrefix constrains a filesystem capability to resources under prefix
// (callable repeatedly to allow several prefixes). It returns the grant for
// chaining.
func (g Grant) WithPathPrefix(cap Capability, prefix string) Grant {
	g.prefixes[cap] = append(g.prefixes[cap], prefix)
	return g
}

// Has reports whether the capability is granted at all, ignoring resource
// constraints. The host uses this to gate operations that carry no resource.
func (g Grant) Has(cap Capability) bool { return g.caps[cap] }

// Empty reports whether the grant carries no capabilities or resource
// constraints. Server config uses it to preserve the legacy single-grant setting
// while allowing CA and connector plugin grants to be split explicitly.
func (g Grant) Empty() bool { return len(g.caps) == 0 && len(g.prefixes) == 0 }

// Allows reports whether the plugin may perform cap on resource: the capability
// must be granted, and if it carries prefix constraints the resource must fall
// under one of them.
func (g Grant) Allows(cap Capability, resource string) bool {
	if !g.caps[cap] {
		return false
	}
	prefixes := g.prefixes[cap]
	if len(prefixes) == 0 {
		return true
	}
	for _, p := range prefixes {
		if strings.HasPrefix(resource, p) {
			return true
		}
	}
	return false
}
