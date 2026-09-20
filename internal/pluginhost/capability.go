// SPDX-License-Identifier: BUSL-1.1

package pluginhost

import (
	"net"
	"path/filepath"
	"sort"
	"strings"
)

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

// WithPathPrefix constrains a capability to resources under prefix (callable
// repeatedly to allow several prefixes). For CapNetDial the prefix is a
// host[:port] authority rather than a path; see Allows for how each kind is
// matched. It returns the grant for chaining.
func (g Grant) WithPathPrefix(cap Capability, prefix string) Grant {
	// An EMPTY constraint is recorded, not skipped, and it denies.
	//
	// This was the opposite before, and it was a fail-open: an empty constraint
	// reached authorityAllows/pathPrefixAllows, both of which treated "" as "no
	// restriction" and returned true. So a caller narrowing a grant to one
	// appliance — WithPathPrefix(CapNetDial, c.host) — WIDENED it to every
	// reachable host the moment c.host came out empty.
	//
	// That is reachable from ordinary operator configuration, not a contrived
	// input: url.Parse("appliance.example") with no scheme puts the authority in
	// Path and leaves Host empty, and the connectors validated only that the
	// endpoint string was non-empty. Eleven connector families derived their
	// dial constraint that way.
	//
	// A caller that wants no restriction expresses it by not adding a
	// constraint at all — len(constraints) == 0 still means unrestricted. What
	// cannot be allowed to mean "everything" is an explicit attempt to narrow
	// that resolved to nothing, because that is what a misconfiguration looks
	// like, and the failure direction of a misconfiguration must be refusal.
	g.prefixes[cap] = append(g.prefixes[cap], prefix)
	return g
}

// Has reports whether the capability is granted at all, ignoring resource
// constraints. The host uses this to gate operations that carry no resource.
func (g Grant) Has(cap Capability) bool { return g.caps[cap] }

// Capabilities returns the granted capability names in deterministic order for
// operator-facing catalog/reporting surfaces. It exposes only capability labels,
// not any secret resource material.
func (g Grant) Capabilities() []Capability {
	out := make([]Capability, 0, len(g.caps))
	for cap, ok := range g.caps {
		if ok {
			out = append(out, cap)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Empty reports whether the grant carries no capabilities or resource
// constraints. Server config uses it to preserve the legacy single-grant setting
// while allowing CA and connector plugin grants to be split explicitly.
func (g Grant) Empty() bool { return len(g.caps) == 0 && len(g.prefixes) == 0 }

// PathPrefixes returns the resource constraints recorded for cap, in the order
// they were granted. The WASM sandbox uses them to open a directory handle per
// prefix, so that filesystem I/O is contained by an open root rather than by a
// string comparison alone.
func (g Grant) PathPrefixes(cap Capability) []string {
	out := make([]string, len(g.prefixes[cap]))
	copy(out, g.prefixes[cap])
	return out
}

// Allows reports whether the plugin may perform cap on resource: the capability
// must be granted, and if it carries resource constraints the resource must fall
// under one of them.
//
// Matching depends on the kind of resource, because a hostname is not a path:
//
//   - CapNetDial constraints are host[:port] authorities, matched on an exact
//     hostname (case-insensitive, trailing root dot and IPv6 brackets ignored).
//     A constraint that names a port also requires that exact port; one with no
//     port accepts any port. Exactness is the point: a prefix match would let
//     "example.com.attacker.example" through a grant for "example.com", and a
//     suffix match would let "evil-example.com" through.
//   - Every other capability constrains a platform-native resource path. Both
//     sides are filepath.Clean'd — so "/etc/nginx/certs/../../root/x" is resolved
//     before it is compared — and the match must land on a separator boundary,
//     so a grant for "/etc/nginx/certs" denies "/etc/nginx/certs-evil/x".
//
// An empty constraint carries no restriction, matching the no-constraints case.
//
// Allows is a pure lexical predicate: it never touches the filesystem, so it
// does not resolve symlinks. A symlink *inside* a granted prefix that points
// outside it still satisfies Allows. That is not a hole in the model, because
// Allows is only half of it: the WASM sandbox performs every filesystem
// operation through an os.Root opened at the granted prefix (see sandbox.go), so
// a symlink or ".." that leaves the root is refused when the path is resolved,
// whatever this predicate concluded. Keep both halves — a caller that consults
// Allows and then opens the path by name has re-opened the escape.
func (g Grant) Allows(cap Capability, resource string) bool {
	if !g.caps[cap] {
		return false
	}
	constraints := g.prefixes[cap]
	if len(constraints) == 0 {
		return true
	}
	for _, c := range constraints {
		if cap == CapNetDial {
			if authorityAllows(c, resource) {
				return true
			}
			continue
		}
		if pathPrefixAllows(c, resource) {
			return true
		}
	}
	return false
}

// pathPrefixAllows reports whether resource resolves to the granted prefix or to
// something beneath it, with both sides canonicalised first and the match forced
// onto a separator boundary.
func pathPrefixAllows(prefix, resource string) bool {
	if prefix == "" {
		// Same rule as authorityAllows, for the same reason: a filesystem grant
		// narrowed to an empty path must not become a grant over every path.
		return false
	}
	p := filepath.Clean(prefix)
	r := filepath.Clean(resource)
	rel, err := filepath.Rel(p, r)
	if err != nil {
		return false
	}
	return rel == "." || (!filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// authorityAllows reports whether resource names the one network authority the
// constraint grants.
func authorityAllows(constraint, resource string) bool {
	if constraint == "" {
		// See WithPathPrefix: an explicit constraint that resolved to nothing
		// denies. It is the signature of a misconfigured endpoint, and reading
		// it as "any host" hands a connector the whole network.
		return false
	}
	grantedHost, grantedPort := splitAuthority(constraint)
	host, port := splitAuthority(resource)
	if grantedHost == "" || host == "" || grantedHost != host {
		return false
	}
	return grantedPort == "" || grantedPort == port
}

// splitAuthority canonicalises a host[:port] authority into a comparable
// hostname (lowercased, IPv6 brackets and the trailing root dot removed) and its
// port, which is empty when the authority names none.
func splitAuthority(authority string) (host, port string) {
	host = strings.TrimSpace(authority)
	if h, p, err := net.SplitHostPort(host); err == nil {
		host, port = h, p
	}
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	host = strings.TrimRight(strings.ToLower(host), ".")
	return host, port
}
