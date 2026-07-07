// SPDX-License-Identifier: LicenseRef-trstctl-EE

package agentstack

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

// A ToolManifest is the set of tool identifiers an agent is DECLARED to be
// configured with. A RegisteredToolSet is the set of tools that has been
// recorded for the agent as permitted. The comparison predicate (Compare)
// checks a declared manifest against a registered set: a declared manifest that
// EXCEEDS the registered set is refused fail-closed (claim 12 / §8.4), and the
// refusal report NAMES the excess capability; a declared manifest that is a
// subset of (or equal to) the registered set is accepted.
//
// Tool identifiers are optionally resolved through a delegation.ToolRegistry-
// style resolver so aliases compare by canonical identity; here we normalize
// tokens (trim + lowercase) and, when a Resolver is supplied, resolve aliases —
// matching AGID-01's tool normalization so the two data models agree on tool
// identity. Fail-closed rule: an UNRESOLVED / UNKNOWN declared tool (one the
// resolver maps to nothing recognized) is treated as EXCEEDING the registered
// set and is never permitted (§8.4, security note).

// Resolver resolves a raw tool identifier to its canonical identifier and
// reports whether the identifier is KNOWN. The delegation package's
// *ToolRegistry does not report unknown-ness (an unknown id resolves to itself),
// so agent-stack manifest comparison uses this narrower interface: a fail-closed
// comparison must be able to distinguish "resolved to a known canonical id" from
// "unresolved / unknown", because an unknown declared tool is treated as
// exceeding the registered set. A nil Resolver means "no alias resolution and no
// known-set gate": tokens are compared by their normalized form and none is
// treated as unknown by resolution (only manifest-vs-registered set membership
// decides excess).
type Resolver interface {
	// ResolveTool returns the canonical id for a raw tool id and whether it is a
	// known/recognized tool. An unknown tool should return ok == false; the
	// canonical string may still be returned (normalized) for naming in reports.
	ResolveTool(raw string) (canonical string, ok bool)
}

// ToolManifest is a declared set of tool identifiers. The zero value is the empty
// manifest (an agent configured with no tools), which never exceeds any
// registered set.
type ToolManifest struct {
	Tools []string `json:"tools,omitempty"`
}

// RegisteredToolSet is the set of tools recorded as permitted for an agent.
type RegisteredToolSet struct {
	Tools []string `json:"tools,omitempty"`
}

// NewToolManifest constructs a manifest from raw tool ids.
func NewToolManifest(tools ...string) ToolManifest { return ToolManifest{Tools: tools} }

// NewRegisteredToolSet constructs a registered set from raw tool ids.
func NewRegisteredToolSet(tools ...string) RegisteredToolSet { return RegisteredToolSet{Tools: tools} }

// normTool applies the tool-id normalization shared with AGID-01: trim
// surrounding whitespace and lower-case. It is part of the versioned canonical
// semantics.
func normTool(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// canonicalTools normalizes, de-duplicates, and sorts a slice of tool ids so the
// tool-manifest digest is order- and duplicate-independent. Empty/whitespace-only
// entries are dropped.
func canonicalTools(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		n := normTool(s)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Canonical returns the sorted, de-duplicated, normalized tool list of the
// manifest.
func (m ToolManifest) Canonical() []string { return canonicalTools(m.Tools) }

// Canonical returns the sorted, de-duplicated, normalized tool list of the
// registered set.
func (s RegisteredToolSet) Canonical() []string { return canonicalTools(s.Tools) }

// Digest returns the domain-separated digest over the sorted tool manifest,
// routed through the internal/crypto AN-3 boundary. The same tool set —
// regardless of declaration order or duplicates — produces identical bytes and
// therefore an identical digest; any tool added or removed flips it. An empty
// manifest yields a well-defined digest (the domain tag over zero tools), so "no
// tools" is a first-class, stable representation rather than an absent field.
func (m ToolManifest) Digest() []byte {
	var b bytes.Buffer
	b.WriteString(toolManifestDigestDomain)
	tools := m.Canonical()
	writeU64(&b, uint64(len(tools)))
	for _, t := range tools {
		writeStr(&b, t)
	}
	return crypto.SHA256Sum(b.Bytes())
}

// ManifestVerdict is the result of comparing a declared manifest against a
// registered tool set (claim 12). It is EVIDENCE ONLY: this card returns the
// predicate and the excess-capability report; the load-bearing signed refusal
// record is minted inside the AN-4 signer (AGID-04). Accepted reports whether the
// declared manifest is a subset of (or equal to) the registered set. When
// Accepted is false, Excess names every declared capability that exceeds the
// registered set (extra tools and unresolved/unknown tools), sorted for stable
// reporting, and Reason is a human-readable, non-secret summary naming the
// excess.
type ManifestVerdict struct {
	Accepted bool     `json:"accepted"`
	Excess   []string `json:"excess,omitempty"`
	Reason   string   `json:"reason,omitempty"`
}

// ErrManifestExceedsRegistered is returned by CompareOrError when a declared
// manifest exceeds the registered set. Its message names the excess so callers
// (AGID-04) can carry the named capability into the signed refusal record.
var ErrManifestExceedsRegistered = errors.New("agentstack: declared tool manifest exceeds registered tool set")

// Compare checks the declared manifest against the registered set and returns a
// verdict (claim 12 / §8.4). It is FAIL-CLOSED:
//
//   - Every declared tool must be a member of the registered set (by canonical
//     identity) to be permitted. A declared tool NOT in the registered set is
//     excess and refuses the manifest, and the tool is NAMED in Excess.
//   - When a resolver is supplied, a declared tool the resolver reports as
//     UNKNOWN (unresolved) is treated as excess and named, even if by raw string
//     it would otherwise match — an unknown/unresolved tool is never permitted.
//   - A declared manifest that is a subset of (or equal to) the registered set is
//     accepted (Excess empty).
//
// The empty manifest is always accepted. Compare performs no key operation.
func Compare(declared ToolManifest, registered RegisteredToolSet, resolver Resolver) ManifestVerdict {
	regSet := resolveSet(registered.Canonical(), resolver)

	seenExcess := make(map[string]struct{})
	var excess []string
	addExcess := func(name string) {
		if _, ok := seenExcess[name]; ok {
			return
		}
		seenExcess[name] = struct{}{}
		excess = append(excess, name)
	}

	for _, raw := range declared.Canonical() {
		canonical, known := raw, true
		if resolver != nil {
			canonical, known = resolver.ResolveTool(raw)
			canonical = normTool(canonical)
			if canonical == "" {
				canonical = raw
			}
		}
		if !known {
			// Fail-closed: an unresolved / unknown declared tool is treated as
			// exceeding the registered set and is named as excess (§8.4).
			addExcess(canonical)
			continue
		}
		if _, ok := regSet[canonical]; !ok {
			addExcess(canonical)
		}
	}

	if len(excess) == 0 {
		return ManifestVerdict{Accepted: true}
	}
	sort.Strings(excess)
	return ManifestVerdict{
		Accepted: false,
		Excess:   excess,
		Reason: fmt.Sprintf("declared tool manifest exceeds registered tool set; excess capability: %s",
			strings.Join(excess, ", ")),
	}
}

// CompareOrError is Compare with an error return for callers that want the
// fail-closed refusal as an error value (the excess is named in both the returned
// verdict and the error message). On acceptance it returns a nil error.
func CompareOrError(declared ToolManifest, registered RegisteredToolSet, resolver Resolver) (ManifestVerdict, error) {
	v := Compare(declared, registered, resolver)
	if v.Accepted {
		return v, nil
	}
	return v, fmt.Errorf("%w: %s", ErrManifestExceedsRegistered, strings.Join(v.Excess, ", "))
}

// resolveSet builds the membership set of registered tools by canonical identity.
// When a resolver is supplied, a registered tool the resolver recognizes is keyed
// by its resolved canonical id; a registered tool the resolver does not recognize
// still contributes its normalized self, so a registry that simply has no alias
// for a legitimately registered id does not accidentally empty the permitted set.
func resolveSet(regTools []string, resolver Resolver) map[string]struct{} {
	set := make(map[string]struct{}, len(regTools))
	for _, raw := range regTools {
		key := raw
		if resolver != nil {
			if canonical, ok := resolver.ResolveTool(raw); ok {
				if n := normTool(canonical); n != "" {
					key = n
				}
			}
		}
		set[key] = struct{}{}
	}
	return set
}
