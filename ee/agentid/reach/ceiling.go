// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reach

import (
	"fmt"
	"sort"
	"strings"
)

// ceiling.go defines the policy ceilings a reachable set is bounded by (claim 5) and the
// ceiling DETERMINATION the verdict binds and the signer verifies. A ceiling is per
// REQUESTER CLASS: the class of the requesting principal (e.g. the designated authority
// class of the delegation head, or a broker-assigned tier) selects the ceiling the
// reachable set is checked against. When a reachable set EXCEEDS any ceiling dimension,
// the determination names the violated ceiling and carries a digest of the offending
// reachable subset, so the signer's refusal names WHICH ceiling was exceeded without
// re-computing the graph (claim 5 / INV-A5).
//
// This file computes the determination OUTSIDE the signer (it is part of what the verdict
// binds); the signer only re-checks the SIGNED determination. Ceilings are pure policy
// values with no I/O.

// CeilingKind names a ceiling dimension, used as the violated-ceiling identifier in a
// determination and in a signed refusal (non-secret, human-meaningful, greppable —
// matching the delegation gate's Check* identifiers).
type CeilingKind string

const (
	// CeilingCardinality bounds the maximum reachable-set cardinality.
	CeilingCardinality CeilingKind = "reach_cardinality"
	// CeilingSensitivity bounds the maximum asset sensitivity class in the reachable set.
	CeilingSensitivity CeilingKind = "reach_sensitivity"
	// CeilingTenantSpan bounds the maximum number of tenants the reachable set may touch.
	CeilingTenantSpan CeilingKind = "reach_tenant_span"
	// CeilingProhibitedLabel is violated when the reachable set touches a prohibited asset
	// label.
	CeilingProhibitedLabel CeilingKind = "reach_prohibited_label"
)

// Ceiling is the policy bound for one requester class (claim 5). A zero value bounds
// nothing (every dimension unlimited / no prohibited labels), so an unconfigured class is
// NOT silently unbounded in the gate — the gate treats a missing verdict / missing ceiling
// as fail-closed (verify.go), while a Ceiling explicitly configured with a bound enforces
// it. Interpretation of each field:
type Ceiling struct {
	// MaxCardinality is the largest reachable-set cardinality allowed. 0 means "no
	// cardinality bound" (unlimited); a positive value is a strict maximum (a set of that
	// exact size is allowed; larger is refused).
	MaxCardinality int `json:"max_cardinality"`
	// MaxSensitivity is the most-sensitive asset class allowed in the reachable set. The
	// zero value (SensitivityUnknown) means "no sensitivity bound" (unlimited); a positive
	// class allows sets whose MaxSensitivity is <= it and refuses more sensitive sets.
	MaxSensitivity Sensitivity `json:"max_sensitivity"`
	// MaxTenantSpan is the largest tenant span allowed. 0 means "no span bound"; a
	// positive value is a strict maximum. Under the AN-1 single-tenant build a set spans
	// at most one tenant, so a span ceiling of 1 is the normal single-tenant policy and a
	// span ceiling that a set exceeds signals a (currently impossible without a persisted
	// multi-tenant graph) cross-tenant reach — modeled so the dimension exists.
	MaxTenantSpan int `json:"max_tenant_span"`
	// ProhibitedLabels are asset labels ("key=value", normalized) that must NOT appear on
	// any reachable node. Any present prohibited label is a violation. Empty means none
	// are prohibited.
	ProhibitedLabels []string `json:"prohibited_labels,omitempty"`
}

// CeilingPolicy maps a requester class to its Ceiling (claim 5, "per requester class").
// A class with no entry has no configured ceiling; the gate treats an authority whose
// class has no ceiling as requiring an EXPLICIT ceiling — a verdict computed against an
// absent ceiling is a fail-closed violation, never "allowed" — see NewCeilingPolicy /
// Ceiling(class). This keeps the bound fail-closed: forgetting to configure a class does
// not silently disable the reachability bound for it.
type CeilingPolicy struct {
	byClass  map[string]Ceiling
	fallback *Ceiling
}

// NewCeilingPolicy builds a ceiling policy from a class->Ceiling map. The optional
// fallback (via WithFallbackCeiling) applies to a class with no explicit entry; without a
// fallback, a class with no entry has NO ceiling, and the gate refuses a request of that
// class fail-closed (a class the operator never bounded must not issue an unbounded reach).
func NewCeilingPolicy(byClass map[string]Ceiling) *CeilingPolicy {
	m := make(map[string]Ceiling, len(byClass))
	for k, v := range byClass {
		m[normLabel(k)] = normalizeCeiling(v)
	}
	return &CeilingPolicy{byClass: m}
}

// WithFallbackCeiling returns a copy of the policy with a fallback ceiling applied to any
// class lacking an explicit entry. A deliberately restrictive fallback is the safe default
// for an operator who wants every un-enumerated class bounded rather than refused.
func (p *CeilingPolicy) WithFallbackCeiling(c Ceiling) *CeilingPolicy {
	if p == nil {
		p = &CeilingPolicy{byClass: map[string]Ceiling{}}
	}
	nc := normalizeCeiling(c)
	cp := &CeilingPolicy{byClass: p.byClass, fallback: &nc}
	return cp
}

// Ceiling returns the ceiling for a requester class and whether one is configured. A class
// with no explicit entry uses the fallback when present; otherwise (false) the gate must
// refuse fail-closed.
func (p *CeilingPolicy) Ceiling(class string) (Ceiling, bool) {
	if p == nil {
		return Ceiling{}, false
	}
	if c, ok := p.byClass[normLabel(class)]; ok {
		return c, true
	}
	if p.fallback != nil {
		return *p.fallback, true
	}
	return Ceiling{}, false
}

// normalizeCeiling canonicalizes a ceiling's prohibited labels (normalized + sorted +
// de-duplicated) so evaluation and the bound-into-verdict form are stable.
func normalizeCeiling(c Ceiling) Ceiling {
	if len(c.ProhibitedLabels) > 0 {
		seen := map[string]bool{}
		var out []string
		for _, l := range c.ProhibitedLabels {
			n := normLabel(l)
			if n == "" || seen[n] {
				continue
			}
			seen[n] = true
			out = append(out, n)
		}
		sort.Strings(out)
		c.ProhibitedLabels = out
	}
	return c
}

// Violation is one exceeded ceiling dimension: the kind, a human-meaningful reason
// (non-secret), and a digest of the OFFENDING reachable subset (the nodes responsible for
// the violation), so a signed refusal can carry it without the graph. It is part of the
// ceiling determination the verdict binds (claim 5).
type Violation struct {
	Ceiling CeilingKind `json:"ceiling"`
	Reason  string      `json:"reason"`
	// OffendingDigest is the canonical digest of the reachable subset that caused the
	// violation (the whole set for a cardinality/span breach; the over-sensitive or
	// prohibited-labeled nodes for those breaches). It lets the refusal reference the
	// cause without leaking node contents.
	OffendingDigest []byte `json:"offending_digest,omitempty"`
}

// Determination is the ceiling-evaluation OUTCOME the verdict binds and the signer
// verifies (claim 5/6). RequesterClass names the class the ceiling was selected by;
// Exceeded is true iff any dimension was violated; Violations names each violated ceiling
// with its offending-subset digest. A Determination with Exceeded=false is an APPROVE
// determination; Exceeded=true is a REFUSE determination the signer honors by performing
// no key op.
type Determination struct {
	RequesterClass string      `json:"requester_class"`
	Exceeded       bool        `json:"exceeded"`
	Violations     []Violation `json:"violations,omitempty"`
}

// Evaluate computes the ceiling determination for a reachable set against a ceiling for
// the given requester class (claim 5). It is pure and deterministic: it checks each
// dimension, records a Violation (with the offending-subset digest) per exceeded
// dimension, and returns a Determination. It performs NO I/O and NO key op. The
// determination is what the verdict binds; the signer re-checks the SIGNED determination,
// never re-running Evaluate over a live graph.
func Evaluate(set ReachableSet, class string, c Ceiling) Determination {
	det := Determination{RequesterClass: class}

	if c.MaxCardinality > 0 && set.Cardinality > c.MaxCardinality {
		det.Violations = append(det.Violations, Violation{
			Ceiling:         CeilingCardinality,
			Reason:          fmt.Sprintf("reachable-set cardinality %d exceeds ceiling %d", set.Cardinality, c.MaxCardinality),
			OffendingDigest: set.Digest(), // the whole set is the offending subset
		})
	}

	if c.MaxSensitivity > SensitivityUnknown && set.MaxSensitivity > c.MaxSensitivity {
		over := subsetBySensitivity(set, c.MaxSensitivity)
		det.Violations = append(det.Violations, Violation{
			Ceiling:         CeilingSensitivity,
			Reason:          fmt.Sprintf("reachable set touches %s assets, exceeding ceiling %s", set.MaxSensitivity, c.MaxSensitivity),
			OffendingDigest: subsetDigest(set.TenantID, "sensitivity", over),
		})
	}

	if c.MaxTenantSpan > 0 && set.TenantSpan > c.MaxTenantSpan {
		det.Violations = append(det.Violations, Violation{
			Ceiling:         CeilingTenantSpan,
			Reason:          fmt.Sprintf("reachable-set tenant span %d exceeds ceiling %d", set.TenantSpan, c.MaxTenantSpan),
			OffendingDigest: set.Digest(),
		})
	}

	if len(c.ProhibitedLabels) > 0 {
		if present := prohibitedPresent(set, c.ProhibitedLabels); len(present) > 0 {
			bad := subsetByLabels(set, present)
			det.Violations = append(det.Violations, Violation{
				Ceiling:         CeilingProhibitedLabel,
				Reason:          fmt.Sprintf("reachable set touches prohibited label(s): %s", strings.Join(present, ", ")),
				OffendingDigest: subsetDigest(set.TenantID, "prohibited-label", bad),
			})
		}
	}

	det.Exceeded = len(det.Violations) > 0
	return det
}

// subsetBySensitivity returns the reachable nodes strictly more sensitive than max, in
// canonical (id-sorted) order.
func subsetBySensitivity(set ReachableSet, max Sensitivity) []ReachedNode {
	var out []ReachedNode
	for _, n := range set.Nodes {
		if n.Sensitivity > max {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// subsetByLabels returns the reachable nodes carrying any of the given (normalized)
// labels, in canonical order.
func subsetByLabels(set ReachableSet, labels []string) []ReachedNode {
	want := map[string]bool{}
	for _, l := range labels {
		want[l] = true
	}
	var out []ReachedNode
	for _, n := range set.Nodes {
		for _, l := range n.Labels {
			if want[l] {
				out = append(out, n)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// prohibitedPresent returns the sorted set of prohibited labels actually present in the
// reachable set (so the reason names only the labels that were hit).
func prohibitedPresent(set ReachableSet, prohibited []string) []string {
	present := map[string]bool{}
	for _, l := range set.PresentLabels {
		present[l] = true
	}
	var hit []string
	for _, p := range prohibited {
		if present[p] {
			hit = append(hit, p)
		}
	}
	sort.Strings(hit)
	return hit
}

// subsetDigest computes a canonical, byte-stable digest of a reachable SUBSET, domain
// -separated by a tag, so an offending-subset digest is reproducible and distinct from the
// whole-set digest. It reuses the reachable-set canonical discipline over the subset's
// nodes.
func subsetDigest(tenantID, tag string, nodes []ReachedNode) []byte {
	sub := ReachableSet{TenantID: tenantID}
	sub.Nodes = append(sub.Nodes, nodes...)
	sort.Slice(sub.Nodes, func(i, j int) bool { return sub.Nodes[i].ID < sub.Nodes[j].ID })
	sub.Cardinality = len(sub.Nodes)
	for _, n := range sub.Nodes {
		if n.Sensitivity > sub.MaxSensitivity {
			sub.MaxSensitivity = n.Sensitivity
		}
	}
	sub.PresentLabels = DistinctLabels(sub.Nodes)
	// Domain-separate by tag so a sensitivity-subset and a label-subset of the same nodes
	// yield distinct digests.
	var b []byte
	b = appendStr(b, reachPrefix)
	b = appendStr(b, "offending-subset")
	b = appendStr(b, tag)
	b = append(b, sub.canonicalBytes()...)
	return sha256Of(b)
}
