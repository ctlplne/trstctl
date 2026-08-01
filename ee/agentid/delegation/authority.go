// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package delegation defines the AGID delegation-chain data model: the
// authority-set model, its stable canonical normalization, the versioned
// partial-order comparator that decides "no broader than the parent" (AGID-claim-3,
// establishing the comparator half of INV-A2), the effective spend/rate budget
// derivation as the minimum along a chain (AGID-claim-4), the delegation-record
// structure with its canonical serialization and delegator signature (§3.1), and
// the versioned AN-2 event types for the delegation lifecycle.
//
// This card is pure data model plus comparator plus event types. It performs NO
// private-key operation and never mints (INV-A1 is preserved here by construction:
// this package holds no issuance key and calls no signer to mint). The in-signer
// verify-before-keygen enforcement that CONSUMES this comparator lives in AGID-04.
// All hashing routes through the core internal/crypto AN-3 boundary; no crypto/* is
// imported here. This package is proprietary Enterprise/Provider material under the
// ee/ fence; core never imports it.
package delegation

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

// ComparatorVersion identifies the exact semantics of the partial-order comparator
// and the canonical-normalization rules below, so a later verifier (AGID-04, the
// relying-party verifier) can reproduce a verdict deterministically. Bump this
// string whenever the normalization rules or the comparison of any dimension
// changes; a recorded verdict is only reproducible against a matching version.
const ComparatorVersion = "agid.authority.compare/v1"

// canonicalPrefix domain-separates the canonical authority encoding from any other
// hashed structure in the repo. It is part of the v1 semantics named above.
const canonicalPrefix = "agid/authority/v1"

// ResourceSelector selects a set of resources a delegate may act on. Kind names the
// selector algebra (for example "path" for hierarchical path prefixes, "exact" for
// opaque identifiers). Containment for a Kind whose algebra supports it (path) is by
// prefix; every other Kind falls back to exact membership (card §3.3).
type ResourceSelector struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// Budget is a spend budget: a non-negative amount in a currency. Two budgets are
// comparable only within the same currency; a currency mismatch is incomparable
// (neither <= the other), which the comparator treats as widening (card §1, §3.3).
type Budget struct {
	Amount   uint64 `json:"amount"`
	Currency string `json:"currency"`
}

// Rate is a rate budget: a call/operation limit per named period. Two rates are
// comparable only for the same period; a period mismatch is incomparable.
type Rate struct {
	Limit uint64 `json:"limit"`
	Per   string `json:"per"`
}

// Window is a validity window as inclusive Unix-second bounds. Nesting (child within
// parent) requires parent.NotBefore <= child.NotBefore and child.NotAfter <=
// parent.NotAfter (card §3.3, validity by window nesting).
type Window struct {
	NotBefore int64 `json:"not_before"`
	NotAfter  int64 `json:"not_after"`
}

// Authority is the conferred authority-set model (card §1): scope identifiers, tool
// identifiers, resource selectors, data classes, a spend budget, a rate budget, a
// delegation depth, and a validity ceiling. The set dimensions are unordered sets;
// the numeric and window dimensions are scalars. Equality and ordering are defined
// only after canonical normalization (Normalize / CanonicalBytes).
type Authority struct {
	Scopes    []string           `json:"scopes,omitempty"`
	Tools     []string           `json:"tools,omitempty"`
	Resources []ResourceSelector `json:"resources,omitempty"`
	Classes   []string           `json:"classes,omitempty"`
	Spend     Budget             `json:"spend"`
	Rate      Rate               `json:"rate"`
	Depth     uint32             `json:"depth"`
	Validity  Window             `json:"validity"`
}

// ToolRegistry resolves tool aliases to canonical tool identifiers so the comparator
// compares tools by resolved identity, not raw spelling (card §3.3: "tool ids
// resolved against a registry"). An unknown tool id resolves to itself (trimmed and
// lower-cased), so an unregistered tool still compares deterministically by its own
// name rather than being silently dropped.
type ToolRegistry struct{ alias map[string]string }

// NewToolRegistry builds a registry from an alias->canonical-id map. Keys are matched
// after the same trim+lowercase normalization applied to scope-like strings, so a
// registered alias resolves regardless of incoming case/whitespace.
func NewToolRegistry(aliases map[string]string) *ToolRegistry {
	m := make(map[string]string, len(aliases))
	for k, v := range aliases {
		m[normToken(k)] = v
	}
	return &ToolRegistry{alias: m}
}

// Resolve returns the canonical id for a tool id, or the trim+lowercased id itself
// when unregistered. A nil registry resolves every id to its normalized self.
func (r *ToolRegistry) Resolve(id string) string {
	n := normToken(id)
	if r == nil {
		return n
	}
	if c, ok := r.alias[n]; ok {
		return c
	}
	return n
}

// normToken applies the scope/class/tool string normalization: trim surrounding
// whitespace and lower-case. This is the "scope strings normalized" rule (card §3.3)
// and is part of the versioned canonical semantics.
func normToken(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// normStrings normalizes, de-duplicates, and sorts a set of tokens.
func normStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		n := normToken(s)
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// normTools resolves every tool id through the registry, then de-duplicates and sorts
// the resolved canonical ids.
func normTools(in []string, reg *ToolRegistry) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		c := reg.Resolve(s)
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// normResources normalizes each selector (trim+lowercase Kind, trim Value; a path
// value additionally has a trailing slash stripped except for root), then
// de-duplicates and sorts by (Kind, Value).
func normResources(in []ResourceSelector) []ResourceSelector {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[ResourceSelector]struct{}, len(in))
	out := make([]ResourceSelector, 0, len(in))
	for _, rs := range in {
		n := ResourceSelector{Kind: normToken(rs.Kind), Value: strings.TrimSpace(rs.Value)}
		if n.Kind == "path" {
			n.Value = cleanPath(n.Value)
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// cleanPath strips a single trailing slash (keeping "/" as root) so "/data" and
// "/data/" are the same node. It does not attempt full path canonicalization; the
// containment test compares boundary-aware prefixes.
func cleanPath(p string) string {
	if len(p) > 1 && strings.HasSuffix(p, "/") {
		return strings.TrimRight(p, "/")
	}
	return p
}

// Normalize returns a copy of a with every set dimension normalized, de-duplicated,
// and sorted, tools resolved through reg, and the scalar Budget/Rate currency/period
// trim+lowercased. It is idempotent: Normalize(Normalize(x)) == Normalize(x).
func Normalize(a Authority, reg *ToolRegistry) Authority {
	return Authority{
		Scopes:    normStrings(a.Scopes),
		Tools:     normTools(a.Tools, reg),
		Resources: normResources(a.Resources),
		Classes:   normStrings(a.Classes),
		Spend:     Budget{Amount: a.Spend.Amount, Currency: normToken(a.Spend.Currency)},
		Rate:      Rate{Limit: a.Rate.Limit, Per: normToken(a.Rate.Per)},
		Depth:     a.Depth,
		Validity:  a.Validity,
	}
}

// CanonicalBytes returns the stable, deterministic byte encoding of a's normalized
// form. The same authority set — regardless of set order, duplicates, or
// semantically-equal spelling — produces identical bytes across runs, machines, and
// architectures (fixed big-endian widths, length-prefixed strings, sorted sets). The
// delegator signature (§3.1) and any digest bind these bytes. The encoding is part of
// the versioned semantics named by ComparatorVersion.
func CanonicalBytes(a Authority, reg *ToolRegistry) ([]byte, error) {
	n := Normalize(a, reg)
	var b bytes.Buffer
	b.WriteString(canonicalPrefix)
	writeStrSet(&b, "scopes", n.Scopes)
	writeStrSet(&b, "tools", n.Tools)
	// resources
	writeField(&b, "resources")
	writeU64(&b, uint64(len(n.Resources)))
	for _, rs := range n.Resources {
		writeStr(&b, rs.Kind)
		writeStr(&b, rs.Value)
	}
	writeStrSet(&b, "classes", n.Classes)
	// spend
	writeField(&b, "spend")
	writeStr(&b, n.Spend.Currency)
	writeU64(&b, n.Spend.Amount)
	// rate
	writeField(&b, "rate")
	writeStr(&b, n.Rate.Per)
	writeU64(&b, n.Rate.Limit)
	// depth
	writeField(&b, "depth")
	writeU64(&b, uint64(n.Depth))
	// validity
	writeField(&b, "validity")
	writeI64(&b, n.Validity.NotBefore)
	writeI64(&b, n.Validity.NotAfter)
	return b.Bytes(), nil
}

func writeField(b *bytes.Buffer, name string) { writeStr(b, name) }

func writeStrSet(b *bytes.Buffer, name string, ss []string) {
	writeField(b, name)
	writeU64(b, uint64(len(ss)))
	for _, s := range ss {
		writeStr(b, s)
	}
}

func writeStr(b *bytes.Buffer, s string) {
	writeU64(b, uint64(len(s)))
	b.WriteString(s)
}

func writeU64(b *bytes.Buffer, v uint64) {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	b.Write(x[:])
}

func writeI64(b *bytes.Buffer, v int64) { writeU64(b, uint64(v)) }

// CanonicalDigest returns the SHA-256 of the canonical bytes of a, routed through the
// internal/crypto AN-3 boundary.
func CanonicalDigest(a Authority, reg *ToolRegistry) ([]byte, error) {
	cb, err := CanonicalBytes(a, reg)
	if err != nil {
		return nil, err
	}
	return crypto.SHA256Sum(cb), nil
}

// WithinParent reports whether child is no broader than parent under the defined
// partial order (child ⊑ parent), after canonical normalization with reg (AGID-claim-3,
// INV-A2 comparator half):
//
//   - scopes, tools, classes: child's normalized set is a subset of parent's;
//   - resources: every child selector is contained by some parent selector (path
//     containment where the algebra supports it, else exact membership);
//   - spend, rate: child <= parent within the same currency/period; a mismatch is
//     incomparable and therefore NOT within (a widening);
//   - depth: child.Depth <= parent.Depth;
//   - validity: child's window nests within parent's.
//
// It is deterministic and versioned (ComparatorVersion). It performs no key
// operation. AGID-04 calls the equivalent check inside the signer to REFUSE a chain
// that widens any dimension (INV-A2's WideningRefused / effective-budget halves are
// exercised there and in EffectiveBudgets).
func WithinParent(child, parent Authority, reg *ToolRegistry) bool {
	c := Normalize(child, reg)
	p := Normalize(parent, reg)

	if !subset(c.Scopes, p.Scopes) {
		return false
	}
	if !subset(c.Tools, p.Tools) {
		return false
	}
	if !subset(c.Classes, p.Classes) {
		return false
	}
	if !resourcesContained(c.Resources, p.Resources) {
		return false
	}
	if !budgetLEQ(c.Spend, p.Spend) {
		return false
	}
	if !rateLEQ(c.Rate, p.Rate) {
		return false
	}
	if c.Depth > p.Depth {
		return false
	}
	if !windowNested(c.Validity, p.Validity) {
		return false
	}
	return true
}

// subset reports whether every element of a (sorted, deduped) is in b.
func subset(a, b []string) bool {
	if len(a) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(b))
	for _, s := range b {
		set[s] = struct{}{}
	}
	for _, s := range a {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

// resourcesContained reports whether every child selector is contained by some parent
// selector. Path selectors use boundary-aware prefix containment; every other kind
// (and cross-kind) uses exact membership.
func resourcesContained(child, parent []ResourceSelector) bool {
	for _, cs := range child {
		if !oneContained(cs, parent) {
			return false
		}
	}
	return true
}

func oneContained(cs ResourceSelector, parent []ResourceSelector) bool {
	for _, ps := range parent {
		if ps.Kind != cs.Kind {
			continue
		}
		if ps.Kind == "path" {
			if pathContains(ps.Value, cs.Value) {
				return true
			}
			continue
		}
		if ps.Value == cs.Value { // exact membership fallback
			return true
		}
	}
	return false
}

// pathContains reports whether outer contains inner as a path prefix with a segment
// boundary, so "/data" contains "/data" and "/data/reports" but not "/database".
func pathContains(outer, inner string) bool {
	if outer == inner {
		return true
	}
	if outer == "/" {
		return strings.HasPrefix(inner, "/")
	}
	return strings.HasPrefix(inner, outer+"/")
}

// budgetLEQ reports whether c <= p within the same currency. Different currencies are
// incomparable (returns false — a widening).
func budgetLEQ(c, p Budget) bool {
	if c.Currency != p.Currency {
		return false
	}
	return c.Amount <= p.Amount
}

// rateLEQ reports whether c <= p within the same period. Different periods are
// incomparable (returns false — a widening).
func rateLEQ(c, p Rate) bool {
	if c.Per != p.Per {
		return false
	}
	return c.Limit <= p.Limit
}

// windowNested reports whether child nests within parent (parent.NotBefore <=
// child.NotBefore and child.NotAfter <= parent.NotAfter).
func windowNested(child, parent Window) bool {
	return parent.NotBefore <= child.NotBefore && child.NotAfter <= parent.NotAfter
}

// ErrEmptyChain is returned when a budget derivation is asked to fold an empty chain.
var ErrEmptyChain = errors.New("delegation: empty chain has no effective budget")

// ErrIncomparableBudget is returned when a chain mixes spend currencies or rate
// periods, so the minimum is not well-defined.
var ErrIncomparableBudget = errors.New("delegation: incomparable budgets in chain (mixed currency or period)")

// EffectiveBudgets returns the effective spend and rate budgets for a delegation
// chain: the MINIMUM of the respective budgets along the chain (AGID-claim-4). The chain
// is ordered root-first, but the minimum fold is order-independent. All spend budgets
// must share a currency and all rate budgets a period; otherwise the minimum is
// undefined and ErrIncomparableBudget is returned. An empty chain returns
// ErrEmptyChain. This derivation performs no key operation.
func EffectiveBudgets(chain []Authority) (Budget, Rate, error) {
	if len(chain) == 0 {
		return Budget{}, Rate{}, ErrEmptyChain
	}
	spend := Budget{Amount: chain[0].Spend.Amount, Currency: normToken(chain[0].Spend.Currency)}
	rate := Rate{Limit: chain[0].Rate.Limit, Per: normToken(chain[0].Rate.Per)}
	for _, a := range chain[1:] {
		cur := normToken(a.Spend.Currency)
		per := normToken(a.Rate.Per)
		if cur != spend.Currency || per != rate.Per {
			return Budget{}, Rate{}, ErrIncomparableBudget
		}
		if a.Spend.Amount < spend.Amount {
			spend.Amount = a.Spend.Amount
		}
		if a.Rate.Limit < rate.Limit {
			rate.Limit = a.Rate.Limit
		}
	}
	return spend, rate, nil
}
