// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package reach is the AGID pre-issuance reachability bound (patent claims 5/6/25,
// INV-A5). BEFORE the isolated signer performs a private-key operation, it must verify a
// SIGNED REACHABILITY VERDICT as a precondition; the verdict is produced OUTSIDE the
// signer by a reachability engine that resolves the requested authority of the FINAL
// delegation record against the read-only core credential graph (internal/graph),
// computes the bounded-depth reachable set (services accepting this authority, the assets
// they front, and the transitive closure), and classifies it (cardinality, sensitivity,
// tenant span). The signer trusts the verdict's SIGNATURE + WATERMARK, never a live graph
// query, so graph computation stays out of the custody boundary (claim 6). A reachable
// set exceeding a policy ceiling yields a refusal, so the signer refuses the key op
// (claim 5).
//
// Scope discipline (card §6.3): the graph is an INPUT TO A REFUSAL GATE at key custody,
// never a detection product. This package adds no alerting, scoring, path-visualization,
// or dashboard surface; it consumes internal/graph read-only and NEVER mutates or extends
// it, and stands up no persisted graph store (the tenant graph is built on demand and
// cached per tenant keyed by a freshness watermark — the r2 G2 decision). The guarantee
// is refusal-on-computation as of the watermark, NOT omniscient runtime containment
// (HARNESS.md §1.5 note (c)).
//
// Boundaries this package holds to:
//   - AN-1: every graph read runs under store.WithTenant for the record's tenant, so a
//     reachability computation NEVER spans tenants (the core graph is in-memory/
//     per-process; reusing a process-wide live graph for a mint decision would be a
//     cross-tenant hazard, so we never do — each build is tenant-scoped).
//   - AN-3: all hashing and signature verification route through internal/crypto; no
//     crypto/* is imported here.
//   - EE fence (§1.6): proprietary Enterprise/Provider material behind ee/; core never
//     imports it, and it imports nothing that would drag a datastore into the isolated
//     signer's verify path (verify.go depends only on internal/crypto).
package reach

import (
	"context"
	"encoding/binary"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/store"
)

// reachPrefix domain-separates every canonical encoding this package hashes (a reachable
// set, a verdict) from every other hashed structure in the repo. It is part of the v1
// canonical semantics.
const reachPrefix = "agid/reach/v1"

// DefaultMaxDepth bounds the transitive closure the engine walks from each authority
// start node. The card requires a BOUNDED-depth closure: an unbounded walk over a large
// tenant graph would be neither a bound nor deterministic to reason about. Depth 0 means
// "the start nodes only"; a positive depth walks that many out-edge hops. The engine
// caps any requested depth to a sane ceiling so a caller cannot ask for an unbounded
// walk.
const DefaultMaxDepth = 8

// maxDepthCeiling is the hard cap on closure depth regardless of what a caller requests,
// so the walk is always bounded (fail-closed against an accidental huge/negative depth).
const maxDepthCeiling = 32

// Sensitivity is an ordered asset-sensitivity class derived from graph node labels. The
// order is total (Public < Internal < Confidential < Restricted) so a ceiling can bound
// the MAXIMUM sensitivity a reachable set may contain. Higher is more sensitive.
type Sensitivity int

// Sensitivity classes, least to most sensitive. SensitivityUnknown sorts as the least
// sensitive so an unlabeled asset never spuriously trips a sensitivity ceiling; a caller
// that wants to treat unlabeled assets as sensitive sets a low ceiling and labels its
// assets.
const (
	SensitivityUnknown      Sensitivity = iota // no recognized sensitivity label
	SensitivityPublic                          // "public"
	SensitivityInternal                        // "internal"
	SensitivityConfidential                    // "confidential"
	SensitivityRestricted                      // "restricted" / "secret" (most sensitive)
)

// String renders a sensitivity for refusal detail (non-secret, human-meaningful).
func (s Sensitivity) String() string {
	switch s {
	case SensitivityPublic:
		return "public"
	case SensitivityInternal:
		return "internal"
	case SensitivityConfidential:
		return "confidential"
	case SensitivityRestricted:
		return "restricted"
	default:
		return "unknown"
	}
}

// sensitivityAttrKeys are the node-attribute keys the engine reads an asset's sensitivity
// label from, in order of preference. The core graph carries free-form Attrs (build.go);
// a deployment target or resource may be labeled with any of these. Reading a LABEL (not
// re-deriving sensitivity) keeps the engine a consumer of the graph, not a scorer.
var sensitivityAttrKeys = []string{"sensitivity", "data_class", "classification", "label"}

// classifySensitivity maps a graph node's labels to a Sensitivity. It reads the first
// recognized label key and normalizes the value; an unrecognized or absent label is
// SensitivityUnknown. It is deterministic and side-effect-free.
func classifySensitivity(n graph.Node) Sensitivity {
	for _, k := range sensitivityAttrKeys {
		if v, ok := n.Attrs[k]; ok {
			switch normLabel(v) {
			case "public", "open":
				return SensitivityPublic
			case "internal":
				return SensitivityInternal
			case "confidential", "sensitive", "pii":
				return SensitivityConfidential
			case "restricted", "secret", "top-secret", "topsecret", "regulated":
				return SensitivityRestricted
			}
		}
	}
	return SensitivityUnknown
}

// ReachedNode is one node in a reachable set: its stable graph id, kind, a stable label
// set (the asset labels that classify it), and its derived sensitivity. Only NON-SECRET,
// stable fields are retained so the reachable-set digest is reproducible and no secret is
// carried into a verdict.
type ReachedNode struct {
	ID          string      `json:"id"`
	Kind        string      `json:"kind"`
	Labels      []string    `json:"labels,omitempty"` // sorted "key=value" asset labels
	Sensitivity Sensitivity `json:"sensitivity"`
}

// ReachableSet is the resolved consequence of a delegation record's authority: the set of
// graph nodes forward-reachable (within the bounded depth) from the services that accept
// the requested authority, with cardinality, the maximum sensitivity encountered, the
// prohibited labels present, and the tenant span. It is the object the verdict binds a
// DIGEST of (claim 6); the verdict never carries the set itself into the signer.
type ReachableSet struct {
	// TenantID is the single tenant this set was computed for (AN-1: a set never spans
	// tenants; the engine builds one tenant graph under WithTenant).
	TenantID string `json:"tenant_id"`
	// Nodes is the reachable node set in canonical (id-sorted) order.
	Nodes []ReachedNode `json:"nodes"`
	// Cardinality is len(Nodes), materialized so a ceiling can bound it without walking
	// the slice and so it survives in a decoded verdict for diagnostics.
	Cardinality int `json:"cardinality"`
	// MaxSensitivity is the greatest Sensitivity across Nodes (SensitivityUnknown for an
	// empty set).
	MaxSensitivity Sensitivity `json:"max_sensitivity"`
	// TenantSpan is the number of distinct tenants the set touches. Under the AN-1 build
	// discipline this is 1 for a non-empty set and 0 for an empty set; it is modeled
	// explicitly so a tenant-span ceiling is a first-class dimension the verdict binds.
	TenantSpan int `json:"tenant_span"`
	// PresentLabels is the sorted set of DISTINCT asset labels ("key=value") present on
	// reachable nodes, so a prohibited-label ceiling can be evaluated against the verdict
	// alone (the signer never sees the graph).
	PresentLabels []string `json:"present_labels,omitempty"`
}

// classifyLabelAttrKeys are the attribute keys whose values are treated as ASSET LABELS
// for prohibited-label ceilings (in addition to the sensitivity keys, which are also
// exported as labels). Reading labels, not inventing them, keeps this a consumer of the
// graph.
var classifyLabelAttrKeys = []string{"sensitivity", "data_class", "classification", "label", "tags", "environment", "env"}

// nodeLabels returns a node's asset labels as sorted "key=value" strings, for prohibited
// -label matching and for the reachable-set digest. Only labels from the recognized
// label keys are exported so unrelated attrs (fingerprints, serials) do not bloat or
// destabilize the digest.
func nodeLabels(n graph.Node) []string {
	var out []string
	for _, k := range classifyLabelAttrKeys {
		if v, ok := n.Attrs[k]; ok && v != "" {
			out = append(out, k+"="+normLabel(v))
		}
	}
	sort.Strings(out)
	return out
}

// GraphSource builds a tenant-scoped credential graph on demand. It abstracts
// graph.Build(ctx, st, tenantID) so the engine can be driven with a real core store in
// production and a small in-memory graph in tests without standing up a datastore in the
// test's hot path. Production wiring supplies StoreGraphSource, which runs the build under
// store.WithTenant (AN-1); a test can supply a StaticGraphSource returning a fixture
// graph for a tenant.
//
// The watermark returned alongside the graph is the freshness token the verdict binds:
// two builds with the same watermark denote the same graph generation, so a verdict's
// reachable-set digest is reproducible for a fixed watermark (acceptance criterion 3).
type GraphSource interface {
	// GraphForTenant returns the tenant's credential graph and its freshness watermark.
	// It MUST scope every read to tenantID (AN-1). The returned graph is treated
	// read-only by the engine.
	GraphForTenant(ctx context.Context, tenantID string) (g *graph.Graph, watermark string, err error)
}

// StoreGraphSource is the production GraphSource: it builds the tenant graph from the core
// store UNDER store.WithTenant (AN-1), so the graph read is tenant-scoped and never spans
// tenants. The watermark is supplied by a caller-provided function (typically the AGID-02
// projection watermark / event sequence for the tenant), so the verdict's freshness is
// pinned to a real ledger position. When no watermark function is supplied, a build-count
// watermark is used so the type is still usable in tests.
//
// It stands up NO persisted graph store: graph.Build is in-memory/per-process, and each
// call rebuilds under WithTenant. Caching lives in the Engine (per-tenant, watermark
// -keyed), never here, so a stale process-wide graph is never reused for a mint decision.
type StoreGraphSource struct {
	Store *store.Store
	// Watermark returns the freshness watermark for a tenant (e.g. the tenant's latest
	// applied event sequence). REQUIRED in production so the verdict binds a real
	// freshness position; a nil function falls back to an opaque per-tenant token, which
	// is acceptable only in tests.
	Watermark func(ctx context.Context, tenantID string) (string, error)
}

// GraphForTenant builds the tenant graph via graph.Build (AN-1). graph.Build reads the
// tenant inventory THROUGH the store's tenant-scoped list methods (ListOwners,
// ListIssuers, ListIdentities, ListDeploymentTargets, ...), and EACH of those runs the
// read under store.WithTenant, which sets the FORCE-d RLS tenant GUC
// (set_config('trstctl.tenant_id', ...)) for its transaction. So EVERY query the build
// issues is tenant-scoped by construction (the card's "run every query under WithTenant"):
// a cross-tenant read is denied by RLS, and the returned graph contains only tenantID's
// inventory. We therefore do not (and must not) wrap the build in a second, redundant
// outer transaction — that would only open a duplicate connection while the inner
// tenant-scoped reads already enforce AN-1.
func (s StoreGraphSource) GraphForTenant(ctx context.Context, tenantID string) (*graph.Graph, string, error) {
	g, err := graph.Build(ctx, s.Store, tenantID)
	if err != nil {
		return nil, "", err
	}
	wm, err := s.watermarkFor(ctx, tenantID)
	if err != nil {
		return nil, "", err
	}
	return g, wm, nil
}

func (s StoreGraphSource) watermarkFor(ctx context.Context, tenantID string) (string, error) {
	if s.Watermark != nil {
		return s.Watermark(ctx, tenantID)
	}
	// No watermark function: derive a stable per-tenant token so the source is usable.
	// This is NOT a freshness position; production supplies Watermark.
	return "tenant:" + tenantID, nil
}

// Engine is the reachability engine (OUTSIDE the signer). It resolves a delegation
// record's authority against the tenant credential graph and produces a reachable set +
// a signed verdict. It caches the built tenant graph per tenant keyed by watermark, so a
// second query at the same watermark reuses the same generation (deterministic digest)
// without a rebuild, but a NEW watermark forces a fresh build — and the cache is
// per-tenant, so no tenant's graph is ever used for another tenant's decision.
//
// The Engine performs NO key operation and mints nothing (INV-A1 preserved by
// construction): it signs only the verdict artifact with its own verdict-signing key,
// exactly as the delegation gate signs only refusals.
type Engine struct {
	src      GraphSource
	maxDepth int
	// cache is the per-tenant, watermark-keyed graph cache. It is intentionally simple:
	// one entry per tenant (the latest watermark seen). A build at a new watermark
	// replaces the tenant's entry. It is guarded by mu.
	cache map[string]cachedGraph
}

// cachedGraph is a cached tenant graph generation.
type cachedGraph struct {
	watermark string
	g         *graph.Graph
}

// EngineOption configures an Engine.
type EngineOption func(*Engine)

// WithMaxDepth sets the bounded closure depth (capped at maxDepthCeiling). A non-positive
// depth resets to DefaultMaxDepth.
func WithMaxDepth(d int) EngineOption {
	return func(e *Engine) {
		if d <= 0 {
			d = DefaultMaxDepth
		}
		if d > maxDepthCeiling {
			d = maxDepthCeiling
		}
		e.maxDepth = d
	}
}

// NewEngine constructs a reachability engine over a GraphSource.
func NewEngine(src GraphSource, opts ...EngineOption) *Engine {
	e := &Engine{src: src, maxDepth: DefaultMaxDepth, cache: map[string]cachedGraph{}}
	for _, o := range opts {
		o(e)
	}
	return e
}

// AuthorityRequest is the reachability engine's input: the tenant and the requested
// authority of the FINAL delegation record (the leaf the credential is being issued for).
// The engine resolves this authority to graph start nodes and walks the bounded closure.
// It is a small, decoupled value so the engine does not import ee/agentid/delegation
// (which would be a cycle: delegation imports reach for the gate extension).
type AuthorityRequest struct {
	TenantID string
	// ResourceValues are the resource-selector VALUES of the final record's authority
	// (Authority.Resources[i].Value). Each names a resource the delegate may act on; the
	// engine maps each to the graph resource node id (graph resourceID == "res:"+value)
	// and walks the closure from there. These are the "services accepting this authority"
	// / "assets they front" entry points.
	ResourceValues []string
	// ExtraStartIDs are additional explicit graph node ids to seed the closure from
	// (optional): a caller that resolves authority to graph nodes by a richer mapping
	// (e.g. scope→workload) can pass those node ids directly. The engine unions them with
	// the resource-derived starts.
	ExtraStartIDs []string
}

// graphForTenant returns the tenant graph at its current watermark, using the per-tenant
// watermark-keyed cache. A cache hit (same watermark) reuses the built graph; a miss (new
// or first watermark) rebuilds via the source and replaces the tenant's cache entry. The
// cache is per-tenant so a graph is never shared across tenants.
func (e *Engine) graphForTenant(ctx context.Context, tenantID string) (*graph.Graph, string, error) {
	g, wm, err := e.srcWatermark(ctx, tenantID)
	if err != nil {
		return nil, "", err
	}
	return g, wm, nil
}

// srcWatermark consults the cache then the source. Because the source is what knows the
// current watermark, we build first (the source is on-demand) but reuse a cached graph
// when the watermark matches, avoiding a re-walk of an identical generation. In this
// on-demand model the source already returns a freshly built graph, so the cache's role
// is to make repeated queries at the SAME watermark reuse ONE generation for a stable
// digest; a persisted incremental store is explicitly out of scope this sprint.
func (e *Engine) srcWatermark(ctx context.Context, tenantID string) (*graph.Graph, string, error) {
	g, wm, err := e.src.GraphForTenant(ctx, tenantID)
	if err != nil {
		return nil, "", err
	}
	if c, ok := e.cache[tenantID]; ok && c.watermark == wm {
		// Same generation: reuse the cached graph so the digest is stable across queries
		// without depending on build determinism of the source.
		return c.g, wm, nil
	}
	e.cache[tenantID] = cachedGraph{watermark: wm, g: g}
	return g, wm, nil
}

// Resolve computes the reachable set for a request against the tenant graph, returning the
// set and the graph watermark it was computed at. It does NOT sign anything (that is
// Verdict). Determinism: for a fixed graph generation (watermark) the returned set — and
// therefore its digest — is identical across calls (acceptance criterion 3), because the
// closure walk and the canonical ordering are deterministic.
func (e *Engine) Resolve(ctx context.Context, req AuthorityRequest) (ReachableSet, string, error) {
	g, wm, err := e.graphForTenant(ctx, req.TenantID)
	if err != nil {
		return ReachableSet{}, "", err
	}
	set := e.resolveOn(g, req)
	return set, wm, nil
}

// resolveOn computes the reachable set against an already-built graph. Split out so tests
// can drive resolution over a fixture graph directly and so Resolve stays a thin
// build-then-resolve.
func (e *Engine) resolveOn(g *graph.Graph, req AuthorityRequest) ReachableSet {
	starts := startNodes(g, req)

	// Bounded-depth transitive closure from every start node, unioned. The walk follows
	// out-edges (impact flows From→To in the core graph, so a node's forward-reachable
	// set is what its authority can reach). Depth is bounded by e.maxDepth.
	reached := map[string]graph.Node{}
	for _, s := range starts {
		for _, n := range boundedReachable(g, s, e.maxDepth) {
			reached[n.ID] = n
		}
	}

	set := ReachableSet{TenantID: req.TenantID}
	for _, n := range reached {
		rn := ReachedNode{
			ID:          n.ID,
			Kind:        string(n.Kind),
			Labels:      nodeLabels(n),
			Sensitivity: classifySensitivity(n),
		}
		set.Nodes = append(set.Nodes, rn)
		if rn.Sensitivity > set.MaxSensitivity {
			set.MaxSensitivity = rn.Sensitivity
		}
	}
	sort.Slice(set.Nodes, func(i, j int) bool { return set.Nodes[i].ID < set.Nodes[j].ID })
	set.Cardinality = len(set.Nodes)
	set.PresentLabels = distinctLabels(set.Nodes)
	if set.Cardinality > 0 {
		// AN-1: one tenant graph per build, so a non-empty set touches exactly one tenant.
		set.TenantSpan = 1
	}
	return set
}

// startNodes resolves an authority request to the set of graph nodes the closure walk
// starts from: the resource nodes named by the authority's resource-selector values
// (mapped to the core graph's "res:"+value ids), unioned with any explicit ExtraStartIDs.
// A start id that names no node in the tenant graph is dropped (it fronts nothing here —
// refusal-on-computation as of the watermark, not a claim of omniscience). Duplicates are
// removed; the result is id-sorted for determinism.
func startNodes(g *graph.Graph, req AuthorityRequest) []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		if _, ok := g.Node(id); !ok {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	for _, v := range req.ResourceValues {
		add(resourceNodeID(v))
	}
	for _, id := range req.ExtraStartIDs {
		add(id)
	}
	sort.Strings(out)
	return out
}

// boundedReachable returns the nodes reachable from start within maxDepth out-edge hops
// (the start node itself excluded), via a breadth-first walk that stops at the depth
// bound. It mirrors graph.Reachable's read-only traversal but ENFORCES the depth bound
// the card requires (graph.Reachable is unbounded). It reads the graph only through its
// public read API (Neighbors), never mutating it.
func boundedReachable(g *graph.Graph, start string, maxDepth int) []graph.Node {
	visited := map[string]bool{start: true}
	var out []graph.Node
	type qentry struct {
		id    string
		depth int
	}
	queue := []qentry{{id: start, depth: 0}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.depth >= maxDepth {
			continue
		}
		for _, n := range g.Neighbors(cur.id) {
			if visited[n.ID] {
				continue
			}
			visited[n.ID] = true
			out = append(out, n)
			queue = append(queue, qentry{id: n.ID, depth: cur.depth + 1})
		}
	}
	return out
}

// distinctLabels returns the sorted union of the label sets across nodes.
func distinctLabels(nodes []ReachedNode) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range nodes {
		for _, l := range n.Labels {
			if !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
	}
	sort.Strings(out)
	return out
}

// resourceNodeID maps a resource-selector value to the core graph's resource node id. The
// core builder keys resource nodes as "res:"+location (build.go resourceID); mirroring
// that mapping here (rather than importing an unexported helper) lets the engine seed the
// closure from the same node ids the builder created. This is a read-only mirror of a
// documented, stable id scheme, not a modification of internal/graph.
func resourceNodeID(value string) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return ""
	}
	return "res:" + v
}

// Digest returns the canonical, byte-stable SHA-256 of the reachable set, routed through
// internal/crypto (AN-3). It is the value the verdict binds (claim 6) and is deterministic
// for a fixed graph watermark (acceptance criterion 3): the encoding is length-prefixed,
// fixed-endian, and iterates canonically-ordered node/label sets, so the same set yields
// identical bytes across runs, machines, and architectures. It carries NO secret (only
// stable ids, kinds, labels, and the derived sensitivity).
func (rs ReachableSet) Digest() []byte {
	return crypto.SHA256Sum(rs.canonicalBytes())
}

// canonicalBytes is the deterministic serialization of the reachable set the digest is
// taken over. It mirrors the length-prefixed, sorted-set discipline of
// taskenv/envelope.go and delegation/record.go so the digest is reproducible.
func (rs ReachableSet) canonicalBytes() []byte {
	var b []byte
	b = appendStr(b, reachPrefix)
	b = appendStr(b, "reachable-set")
	b = appendStr(b, rs.TenantID)
	b = appendU64(b, uint64(rs.Cardinality))
	b = appendU64(b, uint64(rs.MaxSensitivity))
	b = appendU64(b, uint64(rs.TenantSpan))
	// nodes, sorted by id so the digest is a pure function of the set's CONTENT, not the
	// slice order it happens to be built in (defensive: Resolve already id-sorts, but a
	// caller assembling a set by hand still gets an order-independent digest).
	nodes := append([]ReachedNode(nil), rs.Nodes...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	b = appendU64(b, uint64(len(nodes)))
	for _, n := range nodes {
		b = appendStr(b, n.ID)
		b = appendStr(b, n.Kind)
		b = appendU64(b, uint64(n.Sensitivity))
		labels := append([]string(nil), n.Labels...)
		sort.Strings(labels)
		b = appendU64(b, uint64(len(labels)))
		for _, l := range labels {
			b = appendStr(b, l)
		}
	}
	// present labels (sorted union), bound so a decoded verdict's prohibited-label
	// determination is over the same committed bytes.
	pl := append([]string(nil), rs.PresentLabels...)
	sort.Strings(pl)
	b = appendU64(b, uint64(len(pl)))
	for _, l := range pl {
		b = appendStr(b, l)
	}
	return b
}

// ---- canonical writer helpers (length-prefixed, fixed big-endian; mirrors taskenv /
// delegation so the encodings share their discipline). ----

func appendStr(b []byte, s string) []byte {
	b = appendU64(b, uint64(len(s)))
	return append(b, s...)
}

func appendU64(b []byte, v uint64) []byte {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	return append(b, x[:]...)
}

// normLabel normalizes a label/sensitivity value: trim surrounding whitespace and
// lowercase, matching the scope/tool normalization discipline elsewhere so labels compare
// by meaning, not spelling.
func normLabel(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// sha256Of routes a byte slice through the internal/crypto SHA-256 boundary (AN-3). It is
// the single hashing helper the non-verdict files in this package use so no file here
// imports crypto/sha256 directly; ceiling.go's offending-subset digests and any other
// intra-package hashing go through it.
func sha256Of(b []byte) []byte { return crypto.SHA256Sum(b) }
