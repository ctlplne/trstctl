// SPDX-License-Identifier: BUSL-1.1

// Package engine is the OUTSIDE-the-signer half of the AGID pre-issuance reachability
// bound (patent AGID-claims-5/6/25, INV-A5): the reachability engine that resolves the
// requested authority of the FINAL delegation record against the read-only core
// credential graph (internal/graph), computes the bounded-depth reachable set (services
// accepting this authority, the assets they front, and the transitive closure), and
// classifies it (cardinality, sensitivity, tenant span), then emits a SIGNED REACHABILITY
// VERDICT the isolated signer verifies as a precondition.
//
// This package is deliberately split OUT of package internal/agentid/reach so the graph/store
// dependency stays OUT of the signer's dependency closure (AN-4). Package reach holds the
// crypto-only verdict/ceiling/verify surface the signer-linked delegation gate uses and
// imports ONLY internal/crypto; the graph computation (which pulls internal/graph +
// internal/store, and transitively database/sql, pgx, NATS, and net/http) lives HERE, in a
// package NOTHING on the signer path imports. The shared reachable-set / verdict / ceiling
// types live in package reach and are referenced from here qualified (reach.ReachableSet,
// reach.Verdict, reach.Ceiling, ...), so both this engine and the in-signer verify path
// agree on the wire types without the signer ever linking a datastore.
//
// Boundaries this package holds to (unchanged from the AGID-06 design):
//   - AN-1: every graph read runs under store.WithTenant for the record's tenant, so a
//     reachability computation NEVER spans tenants (the core graph is in-memory/
//     per-process; reusing a process-wide live graph for a mint decision would be a
//     cross-tenant hazard, so we never do — each build is tenant-scoped).
//   - AN-3: all hashing and signature verification route through internal/crypto (via the
//     reach package's helpers); no crypto/* is imported here.
//   - Scope discipline (card §6.3): the graph is an INPUT TO A REFUSAL GATE at key custody,
//     never a detection product. This package adds no alerting, scoring, path-visualization,
//     or dashboard surface; it consumes internal/graph read-only and NEVER mutates or
//     extends it, and stands up no persisted graph store (the tenant graph is built on
//     demand and cached per tenant keyed by a freshness watermark). The guarantee is
//     refusal-on-computation as of the watermark, NOT omniscient runtime containment.
//   - EE fence (§1.6): proprietary Enterprise/Provider material behind ee/; core never
//     imports it, and package reach (the signer-linked half) imports nothing that would
//     drag a datastore into the isolated signer's verify path.
package engine

import (
	"context"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/agentid/reach"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/store"
)

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

// sensitivityAttrKeys are the node-attribute keys the engine reads an asset's sensitivity
// label from, in order of preference. The core graph carries free-form Attrs (build.go);
// a deployment target or resource may be labeled with any of these. Reading a LABEL (not
// re-deriving sensitivity) keeps the engine a consumer of the graph, not a scorer.
var sensitivityAttrKeys = []string{"sensitivity", "data_class", "classification", "label"}

// classifySensitivity maps a graph node's labels to a reach.Sensitivity. It reads the first
// recognized label key and normalizes the value; an unrecognized or absent label is
// reach.SensitivityUnknown. It is deterministic and side-effect-free.
func classifySensitivity(n graph.Node) reach.Sensitivity {
	for _, k := range sensitivityAttrKeys {
		if v, ok := n.Attrs[k]; ok {
			switch normLabel(v) {
			case "public", "open":
				return reach.SensitivityPublic
			case "internal":
				return reach.SensitivityInternal
			case "confidential", "sensitive", "pii":
				return reach.SensitivityConfidential
			case "restricted", "secret", "top-secret", "topsecret", "regulated":
				return reach.SensitivityRestricted
			}
		}
	}
	return reach.SensitivityUnknown
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
// store.WithTenant (AN-1); a test can supply a static GraphSource returning a fixture
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
	// replaces the tenant's entry. It is guarded by nothing here (single-goroutine use per
	// the AGID-06 design; a concurrent caller wraps its own synchronization).
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
// It is a small, decoupled value so the engine does not import internal/agentid/delegation
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
// ProduceVerdict). Determinism: for a fixed graph generation (watermark) the returned
// set — and therefore its digest — is identical across calls (acceptance criterion 3),
// because the closure walk and the canonical ordering are deterministic.
func (e *Engine) Resolve(ctx context.Context, req AuthorityRequest) (reach.ReachableSet, string, error) {
	g, wm, err := e.graphForTenant(ctx, req.TenantID)
	if err != nil {
		return reach.ReachableSet{}, "", err
	}
	set := e.resolveOn(g, req)
	return set, wm, nil
}

// resolveOn computes the reachable set against an already-built graph. Split out so tests
// can drive resolution over a fixture graph directly and so Resolve stays a thin
// build-then-resolve.
func (e *Engine) resolveOn(g *graph.Graph, req AuthorityRequest) reach.ReachableSet {
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

	set := reach.ReachableSet{TenantID: req.TenantID}
	for _, n := range reached {
		rn := reach.ReachedNode{
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
	set.PresentLabels = reach.DistinctLabels(set.Nodes)
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

// ProduceVerdict is the engine's end-to-end OUTSIDE-the-signer path (AGID-claims-5/6): resolve
// the reachable set for a request, evaluate it against the requester class's ceiling, and
// return a SIGNED verdict binding the reachable-set digest, the ceiling determination, and
// the graph watermark. class selects the ceiling; a class with no configured ceiling is a
// fail-closed refusal determination (Exceeded with a named cardinality violation carrying
// the whole-set digest), so a verdict is ALWAYS produced (the signer then refuses on the
// Exceeded determination) rather than silently allowing an unbounded reach.
//
// subjectDigest binds the verdict to the exact authority it was computed for (the
// final-record authority digest); the signer requires it to match. issuedAt/key/signer
// come from the engine's signing context. It performs NO issuance key operation and mints
// nothing. The fail-closed ceiling determination and the verdict assembly live in package
// reach (crypto-only) so the signer's verify path shares the exact same semantics without
// linking a datastore.
func (e *Engine) ProduceVerdict(ctx context.Context, req AuthorityRequest, class string, policy *reach.CeilingPolicy, subjectDigest []byte, issuedAt int64, key reach.VerdictKeyRef, signer crypto.Signer) (reach.Verdict, error) {
	set, wm, err := e.Resolve(ctx, req)
	if err != nil {
		return reach.Verdict{}, err
	}
	det := reach.DetermineOrFailClosed(set, class, policy)
	v := reach.NewVerdict(set, det, wm, subjectDigest, issuedAt, key)
	return v.Sign(signer)
}

// normLabel normalizes a label/sensitivity value: trim surrounding whitespace and
// lowercase, matching the scope/tool normalization discipline elsewhere so labels compare
// by meaning, not spelling. A local copy of package reach's normalization keeps this
// package's classification independent of an exported helper.
func normLabel(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
