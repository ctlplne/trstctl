// SPDX-License-Identifier: MPL-2.0

package graph

import (
	"encoding/json"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/store"
)

// Promoting trust-store findings to relationships (epic H1).
//
// Agents already collect trust anchors from OS, Java, NSS, browser and Windows
// stores. They landed as flat findings — a row saying "host A's Java cacerts
// contains an anchor with fingerprint X" — and a flat row cannot answer the
// question anyone actually has, which is the inverse: given this CA, WHO trusts
// it, and where do I go to change that.
//
// Answering it needs an edge, not a column. The rollover question ("if I retire
// this root, whose handshakes break?") and the incident question ("this root is
// compromised — what is the blast radius?") are both graph traversals from an
// issuer outward, and neither is expressible over a finding table without the
// caller reimplementing a join by hand.
//
// The modelling choice worth stating: a trust store is its own node rather than
// an attribute of the host. One machine routinely carries several with different
// contents — the OS store, a JVM's cacerts, Firefox's NSS DB — so "is this CA
// trusted on host X" has no single answer, and folding the store into the host
// would force one. Store → issuer records the trust; host → store records where
// to go, and it is that second edge that turns "N stores" into "N stores across
// M hosts".

// trustStoreFindingKind is the discovery source kind agents report anchors under.
// It mirrors internal/agent/discovery.SourceTrustStore; the graph package cannot
// import the agent, and a guard test pins the two together.
const trustStoreFindingKind = "trust-store"

// trustStoreMeta is the subset of a finding's metadata this promotion reads.
type trustStoreMeta struct {
	TrustStoreKind string `json:"trust_store_kind"`
	Platform       string `json:"platform"`
	Browser        string `json:"browser"`
	Profile        string `json:"profile"`
	// Subject is the anchor's subject as the agent read it. It is how an anchor
	// is matched to a known issuer when no fingerprint correspondence exists.
	Subject string `json:"subject"`
	// Issuer names the anchor's issuer for a non-self-signed entry.
	Issuer string `json:"issuer"`
}

// trustStoreNodeID keys a store by the host that reported it and the store's
// own identity.
//
// Both halves are needed. Keying on the store kind alone would merge every
// host's OS store into one node, which is precisely the collapse that makes the
// count meaningless: "trusted by 1 store" when a thousand machines carry it.
func trustStoreNodeID(host, kind, profile string) string {
	parts := []string{"ts", host, kind}
	if profile != "" {
		parts = append(parts, profile)
	}
	return strings.Join(parts, ":")
}

// trustStoreName is what an operator sees on the node.
func trustStoreName(meta trustStoreMeta, host string) string {
	label := meta.TrustStoreKind
	switch {
	case meta.Browser != "":
		label = meta.Browser
	case meta.Platform != "":
		label = meta.Platform + " " + label
	}
	if meta.Profile != "" {
		label += " (" + meta.Profile + ")"
	}
	if host != "" {
		return strings.TrimSpace(label) + " on " + host
	}
	return strings.TrimSpace(label)
}

// addTrustStoreFinding promotes one trust-store finding into nodes and edges.
//
// Returns false when the finding is not a trust-store anchor, so the caller's
// ordinary credential handling still runs for everything else.
func addTrustStoreFinding(g *Graph, f store.DiscoveryFinding, issuerByName map[string]string) bool {
	if f.Kind != trustStoreFindingKind {
		return false
	}
	var meta trustStoreMeta
	if len(f.Metadata) > 0 {
		// Unparseable metadata still yields a store node: the anchor WAS
		// observed, and dropping it because a metadata field was malformed
		// would silently shrink the blast radius an operator is shown.
		_ = json.Unmarshal(f.Metadata, &meta)
	}
	if meta.TrustStoreKind == "" {
		meta.TrustStoreKind = trustStoreFindingKind
	}

	host := f.Provenance
	storeNode := trustStoreNodeID(host, meta.TrustStoreKind, meta.Profile)
	g.AddNode(Node{
		ID:   storeNode,
		Kind: KindTrustStore,
		Name: trustStoreName(meta, host),
		Attrs: map[string]string{
			"trust_store_kind": meta.TrustStoreKind,
			"platform":         meta.Platform,
			"browser":          meta.Browser,
			"profile":          meta.Profile,
			"host":             host,
			"run_id":           f.RunID,
			"source_id":        f.SourceID,
		},
	})
	if host != "" {
		ensureResource(g, host)
		g.AddEdge(Edge{From: resourceID(host), To: storeNode, Type: EdgeHosts})
	}

	// The anchor itself. It is a credential node so existing queries that walk
	// credentials still see it, with the fingerprint that lets an operator match
	// it against a CA they hold.
	anchorNode := "anchor:" + f.ID
	g.AddNode(Node{
		ID:   anchorNode,
		Kind: KindCredential,
		Name: firstNonEmpty(meta.Subject, f.Ref),
		Attrs: map[string]string{
			"credential_kind": "trust-anchor",
			"fingerprint":     f.Fingerprint,
			"subject":         meta.Subject,
			"issuer":          meta.Issuer,
			"discovery_ref":   f.Ref,
			"provenance":      f.Provenance,
		},
	})
	g.AddEdge(Edge{From: storeNode, To: anchorNode, Type: EdgeTrusts})

	// And, when the anchor corresponds to an issuer this tenant knows about, the
	// edge that makes the inverse query answerable: store → issuer.
	//
	// Matching is by NAME, and that deserves saying plainly: it is the only
	// correspondence available, because a discovered anchor carries a subject
	// string and a managed issuer carries a name. A name match is not proof the
	// two are the same key. The edge is therefore a claim about what the estate
	// APPEARS to trust, and an operator confirming a rollover should check the
	// fingerprint — which is why it is on the anchor node.
	if nid, ok := issuerByName[strings.TrimSpace(meta.Subject)]; ok && meta.Subject != "" {
		g.AddEdge(Edge{From: storeNode, To: nid, Type: EdgeTrusts})
	}
	return true
}

// TrustStoresForIssuer answers "who trusts this CA".
//
// It returns the trust-store nodes with a TRUSTS edge to the issuer, plus the
// hosts those stores sit on — the two halves of "trusted by N stores across M
// hosts". Hosts are counted DISTINCTLY, because a host with an OS store and a
// JVM store contributes two stores and one machine to visit.
func (g *Graph) TrustStoresForIssuer(issuerNodeID string) (stores []Node, hosts []Node) {
	seenHost := map[string]bool{}
	for _, n := range g.nodes {
		if n.Kind != KindTrustStore {
			continue
		}
		trusts := false
		for _, e := range g.out[n.ID] {
			if e.Type == EdgeTrusts && e.To == issuerNodeID {
				trusts = true
				break
			}
		}
		if !trusts {
			continue
		}
		stores = append(stores, n)
		host := n.Attrs["host"]
		if host == "" || seenHost[host] {
			continue
		}
		seenHost[host] = true
		if hn, ok := g.nodes[resourceID(host)]; ok {
			hosts = append(hosts, hn)
		}
	}
	sortNodesByID(stores)
	sortNodesByID(hosts)
	return stores, hosts
}

// sortNodesByID gives the trust queries a stable order.
//
// Deterministic output matters more here than usual: these results drive a
// console table and a blast-radius report, and a list that reshuffles between
// polls reads as the estate changing when nothing has.
func sortNodesByID(ns []Node) {
	sort.Slice(ns, func(i, j int) bool { return ns[i].ID < ns[j].ID })
}
