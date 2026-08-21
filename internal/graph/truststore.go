// SPDX-License-Identifier: MPL-2.0

package graph

import (
	"encoding/json"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/crypto/certinfo"
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
	// Host is stamped by the control plane from the reporting agent's verified
	// mTLS identity. It must not come from client-controlled path metadata.
	Host     string `json:"host"`
	Platform string `json:"platform"`
	Browser  string `json:"browser"`
	Profile  string `json:"profile"`
	// Subject is the anchor's display identity as the agent read it. It is only
	// used to expose an unverified candidate when exact public identity is absent;
	// it never authorizes a TRUSTS edge.
	Subject string `json:"subject"`
	// Issuer names the anchor's issuer for a non-self-signed entry.
	Issuer string `json:"issuer"`
	// SPKISHA256 is the stable hash of the anchor's public key. It lets a
	// cross-signed certificate match the same managed CA key even though the two
	// certificate fingerprints differ.
	SPKISHA256   string `json:"spki_sha256"`
	SubjectKeyID string `json:"subject_key_id"`
}

// issuerAnchorIndex is the exact public identity shared by managed issuers and
// discovered trust anchors. Values are slices because a tenant may deliberately
// register aliases for the same public authority; hiding one would make graph
// output depend on insertion order.
type issuerAnchorIndex struct {
	byCertificate map[string][]string
	bySPKI        map[string][]string
	bySubject     map[string][]string
}

func newIssuerAnchorIndex(issuers []store.Issuer) issuerAnchorIndex {
	idx := issuerAnchorIndex{
		byCertificate: map[string][]string{},
		bySPKI:        map[string][]string{},
		bySubject:     map[string][]string{},
	}
	for _, issuer := range issuers {
		nodeID := issuerID(issuer.ID)
		addIssuerAnchorIndex(idx.bySubject, issuer.Name, nodeID)
		info, ok := managedIssuerCertificateInfo(issuer)
		if !ok {
			continue
		}
		addIssuerAnchorIndex(idx.byCertificate, info.SHA256Fingerprint, nodeID)
		addIssuerAnchorIndex(idx.bySPKI, info.SPKISHA256, nodeID)
		addIssuerAnchorIndex(idx.bySubject, info.Subject, nodeID)
	}
	return idx
}

func managedIssuerCertificateInfo(issuer store.Issuer) (certinfo.Info, bool) {
	if issuer.Kind != store.IssuerX509CA || len(issuer.Chain) == 0 {
		return certinfo.Info{}, false
	}
	// The first certificate is the issuer itself. Ancestors are deliberately
	// not indexed: treating a chain root as the intermediate's identity would
	// recreate the same false blast-radius edge one level higher.
	info, err := certinfo.Inspect([]byte(issuer.Chain[0]))
	return info, err == nil
}

func addIssuerAnchorIndex(index map[string][]string, identity, nodeID string) {
	identity = normalizeAnchorIdentity(identity)
	if identity == "" || nodeID == "" {
		return
	}
	for _, existing := range index[identity] {
		if existing == nodeID {
			return
		}
	}
	index[identity] = append(index[identity], nodeID)
}

func normalizeAnchorIdentity(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, ":", "")
	return value
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
func addTrustStoreFinding(g *Graph, f store.DiscoveryFinding, issuers issuerAnchorIndex) bool {
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

	// Historical findings predate the receiver-stamped host. Provenance fallback
	// preserves their visibility, but current reports count one verified machine
	// once even when it carries several stores or anchor paths.
	host := firstNonEmpty(strings.TrimSpace(meta.Host), f.Provenance)
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
		g.AddEdge(Edge{From: resourceID(host), To: storeNode, Type: EdgeHosts, Source: discoverySourceLabel(f), Confidence: "observed"})
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
			"spki_sha256":     meta.SPKISHA256,
			"subject_key_id":  meta.SubjectKeyID,
			"subject":         meta.Subject,
			"issuer":          meta.Issuer,
			"discovery_ref":   f.Ref,
			"provenance":      f.Provenance,
		},
	})
	g.AddEdge(Edge{From: storeNode, To: anchorNode, Type: EdgeTrusts, Source: discoverySourceLabel(f), Confidence: "observed"})

	// Exact public identity is the only authority for TRUSTS. Certificate
	// fingerprint handles the ordinary case; SPKI handles cross-signed copies of
	// the same CA key. A matching subject alone remains visible as a candidate,
	// but it cannot enter authoritative counts, blast-radius automation, H2, or H3.
	exact := map[string]bool{}
	for _, nodeID := range issuers.byCertificate[normalizeAnchorIdentity(f.Fingerprint)] {
		exact[nodeID] = true
	}
	for _, nodeID := range issuers.bySPKI[normalizeAnchorIdentity(meta.SPKISHA256)] {
		exact[nodeID] = true
	}
	for nodeID := range exact {
		g.AddEdge(Edge{From: storeNode, To: nodeID, Type: EdgeTrusts, Source: discoverySourceLabel(f), Confidence: "authoritative"})
	}
	for _, nodeID := range issuers.bySubject[normalizeAnchorIdentity(meta.Subject)] {
		if !exact[nodeID] {
			g.AddEdge(Edge{From: storeNode, To: nodeID, Type: EdgeTrustCandidate, Source: discoverySourceLabel(f), Confidence: "unverified"})
		}
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
	return g.trustStoresForIssuerEdge(issuerNodeID, EdgeTrusts, false)
}

// TrustCandidatesForIssuer returns subject-only correlations that need operator
// confirmation. A store with an exact edge to the same issuer is excluded even
// if it also contains another same-subject anchor.
func (g *Graph) TrustCandidatesForIssuer(issuerNodeID string) (stores []Node, hosts []Node) {
	return g.trustStoresForIssuerEdge(issuerNodeID, EdgeTrustCandidate, true)
}

func (g *Graph) trustStoresForIssuerEdge(issuerNodeID string, edgeType EdgeType, excludeExact bool) (stores []Node, hosts []Node) {
	seenHost := map[string]bool{}
	for _, n := range g.nodes {
		if n.Kind != KindTrustStore {
			continue
		}
		matches := false
		exact := false
		for _, e := range g.out[n.ID] {
			if e.To != issuerNodeID {
				continue
			}
			if e.Type == edgeType {
				matches = true
			}
			if e.Type == EdgeTrusts {
				exact = true
			}
		}
		if !matches || (excludeExact && exact) {
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
