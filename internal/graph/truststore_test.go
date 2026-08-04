// SPDX-License-Identifier: MPL-2.0

package graph

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/store"
)

// Trust as a relationship, not a row (epic H1).
//
// The agents already collected these anchors; they landed as flat findings, and
// a flat finding cannot answer the question anyone has — which is the INVERSE
// one. "Host A's cacerts contains fingerprint X" is a row. "Given this CA, who
// trusts it and where do I go to change that" is a traversal, and it is what
// both a rollover and an incident actually ask.

func anchorFinding(id, host, storeKind, profile, subject, fingerprint string) store.DiscoveryFinding {
	meta, _ := json.Marshal(map[string]string{
		"trust_store_kind": storeKind,
		"profile":          profile,
		"subject":          subject,
		"platform":         "linux",
	})
	return store.DiscoveryFinding{
		ID: id, Kind: "trust-store", Ref: subject, Provenance: host,
		Fingerprint: fingerprint, Metadata: meta,
	}
}

// The graph package hard-codes the finding kind because it cannot import the
// agent. If the two drift, every anchor silently becomes an ordinary credential
// row again and the trust edges quietly vanish — the failure is invisible.
func TestTheTrustStoreFindingKindMatchesWhatAgentsReport(t *testing.T) {
	t.Parallel()
	if trustStoreFindingKind != discovery.SourceTrustStore {
		t.Fatalf("graph expects finding kind %q but agents report %q; every trust anchor would "+
			"fall through to the generic credential path and the TRUSTS edges would disappear "+
			"without any test failing", trustStoreFindingKind, discovery.SourceTrustStore)
	}
}

func TestAnAnchorBecomesTrustEdgesFromItsStoreAndHost(t *testing.T) {
	t.Parallel()
	g := New()
	issuerByName := map[string]string{"Corp Root CA": issuerID("iss-1")}
	g.AddNode(Node{ID: issuerID("iss-1"), Kind: KindIssuer, Name: "Corp Root CA"})

	if !addTrustStoreFinding(g, anchorFinding("f1", "web01", "java-cacerts", "", "Corp Root CA", "aa"), issuerByName) {
		t.Fatal("a trust-store finding was not recognized as one")
	}

	stores, hosts := g.TrustStoresForIssuer(issuerID("iss-1"))
	if len(stores) != 1 {
		t.Fatalf("stores trusting the CA = %d, want 1", len(stores))
	}
	if len(hosts) != 1 || hosts[0].Name != "web01" {
		t.Fatalf("hosts = %+v, want the machine that reported it", hosts)
	}
	// The host→store edge is what makes "where do I go" answerable.
	found := false
	for _, e := range g.Edges() {
		if e.Type == EdgeHosts && e.From == resourceID("web01") {
			found = true
		}
	}
	if !found {
		t.Error("no HOSTS edge from the machine to its trust store; the store would float free " +
			"of the host an operator has to visit")
	}
}

// One machine carries several stores with DIFFERENT contents. Folding them into
// the host would force a single answer to a question that has none.
func TestStoresOnOneHostStayDistinct(t *testing.T) {
	t.Parallel()
	g := New()
	issuerByName := map[string]string{"Corp Root CA": issuerID("iss-1")}
	g.AddNode(Node{ID: issuerID("iss-1"), Kind: KindIssuer, Name: "Corp Root CA"})

	// The OS store and the JVM's cacerts on the SAME host, both carrying the CA.
	addTrustStoreFinding(g, anchorFinding("f1", "web01", "os", "", "Corp Root CA", "aa"), issuerByName)
	addTrustStoreFinding(g, anchorFinding("f2", "web01", "java-cacerts", "", "Corp Root CA", "aa"), issuerByName)

	stores, hosts := g.TrustStoresForIssuer(issuerID("iss-1"))
	if len(stores) != 2 {
		t.Errorf("stores = %d, want 2; a host's OS store and its JVM cacerts are different "+
			"places with different contents, and collapsing them hides one", len(stores))
	}
	// But it is ONE machine to visit.
	if len(hosts) != 1 {
		t.Errorf("hosts = %d, want 1; two stores on one box is one machine to go to", len(hosts))
	}
}

// The same store kind on DIFFERENT hosts must not merge — that collapse is what
// would make the count meaningless ("trusted by 1 store" across a fleet).
func TestTheSameStoreKindOnDifferentHostsDoesNotMerge(t *testing.T) {
	t.Parallel()
	g := New()
	issuerByName := map[string]string{"Corp Root CA": issuerID("iss-1")}
	g.AddNode(Node{ID: issuerID("iss-1"), Kind: KindIssuer, Name: "Corp Root CA"})

	for _, host := range []string{"web01", "web02", "web03"} {
		addTrustStoreFinding(g, anchorFinding("f-"+host, host, "os", "", "Corp Root CA", "aa"), issuerByName)
	}
	stores, hosts := g.TrustStoresForIssuer(issuerID("iss-1"))
	if len(stores) != 3 || len(hosts) != 3 {
		t.Fatalf("stores=%d hosts=%d, want 3 and 3; merging one store kind across a fleet would "+
			"report a blast radius of one machine for a change that breaks all of them",
			len(stores), len(hosts))
	}
}

// An anchor for a CA this tenant does not manage still becomes a node — the
// estate trusts it, and that is worth seeing — but it produces no issuer edge,
// because there is no issuer to point at.
func TestAnUnmanagedAnchorIsRecordedWithoutAnIssuerEdge(t *testing.T) {
	t.Parallel()
	g := New()
	issuerByName := map[string]string{}

	addTrustStoreFinding(g, anchorFinding("f1", "web01", "os", "", "Some Public CA", "bb"), issuerByName)

	var anchors int
	for _, n := range g.Nodes() {
		if n.Kind == KindCredential && n.Attrs["credential_kind"] == "trust-anchor" {
			anchors++
			if n.Attrs["fingerprint"] != "bb" {
				t.Errorf("anchor fingerprint = %q; it is what lets an operator confirm identity "+
					"beyond a name match", n.Attrs["fingerprint"])
			}
		}
	}
	if anchors != 1 {
		t.Errorf("anchors recorded = %d, want 1; an anchor for an unmanaged CA is still "+
			"something the estate trusts", anchors)
	}
	// No issuer node exists, so nothing claims a correspondence.
	if stores, _ := g.TrustStoresForIssuer(issuerID("iss-1")); len(stores) != 0 {
		t.Error("an unmanaged anchor produced a trust edge to an issuer that does not exist")
	}
}

// Malformed metadata must not silently shrink the blast radius.
func TestUnparseableMetadataStillRecordsTheStore(t *testing.T) {
	t.Parallel()
	g := New()
	f := store.DiscoveryFinding{
		ID: "f1", Kind: "trust-store", Ref: "anchor", Provenance: "web01",
		Fingerprint: "cc", Metadata: json.RawMessage(`{not json`),
	}
	if !addTrustStoreFinding(g, f, map[string]string{}) {
		t.Fatal("a trust-store finding with bad metadata was not recognized")
	}
	var stores int
	for _, n := range g.Nodes() {
		if n.Kind == KindTrustStore {
			stores++
		}
	}
	if stores != 1 {
		t.Errorf("stores = %d, want 1; the anchor WAS observed, and dropping it because a "+
			"metadata field was malformed would quietly understate what the estate trusts", stores)
	}
}

// Non-trust findings still take the ordinary path.
func TestOrdinaryFindingsAreNotPromoted(t *testing.T) {
	t.Parallel()
	g := New()
	f := store.DiscoveryFinding{ID: "f1", Kind: "filesystem", Ref: "/etc/ssl/x.pem"}
	if addTrustStoreFinding(g, f, map[string]string{}) {
		t.Fatal("a filesystem finding was promoted to a trust store")
	}
	if len(g.Nodes()) != 0 {
		t.Error("a non-trust finding produced graph nodes on the trust path")
	}
}
