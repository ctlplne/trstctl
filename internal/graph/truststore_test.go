// SPDX-License-Identifier: MPL-2.0

package graph

import (
	"encoding/json"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/discovery"
	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
	"trstctl.com/trstctl/internal/crypto/certinfo"
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

func anchorFindingWithSPKI(id, host, storeKind, profile, subject, fingerprint, spki string) store.DiscoveryFinding {
	f := anchorFinding(id, host, storeKind, profile, subject, fingerprint)
	var meta map[string]string
	_ = json.Unmarshal(f.Metadata, &meta)
	meta["spki_sha256"] = spki
	f.Metadata, _ = json.Marshal(meta)
	return f
}

func testIssuerAnchorIndex(name, nodeID, fingerprint, spki string) issuerAnchorIndex {
	idx := issuerAnchorIndex{byCertificate: map[string][]string{}, bySPKI: map[string][]string{}, bySubject: map[string][]string{}}
	addIssuerAnchorIndex(idx.byCertificate, fingerprint, nodeID)
	addIssuerAnchorIndex(idx.bySPKI, spki, nodeID)
	addIssuerAnchorIndex(idx.bySubject, name, nodeID)
	return idx
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

// AUD-43: a display name is not a key identity. Two unrelated roots may use the
// same subject, so a subject-only correlation must never enter the authoritative
// TRUSTS set consumed by rollover and incident automation.
func TestSameSubjectDifferentFingerprintIsNotAuthoritativeTrustAUD43(t *testing.T) {
	t.Parallel()
	g := New()
	issuer := issuerID("managed-ca")
	g.AddNode(Node{ID: issuer, Kind: KindIssuer, Name: "Corp Root CA", Attrs: map[string]string{
		"certificate_fingerprint": "aa",
	}})

	addTrustStoreFinding(g, anchorFinding("f1", "web01", "os", "", "Corp Root CA", "bb"),
		testIssuerAnchorIndex("Corp Root CA", issuer, "aa", ""))

	if stores, _ := g.TrustStoresForIssuer(issuer); len(stores) != 0 {
		t.Fatalf("same-subject/different-fingerprint anchor became authoritative trust: %+v", stores)
	}
	if stores, hosts := g.TrustCandidatesForIssuer(issuer); len(stores) != 1 || len(hosts) != 1 {
		t.Fatalf("subject-only candidate stores=%d hosts=%d, want 1/1", len(stores), len(hosts))
	}
	if g.Reaches(trustStoreNodeID("web01", "os", ""), issuer) {
		t.Fatal("default graph traversal followed an unverified subject-only candidate")
	}
	if got := g.Reachable(trustStoreNodeID("web01", "os", ""), EdgeTrustCandidate); len(got) != 1 || got[0].ID != issuer {
		t.Fatalf("explicit candidate traversal = %+v, want issuer %s", got, issuer)
	}
}

// A cross-signed copy has different certificate bytes but the same public key.
// Its SPKI hash is therefore exact authority while its subject remains only
// display metadata.
func TestCrossSignedSameSPKIIsAuthoritativeTrustAUD43(t *testing.T) {
	t.Parallel()
	g := New()
	issuer := issuerID("managed-ca")
	g.AddNode(Node{ID: issuer, Kind: KindIssuer, Name: "Corp Root CA"})
	idx := testIssuerAnchorIndex("Corp Root CA", issuer, "aa", "cc")

	addTrustStoreFinding(g, anchorFindingWithSPKI("f1", "web01", "os", "", "Different display subject", "bb", "cc"), idx)

	if stores, hosts := g.TrustStoresForIssuer(issuer); len(stores) != 1 || len(hosts) != 1 {
		t.Fatalf("same-SPKI cross-sign stores=%d hosts=%d, want 1/1", len(stores), len(hosts))
	}
	if candidates, _ := g.TrustCandidatesForIssuer(issuer); len(candidates) != 0 {
		t.Fatalf("exact SPKI match also appeared as unverified candidate: %+v", candidates)
	}
}

func TestManagedIssuerIndexUsesRealCertificateAndCrossSignIdentityAUD43(t *testing.T) {
	t.Parallel()
	managed, err := cryptoca.NewRoot(cryptoca.CASpec{CommonName: "Shared Root", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer managed.Destroy()
	other, err := cryptoca.NewRoot(cryptoca.CASpec{CommonName: "Shared Root", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Destroy()
	signer, err := cryptoca.NewRoot(cryptoca.CASpec{CommonName: "Cross Signer", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	crossPEM, err := signer.CrossSign(managed.CertificateDER())
	if err != nil {
		t.Fatal(err)
	}
	managedInfo, err := certinfo.Inspect(managed.CertificatePEM())
	if err != nil {
		t.Fatal(err)
	}
	otherInfo, err := certinfo.Inspect(other.CertificatePEM())
	if err != nil {
		t.Fatal(err)
	}
	crossInfo, err := certinfo.Inspect(crossPEM)
	if err != nil {
		t.Fatal(err)
	}
	if crossInfo.SHA256Fingerprint == managedInfo.SHA256Fingerprint || crossInfo.SPKISHA256 != managedInfo.SPKISHA256 {
		t.Fatalf("cross-sign fixture identity: cert=%t spki=%t", crossInfo.SHA256Fingerprint == managedInfo.SHA256Fingerprint, crossInfo.SPKISHA256 == managedInfo.SPKISHA256)
	}

	issuer := store.Issuer{ID: "managed", Kind: store.IssuerX509CA, Name: "operator label", Chain: []string{string(managed.CertificatePEM())}}
	idx := newIssuerAnchorIndex([]store.Issuer{issuer})
	g := New()
	g.AddNode(Node{ID: issuerID(issuer.ID), Kind: KindIssuer, Name: issuer.Name})
	addTrustStoreFinding(g, anchorFindingWithSPKI("cross", "web01", "os", "", crossInfo.Subject, crossInfo.SHA256Fingerprint, crossInfo.SPKISHA256), idx)
	addTrustStoreFinding(g, anchorFindingWithSPKI("wrong", "web02", "os", "", otherInfo.Subject, otherInfo.SHA256Fingerprint, otherInfo.SPKISHA256), idx)

	stores, _ := g.TrustStoresForIssuer(issuerID(issuer.ID))
	if len(stores) != 1 || stores[0].Attrs["host"] != "web01" {
		t.Fatalf("authoritative stores = %+v, want only cross-signed same-key web01", stores)
	}
	candidates, _ := g.TrustCandidatesForIssuer(issuerID(issuer.ID))
	if len(candidates) != 1 || candidates[0].Attrs["host"] != "web02" {
		t.Fatalf("candidate stores = %+v, want same-subject/different-key web02", candidates)
	}
}

func TestAnAnchorBecomesTrustEdgesFromItsStoreAndHost(t *testing.T) {
	t.Parallel()
	g := New()
	issuerByName := testIssuerAnchorIndex("Corp Root CA", issuerID("iss-1"), "aa", "")
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
	issuerByName := testIssuerAnchorIndex("Corp Root CA", issuerID("iss-1"), "aa", "")
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
	issuerByName := testIssuerAnchorIndex("Corp Root CA", issuerID("iss-1"), "aa", "")
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
	issuerByName := testIssuerAnchorIndex("", "", "", "")

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
	if !addTrustStoreFinding(g, f, testIssuerAnchorIndex("", "", "", "")) {
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
	if addTrustStoreFinding(g, f, testIssuerAnchorIndex("", "", "", "")) {
		t.Fatal("a filesystem finding was promoted to a trust store")
	}
	if len(g.Nodes()) != 0 {
		t.Error("a non-trust finding produced graph nodes on the trust path")
	}
}
