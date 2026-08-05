// SPDX-License-Identifier: MPL-2.0

package graph

import (
	"strings"
	"testing"
)

// Sequencing a crypto migration by dependency, not by severity alone (epic M2).
//
// Severity says which algorithm is worst. It does not say which change is hard.
// Sorted by severity alone, a forgotten lab box exhibiting RSA-1024 outranks a
// load balancer twelve services authenticate through — and the migration gets
// planned in the wrong order by a table that looked authoritative.

func readinessGraph() *Graph {
	g := New()
	// A load balancer exhibiting weak crypto, with real dependents.
	g.AddNode(Node{ID: "res:lb-edge", Kind: KindResource, Name: "lb-edge"})
	g.AddNode(Node{ID: "crypto:weak", Kind: KindCryptoAsset, Name: "RSA-1024",
		Attrs: map[string]string{"quantum_vulnerable": "true", "out_of_policy": "true"}})
	g.AddEdge(Edge{From: "res:lb-edge", To: "crypto:weak", Type: EdgeExhibits})
	g.AddNode(Node{ID: "wl:payments", Kind: KindWorkload, Name: "payments"})
	g.AddNode(Node{ID: "wl:checkout", Kind: KindWorkload, Name: "checkout"})
	g.AddEdge(Edge{From: "wl:payments", To: "res:lb-edge", Type: EdgeConnectsTo})
	g.AddEdge(Edge{From: "wl:checkout", To: "res:lb-edge", Type: EdgeConnectsTo})
	// A credential deployed on it — the dependency points AT the resource, so it
	// only appears if the reverse direction is walked.
	g.AddNode(Node{ID: "cred:lb-tls", Kind: KindCredential, Name: "lb tls"})
	g.AddEdge(Edge{From: "cred:lb-tls", To: "res:lb-edge", Type: EdgeDeployedTo})
	g.AddNode(Node{ID: "wl:platform", Kind: KindWorkload, Name: "platform-team"})
	g.AddEdge(Edge{From: "cred:lb-tls", To: "wl:platform", Type: EdgeOwns})

	// A lab box exhibiting equally weak crypto and nothing depending on it.
	g.AddNode(Node{ID: "res:lab-01", Kind: KindResource, Name: "lab-01"})
	g.AddNode(Node{ID: "crypto:lab", Kind: KindCryptoAsset, Name: "RSA-1024",
		Attrs: map[string]string{"quantum_vulnerable": "true", "out_of_policy": "true"}})
	g.AddEdge(Edge{From: "res:lab-01", To: "crypto:lab", Type: EdgeExhibits})

	// A compliant asset with one dependent.
	g.AddNode(Node{ID: "res:api", Kind: KindResource, Name: "api"})
	g.AddNode(Node{ID: "crypto:ok", Kind: KindCryptoAsset, Name: "ECDSA-P256",
		Attrs: map[string]string{"quantum_vulnerable": "false", "out_of_policy": "false"}})
	g.AddEdge(Edge{From: "res:api", To: "crypto:ok", Type: EdgeExhibits})
	g.AddNode(Node{ID: "wl:mobile", Kind: KindWorkload, Name: "mobile"})
	g.AddEdge(Edge{From: "wl:mobile", To: "res:api", Type: EdgeConnectsTo})

	// A CBOM usage with no location at all.
	g.AddNode(Node{ID: "crypto:nowhere", Kind: KindCryptoAsset, Name: "MD5",
		Attrs: map[string]string{"out_of_policy": "true"}})
	return g
}

func rowFor(t *testing.T, rows []CryptoReadinessRow, id string) CryptoReadinessRow {
	t.Helper()
	for _, r := range rows {
		if r.Asset.ID == id {
			return r
		}
	}
	t.Fatalf("no readiness row for %s", id)
	return CryptoReadinessRow{}
}

func TestTwoEquallyWeakAssetsAreSequencedByDependency(t *testing.T) {
	t.Parallel()
	rows := readinessGraph().CryptoReadiness()
	if len(rows) != 4 {
		t.Fatalf("rows = %d, want 4", len(rows))
	}
	// crypto:weak and crypto:lab are IDENTICALLY weak. The only thing that
	// separates them is that three parties depend on one and none on the other,
	// which is the whole point of the epic.
	if rows[0].Asset.ID != "crypto:weak" {
		t.Fatalf("first row = %s, want crypto:weak. Two assets are equally weak here, so a "+
			"severity-only ordering would be free to put the lab box first — which is how a "+
			"migration gets planned in the wrong order by an authoritative-looking table",
			rows[0].Asset.ID)
	}
	weak := rows[0]
	if len(weak.Dependents) != 3 {
		var got []string
		for _, d := range weak.Dependents {
			got = append(got, d.Node.ID)
		}
		t.Fatalf("dependents = %v, want payments, checkout and the deployed credential", got)
	}
	// Every dependent must name the resource it was reached through: a
	// recommendation nobody can check is one nobody should act on.
	for _, d := range weak.Dependents {
		if d.Via.ID != "res:lb-edge" || d.Edge == "" {
			t.Errorf("dependent %s does not explain its path: via=%q edge=%q", d.Node.ID, d.Via.ID, d.Edge)
		}
	}
}

// The credential-shaped dependencies point AT the resource. Walking only
// out-edges would silently miss them, and the surface would under-report blast
// radius while looking complete.
func TestCredentialDependenciesAreFoundInReverse(t *testing.T) {
	t.Parallel()
	weak := rowFor(t, readinessGraph().CryptoReadiness(), "crypto:weak")
	var found bool
	for _, d := range weak.Dependents {
		if d.Node.ID == "cred:lb-tls" {
			found = true
		}
	}
	if !found {
		t.Fatal("the credential deployed on the exhibiting resource is not listed as a dependent; " +
			"DEPLOYED_TO points at the resource, so following only out-edges under-reports the " +
			"blast radius while the table still looks complete")
	}
	// And its owner is attributed, so the blocker has a name on it.
	var owned bool
	for _, o := range weak.Owners {
		if o == "platform-team" {
			owned = true
		}
	}
	if !owned {
		t.Fatalf("owners = %v, want the credential's owning workload attributed", weak.Owners)
	}
}

// The load-bearing honesty property: zero observed dependents must never read
// as safe.
//
// The graph is built from discovery, so "nothing depends on this" and "nothing
// has scanned this" produce the identical row. Calling the first one safe turns
// a coverage gap into a green light.
func TestNoObservedDependentsIsNeverReportedAsSafe(t *testing.T) {
	t.Parallel()
	lab := rowFor(t, readinessGraph().CryptoReadiness(), "crypto:lab")
	if len(lab.Dependents) != 0 {
		t.Fatalf("expected no dependents, got %d", len(lab.Dependents))
	}
	low := strings.ToLower(lab.Recommendation)
	if strings.Contains(low, "safe") {
		t.Fatalf("recommendation calls an asset with zero OBSERVED dependents safe: %q\n\n"+
			"The graph is built from discovery, so this row is identical to one for a resource "+
			"nothing has scanned.", lab.Recommendation)
	}
	if !strings.Contains(low, "not the same as having none") {
		t.Fatalf("recommendation must say that zero observed is not zero: %q", lab.Recommendation)
	}
}

// A CBOM usage with no location cannot be sequenced, and must say so rather than
// sorting to the bottom as though it were low risk.
func TestAnUnlocatedUsageIsFlaggedRatherThanRankedLow(t *testing.T) {
	t.Parallel()
	row := rowFor(t, readinessGraph().CryptoReadiness(), "crypto:nowhere")
	if !row.Unlocated {
		t.Fatal("a crypto usage with no exhibitor edge was not flagged as unlocated")
	}
	if !strings.Contains(row.Recommendation, "cannot be computed") {
		t.Fatalf("recommendation must say the blast radius is uncomputable: %q", row.Recommendation)
	}
	if strings.Contains(strings.ToLower(row.Recommendation), "low-risk asset, it is") == false {
		t.Fatalf("recommendation must refuse the low-risk reading: %q", row.Recommendation)
	}
}

// Urgent rows precede compliant ones regardless of dependent count, so a
// popular compliant asset cannot outrank a weak one.
func TestUrgencyOutranksPopularity(t *testing.T) {
	t.Parallel()
	g := readinessGraph()
	// Give the compliant asset more dependents than the weak one.
	for _, id := range []string{"wl:a", "wl:b", "wl:c", "wl:d"} {
		g.AddNode(Node{ID: id, Kind: KindWorkload, Name: id})
		g.AddEdge(Edge{From: id, To: "res:api", Type: EdgeConnectsTo})
	}
	rows := g.CryptoReadiness()
	if rows[0].Asset.ID != "crypto:weak" {
		t.Fatalf("first row = %s; a compliant asset with more dependents outranked a weak one, "+
			"so the table now sequences by popularity instead of risk", rows[0].Asset.ID)
	}
	ok := rowFor(t, rows, "crypto:ok")
	if len(ok.Dependents) != 5 {
		t.Fatalf("compliant asset dependents = %d, want 5", len(ok.Dependents))
	}
}
