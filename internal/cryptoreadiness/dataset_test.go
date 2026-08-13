// SPDX-License-Identifier: MPL-2.0

package cryptoreadiness

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/store"
)

func TestCanonicalDatasetAndExportsKeepTheSameOrderedFactsAUD65(t *testing.T) {
	g := readinessGraph()
	row := g.CryptoReadiness()[0]
	rowDigest, err := RowDigest("tenant-a", row)
	if err != nil {
		t.Fatal(err)
	}
	actions := []store.CryptoReadinessAction{{
		TenantID: "tenant-a", CampaignID: "campaign-a", Name: "Payments blocker",
		OwnerRef: "payments-team", Deadline: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		Wave: "wave-1", Status: "open", ReadinessStatus: "blocked", FindingID: "asset-a",
		ReadinessDigest: rowDigest, Disposition: "pending",
		ReadinessEvidenceRefs: []string{"change:CAB-2048"}, EvidenceRefs: []string{"audit:owner-approved"},
	}}

	dataset, err := FromGraph("tenant-a", g, actions)
	if err != nil {
		t.Fatal(err)
	}
	again, err := FromGraph("tenant-a", g, actions)
	if err != nil {
		t.Fatal(err)
	}
	if dataset.DatasetDigest == "" || dataset.DatasetDigest != again.DatasetDigest {
		t.Fatalf("deterministic dataset digest = %q / %q", dataset.DatasetDigest, again.DatasetDigest)
	}
	if len(dataset.Items) != 1 || dataset.Items[0].Asset.ID != "crypto:asset-a" || len(dataset.Items[0].Actions) != 1 || dataset.Items[0].Actions[0].Stale {
		t.Fatalf("canonical joined item = %+v", dataset.Items)
	}

	csvBytes, err := CSV(dataset)
	if err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(bytes.NewReader(csvBytes)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[1][1] != dataset.DatasetDigest || records[1][2] != "crypto:asset-a" || !strings.Contains(records[1][11], "campaign-a") || !strings.Contains(records[1][12], "change:CAB-2048") {
		t.Fatalf("CSV does not preserve canonical row/action: %q", records)
	}
	formula := dataset
	formula.Items[0].Recommendation = "=HYPERLINK(\"https://attacker.invalid\")"
	formulaCSV, err := CSV(formula)
	if err != nil {
		t.Fatal(err)
	}
	formulaRows, err := csv.NewReader(bytes.NewReader(formulaCSV)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(formulaRows[1][10], "'=") {
		t.Fatalf("spreadsheet formula was not neutralized: %q", formulaRows[1][10])
	}

	ndjsonBytes, err := NDJSON(dataset)
	if err != nil {
		t.Fatal(err)
	}
	var line struct {
		Sequence         int    `json:"sequence"`
		DatasetDigest    string `json:"dataset_digest"`
		CoverageGuidance string `json:"coverage_guidance"`
		Item             Item   `json:"item"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(ndjsonBytes), &line); err != nil {
		t.Fatal(err)
	}
	if line.Sequence != 1 || line.DatasetDigest != dataset.DatasetDigest || line.CoverageGuidance != dataset.CoverageGuidance || line.Item.Asset.ID != dataset.Items[0].Asset.ID || line.Item.Actions[0].CampaignID != "campaign-a" {
		t.Fatalf("NDJSON diverged from canonical dataset: %+v", line)
	}

	// A production-edge mutation changes both the dataset digest and the row
	// binding. The old event-backed action remains visible as stale.
	g.AddNode(graph.Node{ID: "wl:checkout", Kind: graph.KindWorkload, Name: "checkout-service"})
	g.AddEdge(graph.Edge{From: "wl:checkout", To: "res:lb-edge", Type: graph.EdgeConnectsTo})
	changed, err := FromGraph("tenant-a", g, actions)
	if err != nil {
		t.Fatal(err)
	}
	if changed.DatasetDigest == dataset.DatasetDigest || !changed.Items[0].Actions[0].Stale || len(changed.Items[0].Dependents) != 2 {
		t.Fatalf("edge mutation did not reach digest/action/consumer: before=%+v after=%+v", dataset, changed)
	}
}

func TestCanonicalDatasetRefusesForeignTenantActionsAUD65(t *testing.T) {
	_, err := FromGraph("tenant-a", readinessGraph(), []store.CryptoReadinessAction{
		{TenantID: "tenant-b", CampaignID: "foreign-action", FindingID: "asset-a"},
	})
	if err == nil || !strings.Contains(err.Error(), "outside tenant") {
		t.Fatalf("foreign action error = %v", err)
	}
}

func readinessGraph() *graph.Graph {
	g := graph.New()
	g.AddNode(graph.Node{ID: "wl:payments", Kind: graph.KindWorkload, Name: "payments-team"})
	g.AddNode(graph.Node{ID: "res:lb-edge", Kind: graph.KindResource, Name: "lb-edge"})
	g.AddNode(graph.Node{ID: "crypto:asset-a", Kind: graph.KindCryptoAsset, Name: "RSA", Attrs: map[string]string{
		"quantum_vulnerable": "true", "out_of_policy": "true",
	}})
	g.AddEdge(graph.Edge{From: "wl:payments", To: "res:lb-edge", Type: graph.EdgeConnectsTo})
	g.AddEdge(graph.Edge{From: "res:lb-edge", To: "crypto:asset-a", Type: graph.EdgeExhibits})
	return g
}
