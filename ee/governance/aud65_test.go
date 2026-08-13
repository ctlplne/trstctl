// SPDX-License-Identifier: LicenseRef-trstctl-EE

package governance

import (
	"bytes"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/graph"
)

func TestAUD65SignedComplianceManifestIncludesCanonicalCryptoReadiness(t *testing.T) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	g := graph.New()
	g.AddNode(graph.Node{ID: "wl:payments", Kind: graph.KindWorkload, Name: "payments-team"})
	g.AddNode(graph.Node{ID: "res:lb-edge", Kind: graph.KindResource, Name: "lb-edge"})
	g.AddNode(graph.Node{ID: "crypto:asset-a", Kind: graph.KindCryptoAsset, Name: "RSA", Attrs: map[string]string{
		"quantum_vulnerable": "true", "out_of_policy": "true",
	}})
	g.AddEdge(graph.Edge{From: "wl:payments", To: "res:lb-edge", Type: graph.EdgeConnectsTo})
	g.AddEdge(graph.Edge{From: "res:lb-edge", To: "crypto:asset-a", Type: graph.EdgeExhibits})

	reporter := New("tenant-a", signer)
	report, err := reporter.Generate(SOC2, nil, g, testEvidenceWindow())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := reporter.Export(report)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := Verify(signed, signer.Public().DER)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte(`"crypto_readiness"`), []byte(`"dataset_digest"`), []byte(`"crypto:asset-a"`),
		[]byte(`"payments-team"`), []byte(`"coverage_guidance"`),
	} {
		if !bytes.Contains(manifest, required) {
			t.Fatalf("signed compliance manifest omits %s: %s", required, manifest)
		}
	}
}
