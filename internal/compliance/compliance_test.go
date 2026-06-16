package compliance

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/graph"
)

func cbom() *graph.Graph {
	g := graph.New()
	add := func(id string, alg crypto.Algorithm) {
		g.AddNode(graph.Node{ID: id, Kind: graph.KindCryptoAsset, Attrs: map[string]string{"algorithm": string(alg)}})
	}
	add("a", crypto.RSA2048)   // quantum-vulnerable
	add("b", crypto.ECDSAP256) // quantum-vulnerable
	add("c", crypto.MLDSA65)   // post-quantum
	return g
}

func auditFixture() []auditsink.Record {
	rec := &auditsink.Recorder{}
	_ = rec.Audit(context.Background(), "certificate.issued", "t1", []byte(`{}`))
	return rec.Records()
}

func TestGeneratePostureAndControls(t *testing.T) {
	caKey, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer caKey.Destroy()
	r := New("t1", caKey)
	rep, err := r.Generate(PCIDSS, auditFixture(), cbom())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Posture.TotalCryptoAssets != 3 || rep.Posture.QuantumVulnerable != 2 || rep.Posture.PostQuantum != 1 {
		t.Fatalf("posture = %+v, want 3/2/1", rep.Posture)
	}
	if len(rep.Controls) == 0 {
		t.Error("no controls generated")
	}
	if len(rep.ProductEvidences) == 0 || len(rep.OperatorAttests) == 0 {
		t.Error("product-evidences vs operator-attests boundary not present")
	}
}

func TestCNSA2HasPQCControl(t *testing.T) {
	caKey, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer caKey.Destroy()
	rep, _ := New("t1", caKey).Generate(CNSA2, auditFixture(), cbom())
	found := false
	for _, c := range rep.Controls {
		if c.ID == "cnsa-2.0-pqc-adoption" {
			found = true
			if c.Status != "gap" { // 2 quantum-vulnerable assets remain
				t.Errorf("pqc-adoption status = %q, want gap", c.Status)
			}
		}
	}
	if !found {
		t.Error("CNSA 2.0 report missing the PQC-adoption control")
	}
}

func TestSignedExportVerifiesAndDetectsTamper(t *testing.T) {
	caKey, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer caKey.Destroy()
	r := New("t1", caKey)
	rep, _ := r.Generate(SOC2, auditFixture(), cbom())
	signed, err := r.Export(rep)
	if err != nil {
		t.Fatal(err)
	}
	pub := caKey.Public().DER
	if _, err := Verify(signed, pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// Tamper the export.
	tampered := bytes.Replace(signed, []byte("soc2"), []byte("xxxx"), 1)
	if _, err := Verify(tampered, pub); err == nil {
		t.Error("Verify accepted a tampered export")
	}
}

func TestGenerateIsReproducible(t *testing.T) {
	caKey, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer caKey.Destroy()
	r := New("t1", caKey)
	a, _ := r.Generate(PCIDSS, auditFixture(), cbom())
	b, _ := r.Generate(PCIDSS, auditFixture(), cbom())
	// The report (the evidence) is reproducible over the same inputs.
	ja, _ := r.Export(a)
	jb, _ := r.Export(b)
	// Manifests must match (signatures may differ: ECDSA is randomized).
	ma, _ := Verify(ja, caKey.Public().DER)
	mb, _ := Verify(jb, caKey.Public().DER)
	if !bytes.Equal(ma, mb) {
		t.Error("report manifest not reproducible over identical inputs")
	}
}
