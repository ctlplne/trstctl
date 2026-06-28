package governance

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

func TestCAAuditPostureFrameworksSeparateEvidenceFromCertification(t *testing.T) {
	caKey, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer caKey.Destroy()
	for _, fw := range []Framework{WebTrust, ETSI} {
		rep, err := New("t1", caKey).Generate(fw, auditFixture(), cbom())
		if err != nil {
			t.Fatalf("Generate(%s): %v", fw, err)
		}
		if rep.Framework != string(fw) {
			t.Fatalf("framework = %q, want %q", rep.Framework, fw)
		}
		foundAudit := false
		foundResidual := false
		for _, control := range rep.Controls {
			if control.Status == "evidenced" && contains(control.Evidence, "signed audit evidence log") {
				foundAudit = true
			}
			if control.Status == "gap" {
				for _, evidence := range control.Evidence {
					if evidence == "external practitioner report" || evidence == "external conformity assessment" {
						foundResidual = true
					}
				}
			}
		}
		if !foundAudit {
			t.Fatalf("%s report did not evidence CA/audit posture: %+v", fw, rep.Controls)
		}
		if !foundResidual {
			t.Fatalf("%s report did not keep certification/assessment as operator residual: %+v", fw, rep.Controls)
		}
		if !contains(rep.ProductEvidences, "CA issuance and revocation audit evidence") {
			t.Fatalf("%s product evidence missing CA audit posture: %+v", fw, rep.ProductEvidences)
		}
	}
}

func TestCABFBaselineRequirementsReportSeparatesEvidenceFromPublicTrustAttestation(t *testing.T) {
	caKey, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer caKey.Destroy()
	rep, err := New("t1", caKey).Generate(CABFBR, auditFixture(), cbom())
	if err != nil {
		t.Fatalf("Generate(%s): %v", CABFBR, err)
	}
	if rep.Framework != string(CABFBR) {
		t.Fatalf("framework = %q, want %q", rep.Framework, CABFBR)
	}
	mustHaveControl(t, rep.Controls, "cabf-br-profile-lint", "evidenced")
	mustHaveControl(t, rep.Controls, "cabf-br-ca-audit-trail", "evidenced")
	mustHaveControl(t, rep.Controls, "cabf-br-public-trust-residual", "gap")
	for _, want := range []string{
		"CA/Browser Forum profile lint evidence",
		"external zlint corpus gate",
		"served CA issuance and revocation audit evidence",
	} {
		if !contains(rep.ProductEvidences, want) {
			t.Fatalf("CABF BR product evidence missing %q: %+v", want, rep.ProductEvidences)
		}
	}
	for _, want := range []string{
		"CP/CPS publication",
		"independent WebTrust practitioner opinion for public-trust issuance",
		"CA/Browser Forum policy program operation",
	} {
		if !contains(rep.OperatorAttests, want) {
			t.Fatalf("CABF BR operator attestation missing %q: %+v", want, rep.OperatorAttests)
		}
	}
}

func mustHaveControl(t *testing.T, controls []Control, id, status string) {
	t.Helper()
	for _, control := range controls {
		if control.ID == id {
			if control.Status != status {
				t.Fatalf("control %s status = %q, want %q", id, control.Status, status)
			}
			return
		}
	}
	t.Fatalf("missing control %s in %+v", id, controls)
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

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
