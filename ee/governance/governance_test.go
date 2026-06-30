package governance

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/compliance"
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

func TestFIPSAndCommonCriteriaReportSeparatesEvidenceFromExternalValidation(t *testing.T) {
	caKey, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer caKey.Destroy()
	for _, tc := range []struct {
		framework       Framework
		evidenced       string
		residual        string
		productEvidence string
		operatorAttest  string
	}{
		{
			framework:       FIPS140,
			evidenced:       "fips-140-module-post",
			residual:        "fips-140-cmvp-certificate-residual",
			productEvidence: "regulated FIPS deployment profile with pinned Go module selector",
			operatorAttest:  "NIST CMVP certificate number for the deployed validated module",
		},
		{
			framework:       CommonCriteria,
			evidenced:       "common-criteria-security-target-evidence",
			residual:        "common-criteria-evaluation-residual",
			productEvidence: "security-target evidence map over served controls",
			operatorAttest:  "Common Criteria certificate and evaluation report",
		},
	} {
		rep, err := New("t1", caKey).Generate(tc.framework, auditFixture(), cbom())
		if err != nil {
			t.Fatalf("Generate(%s): %v", tc.framework, err)
		}
		if rep.Framework != string(tc.framework) {
			t.Fatalf("framework = %q, want %q", rep.Framework, tc.framework)
		}
		mustHaveControl(t, rep.Controls, tc.evidenced, "evidenced")
		mustHaveControl(t, rep.Controls, tc.residual, "gap")
		if !contains(rep.ProductEvidences, tc.productEvidence) {
			t.Fatalf("%s product evidence missing %q: %+v", tc.framework, tc.productEvidence, rep.ProductEvidences)
		}
		if !contains(rep.OperatorAttests, tc.operatorAttest) {
			t.Fatalf("%s operator attestation missing %q: %+v", tc.framework, tc.operatorAttest, rep.OperatorAttests)
		}
		if tc.framework == FIPS140 {
			mustHaveControl(t, rep.Controls, "fips-140-approved-algorithm-profile", "evidenced")
			mustHaveControl(t, rep.Controls, "fips-140-non-fips-pqc-fence", "evidenced")
			mustHaveControl(t, rep.Controls, "fips-140-hsm-kms-validation-records", "evidenced")
			if rep.FIPSProfile == nil {
				t.Fatal("FIPS report missing regulated deployment profile")
			}
			if err := compliance.ValidateFIPSRegulatedDeploymentProfile(*rep.FIPSProfile); err != nil {
				t.Fatalf("FIPS report profile is invalid: %v", err)
			}
			if rep.FIPSProfile.GoFIPSModuleSelector != compliance.DefaultFIPSGoModuleSelector {
				t.Fatalf("FIPS report module selector=%q, want %q", rep.FIPSProfile.GoFIPSModuleSelector, compliance.DefaultFIPSGoModuleSelector)
			}
		}
	}
}

func TestRegulatoryMappingFrameworksSeparateEvidenceFromCertificationCAPCMP04(t *testing.T) {
	caKey, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer caKey.Destroy()
	for _, tc := range []struct {
		framework       Framework
		evidenced       string
		residual        string
		productEvidence string
		operatorAttest  string
	}{
		{
			framework:       NIST80053,
			evidenced:       "nist-800-53-au-evidence",
			residual:        "nist-800-53-operator-tailoring-residual",
			productEvidence: "NHI inventory and posture evidence mappings",
			operatorAttest:  "NIST SP 800-53 control tailoring",
		},
		{
			framework:       NISTCSF20,
			evidenced:       "nist-csf-2.0-identify-protect-detect",
			residual:        "nist-csf-2.0-govern-operator-residual",
			productEvidence: "least-privilege and stale-credential posture evidence",
			operatorAttest:  "NIST CSF organizational profile",
		},
		{
			framework:       FedRAMP,
			evidenced:       "fedramp-rev5-au-ac-ia-evidence",
			residual:        "fedramp-rev5-authorization-residual",
			productEvidence: "signed audit evidence mapped to framework controls",
			operatorAttest:  "FedRAMP authorization package",
		},
		{
			framework:       CMMC20,
			evidenced:       "cmmc-2.0-ac-ia-au-evidence",
			residual:        "cmmc-2.0-cui-scope-residual",
			productEvidence: "static credential and rotation posture evidence",
			operatorAttest:  "CMMC scope and CUI boundary",
		},
		{
			framework:       EIDAS,
			evidenced:       "eidas-trust-service-security-evidence",
			residual:        "eidas-qualified-status-residual",
			productEvidence: "signed audit evidence mapped to framework controls",
			operatorAttest:  "eIDAS conformity assessment",
		},
		{
			framework:       NIS2,
			evidenced:       "nis2-article-21-risk-measures",
			residual:        "nis2-governance-reporting-residual",
			productEvidence: "NHI inventory and posture evidence mappings",
			operatorAttest:  "NIS2 entity scope and national transposition obligations",
		},
	} {
		rep, err := New("t1", caKey).Generate(tc.framework, auditFixture(), cbom())
		if err != nil {
			t.Fatalf("Generate(%s): %v", tc.framework, err)
		}
		if rep.Framework != string(tc.framework) {
			t.Fatalf("framework = %q, want %q", rep.Framework, tc.framework)
		}
		mustHaveControl(t, rep.Controls, tc.evidenced, "evidenced")
		mustHaveControl(t, rep.Controls, tc.residual, "gap")
		if !contains(rep.ProductEvidences, tc.productEvidence) {
			t.Fatalf("%s product evidence missing %q: %+v", tc.framework, tc.productEvidence, rep.ProductEvidences)
		}
		if !contains(rep.OperatorAttests, tc.operatorAttest) {
			t.Fatalf("%s operator attestation missing %q: %+v", tc.framework, tc.operatorAttest, rep.OperatorAttests)
		}
	}
}

func TestFIPSEvidencePackCarriesRegulatedDeploymentProfile(t *testing.T) {
	caKey, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer caKey.Destroy()
	rep, err := New("t1", caKey).Generate(FIPS140, auditFixture(), cbom())
	if err != nil {
		t.Fatalf("Generate(%s): %v", FIPS140, err)
	}
	if rep.FIPSProfile == nil {
		t.Fatal("FIPS report missing regulated deployment profile")
	}
	for _, family := range []string{"ML-DSA", "ML-KEM", "SLH-DSA", "Ed25519"} {
		if !fipsProfileFenceContains(rep.FIPSProfile, family) {
			t.Fatalf("FIPS profile missing non-FIPS fence for %s: %+v", family, rep.FIPSProfile.NonFIPSFences)
		}
	}
	for _, provider := range []string{"AWS KMS / AWS CloudHSM", "Azure Key Vault Managed HSM", "Google Cloud KMS / Cloud HSM", "PKCS#11 HSM"} {
		if !fipsProfileCertificateContains(rep.FIPSProfile, provider) {
			t.Fatalf("FIPS profile missing HSM/KMS validation certificate requirement for %s: %+v", provider, rep.FIPSProfile.HSMKMSValidationCertificates)
		}
	}
	if compliance.FIPSApprovedUnderRegulatedProfile(crypto.MLDSA65) || compliance.FIPSApprovedUnderRegulatedProfile(crypto.Ed25519) {
		t.Fatal("regulated FIPS profile approved a fenced algorithm")
	}
}

func TestFIPSSignedExportIncludesRegulatedDeploymentProfile(t *testing.T) {
	caKey, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer caKey.Destroy()
	r := New("t1", caKey)
	rep, err := r.Generate(FIPS140, auditFixture(), cbom())
	if err != nil {
		t.Fatalf("Generate(%s): %v", FIPS140, err)
	}
	signed, err := r.Export(rep)
	if err != nil {
		t.Fatalf("Export(%s): %v", FIPS140, err)
	}
	manifest, err := Verify(signed, caKey.Public().DER)
	if err != nil {
		t.Fatalf("Verify(%s): %v", FIPS140, err)
	}
	for _, want := range []string{
		`"fips_regulated_deployment_profile"`,
		`"go_fips_module_selector":"` + compliance.DefaultFIPSGoModuleSelector + `"`,
		`"non_fips_fences"`,
		`"hsm_kms_validation_certificates"`,
	} {
		if !bytes.Contains(manifest, []byte(want)) {
			t.Fatalf("signed FIPS evidence pack manifest missing %s: %s", want, manifest)
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

func fipsProfileFenceContains(profile *compliance.FIPSRegulatedDeploymentProfile, want string) bool {
	for _, fence := range profile.NonFIPSFences {
		for _, alg := range fence.Algorithms {
			if strings.Contains(alg, want) {
				return true
			}
		}
	}
	return false
}

func fipsProfileCertificateContains(profile *compliance.FIPSRegulatedDeploymentProfile, provider string) bool {
	for _, cert := range profile.HSMKMSValidationCertificates {
		if cert.Provider == provider && cert.CertificateRef != "" && cert.ValidationScope != "" {
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
