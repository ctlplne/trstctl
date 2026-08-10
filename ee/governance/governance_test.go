// SPDX-License-Identifier: LicenseRef-trstctl-EE

package governance

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	eepqc "trstctl.com/trstctl/ee/pqc"
	"trstctl.com/trstctl/internal/audit"
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
	add("c", eepqc.MLDSA65)    // post-quantum
	g.AddNode(graph.Node{ID: "wl:payments", Kind: graph.KindWorkload, Name: "payments"})
	g.AddNode(graph.Node{ID: "id:payments-api", Kind: graph.KindCredential, Name: "payments-api"})
	g.AddEdge(graph.Edge{From: "wl:payments", To: "id:payments-api", Type: graph.EdgeOwns})
	return g
}

var evidenceFixtureTime = time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

func testEvidenceWindow() EvidenceWindow {
	return EvidenceWindow{From: evidenceFixtureTime.Add(-time.Hour), Through: evidenceFixtureTime.Add(time.Hour)}
}

func auditFixture() []audit.Record {
	records := []struct {
		typ  string
		data string
	}{
		{"certificate.recorded", `{}`},
		{"certificate.revoked", `{}`},
		{"policy.decision", `{}`},
		{"discovery.finding.recorded", `{}`},
		{"profile.created", `{}`},
		{"ca.endentity.issued", `{}`},
		{"ca.crl.published", `{}`},
		{"ca.ceremony.approved", `{}`},
		{"nhi.access_review.campaign.started", `{"id":"review-1","items":[{"item_id":"item-1"}]}`},
		{"nhi.access_review.item.decided", `{"campaign_id":"review-1","item_id":"item-1","decision":"certified"}`},
		{"access.change_request.created", `{"id":"change-1","requester_subject":"requester","change_ref":"pr:42","evidence_refs":["check:42"],"required_approvals":2}`},
		{"access.change_request.decided", `{"request_id":"change-1","decision":"approved","approver_subject":"approver-a","decision_evidence_refs":["review:a"]}`},
		{"access.change_request.decided", `{"request_id":"change-1","decision":"approved","approver_subject":"approver-b","decision_evidence_refs":["review:b"]}`},
		{"policy.version.authored", `{"id":"policy-1","module_sha256":"sha256:policy","change_ref":"pr:policy","evidence_refs":["check:policy"]}`},
		{"policy.version.activated", `{"id":"policy-1","evidence_refs":["approval:policy"]}`},
		{"tenant.key_domain.migration_completed", `{"protection_mode":"tenant_domain","state":"unsealed","wrapper_kind":"pkcs11","wrapper_id":"hsm-prod","transition_evidence_refs":["cmvp:1234"]}`},
	}
	out := make([]audit.Record, 0, len(records))
	for n, fixture := range records {
		sequence := uint64(n + 1)
		out = append(out, audit.Record{
			Sequence: sequence, StreamSequence: sequence, ID: fmt.Sprintf("event-%02d", sequence),
			Type: fixture.typ, TenantID: "t1", Time: evidenceFixtureTime.Add(time.Duration(n) * time.Second),
			Data: []byte(fixture.data), Hash: fmt.Sprintf("sha256:event-%02d", sequence),
		})
	}
	return out
}

func TestGeneratePostureAndControls(t *testing.T) {
	caKey, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer caKey.Destroy()
	r := New("t1", caKey)
	rep, err := r.Generate(PCIDSS, auditFixture(), cbom(), testEvidenceWindow())
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
	rep, _ := New("t1", caKey).Generate(CNSA2, auditFixture(), cbom(), testEvidenceWindow())
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
		rep, err := New("t1", caKey).Generate(fw, auditFixture(), cbom(), testEvidenceWindow())
		if err != nil {
			t.Fatalf("Generate(%s): %v", fw, err)
		}
		if rep.Framework != string(fw) {
			t.Fatalf("framework = %q, want %q", rep.Framework, fw)
		}
		foundAudit := false
		foundResidual := false
		for _, control := range rep.Controls {
			if control.Status == "evidenced" && len(control.EvidenceRefs) > 0 && (control.ID == "webtrust-ca-lifecycle" || control.ID == "etsi-en-319-411-ca-operations") {
				foundAudit = true
			}
			if control.Status == "gap" {
				for _, evidence := range append(append([]string(nil), control.Evidence...), control.Missing...) {
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
		assertResolvableProductEvidence(t, rep.ProductEvidences)
	}
}

func TestCABFBaselineRequirementsReportSeparatesEvidenceFromPublicTrustAttestation(t *testing.T) {
	caKey, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer caKey.Destroy()
	rep, err := New("t1", caKey).Generate(CABFBR, auditFixture(), cbom(), testEvidenceWindow())
	if err != nil {
		t.Fatalf("Generate(%s): %v", CABFBR, err)
	}
	if rep.Framework != string(CABFBR) {
		t.Fatalf("framework = %q, want %q", rep.Framework, CABFBR)
	}
	mustHaveControl(t, rep.Controls, "cabf-br-profile-lint", "evidenced")
	mustHaveControl(t, rep.Controls, "cabf-br-ca-audit-trail", "evidenced")
	mustHaveControl(t, rep.Controls, "cabf-br-public-trust-residual", "gap")
	assertResolvableProductEvidence(t, rep.ProductEvidences)
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
			evidenced:       "fips-140-hsm-kms-validation-records",
			residual:        "fips-140-cmvp-certificate-residual",
			productEvidence: "event:event-16",
			operatorAttest:  "NIST CMVP certificate number for the deployed validated module",
		},
		{
			framework:       CommonCriteria,
			evidenced:       "common-criteria-configuration-management-evidence",
			residual:        "common-criteria-evaluation-residual",
			productEvidence: "event:event-15",
			operatorAttest:  "Common Criteria certificate and evaluation report",
		},
	} {
		rep, err := New("t1", caKey).Generate(tc.framework, auditFixture(), cbom(), testEvidenceWindow())
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
			mustHaveControl(t, rep.Controls, "fips-140-module-post", "gap")
			mustHaveControl(t, rep.Controls, "fips-140-crypto-boundary", "gap")
			mustHaveControl(t, rep.Controls, "fips-140-approved-algorithm-profile", "gap")
			mustHaveControl(t, rep.Controls, "fips-140-non-fips-pqc-fence", "gap")
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
		framework      Framework
		evidenced      string
		residual       string
		operatorAttest string
	}{
		{
			framework:      NIST80053,
			evidenced:      "nist-800-53-au-evidence",
			residual:       "nist-800-53-operator-tailoring-residual",
			operatorAttest: "NIST SP 800-53 control tailoring",
		},
		{
			framework:      NISTCSF20,
			evidenced:      "nist-csf-2.0-identify-protect-detect",
			residual:       "nist-csf-2.0-govern-operator-residual",
			operatorAttest: "NIST CSF organizational profile",
		},
		{
			framework:      FedRAMP,
			evidenced:      "fedramp-rev5-au-ac-ia-evidence",
			residual:       "fedramp-rev5-authorization-residual",
			operatorAttest: "FedRAMP authorization package",
		},
		{
			framework:      CMMC20,
			evidenced:      "cmmc-2.0-ac-ia-au-evidence",
			residual:       "cmmc-2.0-cui-scope-residual",
			operatorAttest: "CMMC scope and CUI boundary",
		},
		{
			framework:      EIDAS,
			evidenced:      "eidas-trust-service-security-evidence",
			residual:       "eidas-qualified-status-residual",
			operatorAttest: "eIDAS conformity assessment",
		},
		{
			framework:      NIS2,
			evidenced:      "nis2-article-21-risk-measures",
			residual:       "nis2-governance-reporting-residual",
			operatorAttest: "NIS2 entity scope and national transposition obligations",
		},
	} {
		rep, err := New("t1", caKey).Generate(tc.framework, auditFixture(), cbom(), testEvidenceWindow())
		if err != nil {
			t.Fatalf("Generate(%s): %v", tc.framework, err)
		}
		if rep.Framework != string(tc.framework) {
			t.Fatalf("framework = %q, want %q", rep.Framework, tc.framework)
		}
		mustHaveControl(t, rep.Controls, tc.evidenced, "evidenced")
		mustHaveControl(t, rep.Controls, tc.residual, "gap")
		assertResolvableProductEvidence(t, rep.ProductEvidences)
		if !contains(rep.OperatorAttests, tc.operatorAttest) {
			t.Fatalf("%s operator attestation missing %q: %+v", tc.framework, tc.operatorAttest, rep.OperatorAttests)
		}
	}
}

func TestFIPSEvidencePackCarriesRegulatedDeploymentProfile(t *testing.T) {
	caKey, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer caKey.Destroy()
	rep, err := New("t1", caKey).Generate(FIPS140, auditFixture(), cbom(), testEvidenceWindow())
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
	if compliance.FIPSApprovedUnderRegulatedProfile(eepqc.MLDSA65) || compliance.FIPSApprovedUnderRegulatedProfile(crypto.Ed25519) {
		t.Fatal("regulated FIPS profile approved a fenced algorithm")
	}
}

func TestFIPSSignedExportIncludesRegulatedDeploymentProfile(t *testing.T) {
	caKey, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer caKey.Destroy()
	r := New("t1", caKey)
	rep, err := r.Generate(FIPS140, auditFixture(), cbom(), testEvidenceWindow())
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

func TestSOC2EvidencePackMapsTrustServicesCriteriaWithoutClaimingAttestationCAPCMP05(t *testing.T) {
	caKey, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer caKey.Destroy()
	rep, err := New("t1", caKey).Generate(SOC2, auditFixture(), cbom(), testEvidenceWindow())
	if err != nil {
		t.Fatalf("Generate(SOC2): %v", err)
	}
	if rep.Framework != string(SOC2) {
		t.Fatalf("framework = %q, want %q", rep.Framework, SOC2)
	}
	mustHaveControl(t, rep.Controls, "soc2-cc6-access-control", "evidenced")
	mustHaveControl(t, rep.Controls, "soc2-cc7-monitoring-audit-evidence", "evidenced")
	mustHaveControl(t, rep.Controls, "soc2-cc8-change-management-evidence", "evidenced")
	mustHaveControl(t, rep.Controls, "soc2-attestation-residual", "gap")
	assertResolvableProductEvidence(t, rep.ProductEvidences)
	if !contains(rep.OperatorAttests, "independent CPA SOC 2 examination report") {
		t.Fatalf("SOC 2 operator attestations missing CPA examination residual: %+v", rep.OperatorAttests)
	}
}

func TestSOC2ControlsRejectUnrelatedAuditEvidenceAUD76(t *testing.T) {
	caKey, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer caKey.Destroy()

	// A tenant membership mutation is a real immutable audit record, but it says
	// nothing about NHI ownership/access review, security monitoring, governed
	// credential changes, or tenant key custody. It must not satisfy those claims.
	unrelated := []audit.Record{{
		ID:       "event-unrelated",
		Sequence: 1,
		Type:     "tenant.member.upserted",
		TenantID: "t1",
		Time:     evidenceFixtureTime,
		Data:     []byte(`{"subject":"auditor@example.test"}`),
	}}
	rep, err := New("t1", caKey).Generate(SOC2, unrelated, cbom(), testEvidenceWindow())
	if err != nil {
		t.Fatalf("Generate(SOC2): %v", err)
	}
	for _, id := range []string{
		"soc2-key-management",
		"soc2-cc6-access-control",
		"soc2-cc7-monitoring-audit-evidence",
		"soc2-cc8-change-management-evidence",
	} {
		mustHaveControl(t, rep.Controls, id, "gap")
	}
}

func TestSOC2ControlsCarryTenantWindowAndResolvableEvidenceAUD76(t *testing.T) {
	caKey, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer caKey.Destroy()

	reporter := New("t1", caKey)
	rep, err := reporter.Generate(SOC2, auditFixture(), cbom(), testEvidenceWindow())
	if err != nil {
		t.Fatalf("Generate(SOC2): %v", err)
	}
	if rep.TenantID != "t1" || rep.EvidenceWindow != testEvidenceWindow() || !rep.GeneratedAt.Equal(testEvidenceWindow().Through) {
		t.Fatalf("report tenant/window = tenant=%q generated=%s window=%+v", rep.TenantID, rep.GeneratedAt, rep.EvidenceWindow)
	}
	for _, id := range []string{
		"soc2-key-management",
		"soc2-cc6-access-control",
		"soc2-cc7-monitoring-audit-evidence",
		"soc2-cc8-change-management-evidence",
	} {
		control := controlByID(t, rep.Controls, id)
		if control.Status != "evidenced" || len(control.Missing) != 0 || len(control.EvidenceRefs) == 0 {
			t.Fatalf("control %s is not backed by exact evidence: %+v", id, control)
		}
		if control.Window != testEvidenceWindow() {
			t.Fatalf("control %s window = %+v", id, control.Window)
		}
		for _, ref := range control.EvidenceRefs {
			if ref.Ref == "" || ref.Source == "" || ref.Type == "" || ref.ObservedAt.IsZero() {
				t.Fatalf("control %s has unresolved evidence reference: %+v", id, ref)
			}
			if ref.Source == "audit_event" && (ref.Sequence == 0 || ref.Digest == "") {
				t.Fatalf("control %s event reference lacks sequence/hash: %+v", id, ref)
			}
		}
	}
	if len(rep.ProductEvidences) == 0 {
		t.Fatal("derived product evidence references are empty")
	}
	for _, ref := range rep.ProductEvidences {
		if !strings.HasPrefix(ref, "event:") && !strings.HasPrefix(ref, "object:") && !strings.HasPrefix(ref, "runtime:") {
			t.Fatalf("product evidence %q is an unresolvable capability phrase", ref)
		}
	}

	signed, err := reporter.Export(rep)
	if err != nil {
		t.Fatalf("Export(SOC2): %v", err)
	}
	manifest, err := Verify(signed, caKey.Public().DER)
	if err != nil {
		t.Fatalf("Verify(SOC2): %v", err)
	}
	for _, want := range []string{`"tenant_id":"t1"`, `"evidence_window"`, `"coverage_window"`, `"evidence_refs"`, `"event:event-`} {
		if !bytes.Contains(manifest, []byte(want)) {
			t.Fatalf("signed manifest missing %s: %s", want, manifest)
		}
	}
}

func TestSOC2ControlTransitionsRequireExactCurrentTenantEvidenceAUD76(t *testing.T) {
	caKey, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer caKey.Destroy()
	reporter := New("t1", caKey)

	cc7Types := map[string]bool{
		"certificate.recorded":       true,
		"policy.decision":            true,
		"discovery.finding.recorded": true,
	}
	exact := auditRecordsByType(auditFixture(), cc7Types)
	rep, err := reporter.Generate(SOC2, exact, cbom(), testEvidenceWindow())
	if err != nil {
		t.Fatalf("Generate exact CC7 evidence: %v", err)
	}
	mustHaveControl(t, rep.Controls, "soc2-cc7-monitoring-audit-evidence", "evidenced")
	mustHaveControl(t, rep.Controls, "soc2-cc6-access-control", "gap")
	mustHaveControl(t, rep.Controls, "soc2-cc8-change-management-evidence", "gap")

	wrongTenant := append([]audit.Record(nil), exact...)
	for n := range wrongTenant {
		wrongTenant[n].TenantID = "t2"
	}
	rep, err = reporter.Generate(SOC2, wrongTenant, cbom(), testEvidenceWindow())
	if err != nil {
		t.Fatalf("Generate wrong-tenant evidence: %v", err)
	}
	mustHaveControl(t, rep.Controls, "soc2-cc7-monitoring-audit-evidence", "gap")

	stale := append([]audit.Record(nil), exact...)
	for n := range stale {
		stale[n].Time = testEvidenceWindow().From.Add(-time.Second)
	}
	rep, err = reporter.Generate(SOC2, stale, cbom(), testEvidenceWindow())
	if err != nil {
		t.Fatalf("Generate stale evidence: %v", err)
	}
	mustHaveControl(t, rep.Controls, "soc2-cc7-monitoring-audit-evidence", "gap")

	cc8Types := map[string]bool{
		"certificate.recorded":          true,
		"policy.version.authored":       true,
		"policy.version.activated":      true,
		"access.change_request.created": true,
		"access.change_request.decided": true,
	}
	rep, err = reporter.Generate(SOC2, auditRecordsByType(auditFixture(), cc8Types), cbom(), testEvidenceWindow())
	if err != nil {
		t.Fatalf("Generate exact CC8 evidence: %v", err)
	}
	mustHaveControl(t, rep.Controls, "soc2-cc8-change-management-evidence", "evidenced")
}

func TestEventRequirementsSelectOneDeterministicLatestReferenceAUD76(t *testing.T) {
	caKey, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer caKey.Destroy()
	reporter := New("t1", caKey)

	records := []audit.Record{
		{ID: "older", Sequence: 7, Type: "identity.issued", TenantID: "t1", Time: evidenceFixtureTime.Add(-time.Minute), Hash: "sha256:older"},
		{ID: "latest-lower-sequence", Sequence: 8, Type: "certificate.recorded", TenantID: "t1", Time: evidenceFixtureTime, Hash: "sha256:latest-lower"},
		{ID: "latest", Sequence: 9, Type: "identity.revoked", TenantID: "t1", Time: evidenceFixtureTime, Hash: "sha256:latest"},
	}
	rep, err := reporter.Generate(SOC2, records, cbom(), testEvidenceWindow())
	if err != nil {
		t.Fatalf("Generate bounded event evidence: %v", err)
	}
	control := controlByID(t, rep.Controls, "soc2-audit-trail")
	if len(control.EvidenceRefs) != 1 {
		t.Fatalf("audit-trail evidence refs = %d, want one deterministic existence witness: %+v", len(control.EvidenceRefs), control.EvidenceRefs)
	}
	if ref := control.EvidenceRefs[0]; ref.Ref != "event:latest" || ref.Sequence != 9 || ref.Digest != "sha256:latest" {
		t.Fatalf("audit-trail evidence ref = %+v, want latest event with sequence tie-break", ref)
	}
}

func auditRecordsByType(records []audit.Record, types map[string]bool) []audit.Record {
	out := make([]audit.Record, 0, len(records))
	for _, record := range records {
		if types[record.Type] {
			out = append(out, record)
		}
	}
	return out
}

func controlByID(t *testing.T, controls []Control, id string) Control {
	t.Helper()
	for _, control := range controls {
		if control.ID == id {
			return control
		}
	}
	t.Fatalf("missing control %s in %+v", id, controls)
	return Control{}
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
	rep, _ := r.Generate(SOC2, auditFixture(), cbom(), testEvidenceWindow())
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

func assertResolvableProductEvidence(t *testing.T, refs []string) {
	t.Helper()
	if len(refs) == 0 {
		t.Fatal("derived product evidence references are empty")
	}
	for _, ref := range refs {
		if !strings.HasPrefix(ref, "event:") && !strings.HasPrefix(ref, "object:") && !strings.HasPrefix(ref, "runtime:") {
			t.Fatalf("product evidence %q is an unresolvable capability phrase", ref)
		}
	}
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
	a, _ := r.Generate(PCIDSS, auditFixture(), cbom(), testEvidenceWindow())
	b, _ := r.Generate(PCIDSS, auditFixture(), cbom(), testEvidenceWindow())
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
