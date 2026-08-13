// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package governance produces signed, tenant-bound compliance evidence packs
// from the immutable audit chain and current tenant CBOM/credential graph. A
// control is evidenced only when its named event/object prerequisites exist in
// the signed coverage window; missing prerequisites remain explicit gaps.
// Evidence supports an auditor's review. It never confers certification.
package governance

import (
	"encoding/json"
	"fmt"
	"time"

	eepqc "trstctl.com/trstctl/ee/pqc"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/compliance"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/cryptoreadiness"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/graph"
)

// Framework is a compliance framework.
type Framework = api.ComplianceFramework

const (
	PCIDSS         Framework = api.CompliancePCIDSS
	HIPAA          Framework = api.ComplianceHIPAA
	SOC2           Framework = api.ComplianceSOC2
	NIST80053      Framework = api.ComplianceNIST80053
	NISTCSF20      Framework = api.ComplianceNISTCSF20
	FedRAMP        Framework = api.ComplianceFedRAMP
	CMMC20         Framework = api.ComplianceCMMC20
	CNSA2          Framework = api.ComplianceCNSA2
	FIPS140        Framework = api.ComplianceFIPS140
	CommonCriteria Framework = api.ComplianceCommonCriteria
	CABFBR         Framework = api.ComplianceCABFBR
	WebTrust       Framework = api.ComplianceWebTrust
	ETSI           Framework = api.ComplianceETSI
	EIDAS          Framework = api.ComplianceEIDAS
	NIS2           Framework = api.ComplianceNIS2
)

// Control is one evaluated framework control. Evidence contains the satisfied
// prerequisite labels; EvidenceRefs contains their exact signed references;
// Missing names every prerequisite that prevented an evidenced verdict.
type Control struct {
	ID           string              `json:"id"`
	Title        string              `json:"title"`
	Status       string              `json:"status"` // "evidenced" | "gap" | "unknown"
	Evidence     []string            `json:"evidence"`
	EvidenceRefs []EvidenceReference `json:"evidence_refs"`
	Missing      []string            `json:"missing"`
	Window       EvidenceWindow      `json:"coverage_window"`
}

// Posture summarizes cryptographic posture from the tenant CBOM.
type Posture struct {
	TotalCryptoAssets int `json:"total_crypto_assets"`
	QuantumVulnerable int `json:"quantum_vulnerable"`
	PostQuantum       int `json:"post_quantum"`
}

// Report is the signed compliance evidence-pack manifest.
type Report struct {
	TenantID         string                                     `json:"tenant_id"`
	Framework        string                                     `json:"framework"`
	GeneratedAt      time.Time                                  `json:"generated_at"`
	EvidenceWindow   EvidenceWindow                             `json:"evidence_window"`
	Controls         []Control                                  `json:"controls"`
	Posture          Posture                                    `json:"posture"`
	Custody          custody.CertificateSummary                 `json:"custody"`
	ProductEvidences []string                                   `json:"product_evidences"`
	OperatorAttests  []string                                   `json:"operator_attests"`
	FIPSProfile      *compliance.FIPSRegulatedDeploymentProfile `json:"fips_regulated_deployment_profile,omitempty"`
	ADCS             api.ADCSComplianceEvidence                 `json:"adcs"`
	CryptoReadiness  cryptoreadiness.Dataset                    `json:"crypto_readiness"`
}

// Reporter generates and signs reports.
type Reporter struct {
	tenantID string
	signer   crypto.DigestSigner
}

// New constructs a Reporter.
func New(tenantID string, signer crypto.DigestSigner) *Reporter {
	return &Reporter{tenantID: tenantID, signer: signer}
}

// Generate builds a deterministic report over the exact supplied evidence
// inputs and inclusive coverage window.
func (r *Reporter) Generate(fw Framework, records []audit.Record, cbom *graph.Graph, window EvidenceWindow) (Report, error) {
	tenantID := normalizedTenantID(r.tenantID)
	if tenantID == "" {
		return Report{}, fmt.Errorf("governance: report requires a tenant")
	}
	if !validEvidenceWindow(window) {
		return Report{}, fmt.Errorf("governance: report requires a bounded evidence window")
	}
	p := posture(cbom)
	c := custodyPosture(cbom)
	idx := newEvidenceIndex(tenantID, records, cbom, window)
	adcsEvidence, err := buildADCSComplianceEvidence(tenantID, records, window)
	if err != nil {
		return Report{}, err
	}
	readiness, err := cryptoreadiness.FromGraph(tenantID, cbom, nil)
	if err != nil {
		return Report{}, fmt.Errorf("governance: build crypto readiness: %w", err)
	}
	var fipsProfile *compliance.FIPSRegulatedDeploymentProfile
	if fw == FIPS140 {
		status, err := crypto.PowerOnSelfTest(false)
		if err != nil {
			return Report{}, fmt.Errorf("governance: fips power-on self-test: %w", err)
		}
		profile := compliance.RegulatedFIPSDeploymentProfile(status)
		profile.NonFIPSFences = append(profile.NonFIPSFences, pqcFIPSFence())
		profile.EvidenceRefs = append(profile.EvidenceRefs, "code:ee/pqc/doc.go")
		if err := compliance.ValidateFIPSRegulatedDeploymentProfile(profile); err != nil {
			return Report{}, fmt.Errorf("governance: fips regulated deployment profile invalid: %w", err)
		}
		fipsProfile = &profile
		if status.ModuleActive && status.SelfTestPassed {
			idx.addRuntime("fips-post", "crypto.fips.module_active")
		}
	}
	controls := controlsFor(fw, p, idx)
	return Report{
		TenantID: tenantID, Framework: string(fw), GeneratedAt: window.Through,
		EvidenceWindow: window, Controls: controls, Posture: p, Custody: c,
		ProductEvidences: productEvidencesFor(controls), OperatorAttests: operatorAttestsFor(fw),
		FIPSProfile: fipsProfile, ADCS: adcsEvidence, CryptoReadiness: readiness,
	}, nil
}

func custodyPosture(g *graph.Graph) custody.CertificateSummary {
	var certificates []custody.CertificateEvidence
	if g != nil {
		for _, node := range g.Nodes() {
			if node.Kind != graph.KindCredential || node.Attrs["credential_kind"] != "certificate" {
				continue
			}
			certificates = append(certificates, custody.CertificateEvidence{
				ID: node.Attrs["certificate_id"], Fingerprint: node.Attrs["fingerprint"],
				Subject: node.Attrs["subject"],
				Record: custody.Record{
					Origin:      custody.KeyOrigin(node.Attrs["key_origin"]),
					Storage:     custody.StorageClass(node.Attrs["key_storage"]),
					Exportable:  custody.Exportability(node.Attrs["key_exportable"]),
					GeneratedBy: node.Attrs["key_generated_by"],
				},
			})
		}
	}
	return custody.SummarizeCertificates(certificates)
}

func posture(g *graph.Graph) Posture {
	var p Posture
	if g == nil {
		return p
	}
	for _, n := range g.Nodes() {
		if n.Kind != graph.KindCryptoAsset {
			continue
		}
		p.TotalCryptoAssets++
		if c, err := classifyLicensedAlgorithm(crypto.Algorithm(n.Attrs["algorithm"])); err == nil {
			if c.QuantumVulnerable {
				p.QuantumVulnerable++
			}
			if c.PostQuantum {
				p.PostQuantum++
			}
		}
	}
	return p
}

func classifyLicensedAlgorithm(alg crypto.Algorithm) (crypto.Classification, error) {
	if c, err := crypto.Classify(alg); err == nil {
		return c, nil
	}
	switch alg {
	case eepqc.MLDSA44, eepqc.MLDSA65, eepqc.MLDSA87:
		return crypto.Classification{Algorithm: alg, Family: "ML-DSA", Kind: "signature", PostQuantum: true}, nil
	case eepqc.MLKEM512, eepqc.MLKEM768, eepqc.MLKEM1024:
		return crypto.Classification{Algorithm: alg, Family: "ML-KEM", Kind: "kem", PostQuantum: true}, nil
	case eepqc.SLHDSA128s, eepqc.SLHDSA128f, eepqc.SLHDSA192s, eepqc.SLHDSA256s:
		return crypto.Classification{Algorithm: alg, Family: "SLH-DSA", Kind: "signature", PostQuantum: true}, nil
	case eepqc.HybridEd25519Dilithium3, crypto.Algorithm(eepqc.HybridMLDSA44ECDSAP256Algorithm):
		return crypto.Classification{Algorithm: alg, Family: "Hybrid", Kind: "signature", PostQuantum: true}, nil
	default:
		return crypto.Classification{}, fmt.Errorf("governance: unknown algorithm %q", alg)
	}
}

func pqcFIPSFence() compliance.FIPSNonFIPSFence {
	return compliance.FIPSNonFIPSFence{
		Surface: "ee/pqc",
		Algorithms: []string{
			string(eepqc.MLDSA44), string(eepqc.MLDSA65), string(eepqc.MLDSA87),
			string(eepqc.MLKEM512), string(eepqc.MLKEM768), string(eepqc.MLKEM1024),
			string(eepqc.SLHDSA128s), string(eepqc.SLHDSA128f), string(eepqc.SLHDSA192s), string(eepqc.SLHDSA256s),
		},
		StatusUnderFIPS: "fenced: not eligible for approved-mode issuance unless the operation is supplied by a validated module boundary",
		Reason:          "The licensed PQC implementations are outside the Go FIPS 140-3 module boundary even though the algorithms map to FIPS 203/204/205 migration posture.",
		Action:          "Treat as non-FIPS migration evidence in --fips deployments, or route the operation to a validated PQC module/HSM before claiming approved mode.",
		EvidenceRef:     "ee/pqc/doc.go",
	}
}

func operatorAttestsFor(fw Framework) []string {
	attests := []string{
		"physical & environmental security",
		"personnel security & training",
		"organizational policies & governance",
	}
	switch fw {
	case WebTrust:
		attests = append(attests, "CP/CPS publication", "WebTrust practitioner audit opinion", "CA/Browser Forum policy program operation")
	case CABFBR:
		attests = append(attests, "CP/CPS publication", "independent WebTrust practitioner opinion for public-trust issuance", "CA/Browser Forum policy program operation", "domain validation and CAA procedure evidence")
	case FIPS140:
		attests = append(attests, "NIST CMVP certificate number for the deployed validated module", "approved FIPS deployment configuration", "external module validation scope and vendor certificate", "HSM/KMS CMVP certificate references for each configured external key-custody boundary", "operator confirmation that PQC, hybrid, and Ed25519 paths are outside approved-mode FIPS issuance unless backed by a validated module")
	case CommonCriteria:
		attests = append(attests, "Common Criteria certificate and evaluation report", "protection profile and TOE security target approved by the lab", "evaluated configuration guide and lab verdict")
	case ETSI:
		attests = append(attests, "ETSI conformity assessment", "qualified trust-service status where applicable", "subscriber registration authority procedures")
	case NIST80053:
		attests = append(attests, "NIST SP 800-53 control tailoring", "system boundary and SSP", "assessment results and POA&M")
	case NISTCSF20:
		attests = append(attests, "NIST CSF organizational profile", "risk appetite and governance strategy", "target profile acceptance")
	case SOC2:
		attests = append(attests, "SOC 2 trust-services category scope", "management assertion", "independent CPA SOC 2 examination report", "control operating-effectiveness sampling", "subservice organization carve-outs")
	case FedRAMP:
		attests = append(attests, "FedRAMP authorization package", "agency or JAB authorization decision", "continuous monitoring package")
	case CMMC20:
		attests = append(attests, "CMMC scope and CUI boundary", "assessment level and assessor package", "organization-level policy evidence")
	case EIDAS:
		attests = append(attests, "qualified trust-service status if claimed", "eIDAS conformity assessment", "supervisory body notification evidence")
	case NIS2:
		attests = append(attests, "NIS2 entity scope and national transposition obligations", "management-body accountability evidence", "incident notification process")
	}
	return attests
}

type signedEnvelope struct {
	Manifest  json.RawMessage `json:"manifest"`
	Signature []byte          `json:"signature"`
}

// Export deterministically marshals and signs the tenant-bound manifest.
func (r *Reporter) Export(rep Report) ([]byte, error) {
	manifest, err := json.Marshal(rep)
	if err != nil {
		return nil, err
	}
	sig, err := crypto.SignMessage(r.signer, manifest)
	if err != nil {
		return nil, fmt.Errorf("compliance: sign export: %w", err)
	}
	return json.Marshal(signedEnvelope{Manifest: manifest, Signature: sig})
}

// Verify checks a signed export and returns its manifest.
func Verify(signed, pubDER []byte) (json.RawMessage, error) {
	var env signedEnvelope
	if err := json.Unmarshal(signed, &env); err != nil {
		return nil, fmt.Errorf("compliance: parse export: %w", err)
	}
	if err := crypto.VerifyMessage(pubDER, env.Manifest, env.Signature); err != nil {
		return nil, fmt.Errorf("compliance: export signature invalid: %w", err)
	}
	return env.Manifest, nil
}
