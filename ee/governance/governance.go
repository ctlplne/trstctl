// Package governance produces evidence packs and posture from the tamper-evident
// audit log (F9) and the CBOM (S20.5, F62): report templates for PCI-DSS, HIPAA,
// SOC 2, NIST SP 800-53, NIST CSF, FedRAMP, CMMC, CNSA 2.0, FIPS 140,
// Common Criteria, CA/Browser Forum Baseline Requirements, WebTrust, ETSI,
// eIDAS, and NIS2, posture over the live CBOM, and signed, reproducible
// exports. Reports derive from the audit log (AN-2). It does not overclaim:
// output separates what the product evidences from what the operator must still
// attest; evidence supports controls, it does not confer certification.
package governance

import (
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/compliance"
	"trstctl.com/trstctl/internal/crypto"
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

// Control is one evidenced control.
type Control struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Status   string   `json:"status"` // "evidenced" | "gap"
	Evidence []string `json:"evidence"`
}

// Posture summarizes cryptographic posture from the CBOM.
type Posture struct {
	TotalCryptoAssets int `json:"total_crypto_assets"`
	QuantumVulnerable int `json:"quantum_vulnerable"`
	PostQuantum       int `json:"post_quantum"`
}

// Report is a compliance evidence pack.
type Report struct {
	Framework        string                                     `json:"framework"`
	Controls         []Control                                  `json:"controls"`
	Posture          Posture                                    `json:"posture"`
	ProductEvidences []string                                   `json:"product_evidences"`
	OperatorAttests  []string                                   `json:"operator_attests"`
	FIPSProfile      *compliance.FIPSRegulatedDeploymentProfile `json:"fips_regulated_deployment_profile,omitempty"`
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

// Generate builds a framework report from the audit records and the CBOM. It is
// deterministic over the same inputs (reproducible).
func (r *Reporter) Generate(fw Framework, audit []auditsink.Record, cbom *graph.Graph) (Report, error) {
	p := posture(cbom)
	var fipsProfile *compliance.FIPSRegulatedDeploymentProfile
	if fw == FIPS140 {
		status, err := crypto.PowerOnSelfTest(false)
		if err != nil {
			return Report{}, fmt.Errorf("governance: fips power-on self-test: %w", err)
		}
		profile := compliance.RegulatedFIPSDeploymentProfile(status)
		if err := compliance.ValidateFIPSRegulatedDeploymentProfile(profile); err != nil {
			return Report{}, fmt.Errorf("governance: fips regulated deployment profile invalid: %w", err)
		}
		fipsProfile = &profile
	}
	return Report{
		Framework:        string(fw),
		Controls:         controlsFor(fw, p, len(audit) > 0),
		Posture:          p,
		ProductEvidences: productEvidencesFor(fw),
		OperatorAttests:  operatorAttestsFor(fw),
		FIPSProfile:      fipsProfile,
	}, nil
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
		if c, err := crypto.Classify(crypto.Algorithm(n.Attrs["algorithm"])); err == nil {
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

func statusIf(ok bool) string {
	if ok {
		return "evidenced"
	}
	return "gap"
}

func controlsFor(fw Framework, p Posture, hasAudit bool) []Control {
	controls := []Control{
		{ID: string(fw) + "-crypto-inventory", Title: "Cryptographic inventory maintained", Status: statusIf(p.TotalCryptoAssets > 0), Evidence: []string{"CBOM"}},
		{ID: string(fw) + "-audit-trail", Title: "Tamper-evident audit trail of credential operations", Status: statusIf(hasAudit), Evidence: []string{"signed audit evidence log"}},
		{ID: string(fw) + "-key-management", Title: "Keys managed behind a hardened boundary (HSM-capable)", Status: "evidenced", Evidence: []string{"cryptographic operation boundary", "isolated signing service"}},
	}
	if fw == CNSA2 {
		controls = append(controls, Control{
			ID: string(fw) + "-pqc-adoption", Title: "Post-quantum algorithms in use", Status: statusIf(p.PostQuantum > 0 && p.QuantumVulnerable == 0), Evidence: []string{"CBOM classification", "PQC migration program"},
		})
	}
	if fw == NIST80053 {
		controls = append(controls,
			Control{ID: "nist-800-53-au-evidence", Title: "Audit-event generation, review, and protection evidence is exportable", Status: statusIf(hasAudit), Evidence: []string{"signed audit evidence log", "AU-2/AU-6/AU-9/AU-12 mapping"}},
			Control{ID: "nist-800-53-ac-ia-evidence", Title: "NHI access and authenticator lifecycle evidence is mapped", Status: "evidenced", Evidence: []string{"NHI inventory", "least-privilege posture", "static credential posture"}},
			Control{ID: "nist-800-53-operator-tailoring-residual", Title: "Control tailoring, system boundary, and assessment evidence remain operator responsibilities", Status: "gap", Evidence: []string{"operator attestation", "system security plan", "assessment package"}},
		)
	}
	if fw == NISTCSF20 {
		controls = append(controls,
			Control{ID: "nist-csf-2.0-identify-protect-detect", Title: "Identify, Protect, and Detect functions have NHI evidence mappings", Status: "evidenced", Evidence: []string{"NHI inventory", "credential posture", "audit evidence"}},
			Control{ID: "nist-csf-2.0-govern-operator-residual", Title: "Govern and organizational risk strategy remain operator program responsibilities", Status: "gap", Evidence: []string{"operator attestation", "risk management program"}},
		)
	}
	if fw == FedRAMP {
		controls = append(controls,
			Control{ID: "fedramp-rev5-au-ac-ia-evidence", Title: "FedRAMP Rev. 5 AU/AC/IA evidence is mapped from audit, RBAC, and NHI posture", Status: "evidenced", Evidence: []string{"signed audit evidence log", "tenant RBAC", "NHI compliance mapping"}},
			Control{ID: "fedramp-rev5-authorization-residual", Title: "ATO package, boundary tailoring, and assessor artifacts remain operator responsibilities", Status: "gap", Evidence: []string{"system security plan", "security assessment report", "plan of action and milestones"}},
		)
	}
	if fw == CMMC20 {
		controls = append(controls,
			Control{ID: "cmmc-2.0-ac-ia-au-evidence", Title: "CMMC access control, identification, authenticator, and audit evidence is mapped", Status: "evidenced", Evidence: []string{"NHI inventory", "least-privilege posture", "static credential posture", "signed audit evidence log"}},
			Control{ID: "cmmc-2.0-cui-scope-residual", Title: "CUI scope, assessment level, and assessor package remain operator responsibilities", Status: "gap", Evidence: []string{"operator attestation", "CMMC assessment package"}},
		)
	}
	if fw == FIPS140 {
		controls = append(controls,
			Control{
				ID:       "fips-140-module-post",
				Title:    "FIPS-capable build path and fail-closed power-on self-test are evidenced",
				Status:   "evidenced",
				Evidence: []string{"make fips-build artifact gate", "--fips fail-closed POST", "crypto.fips.module_active posture"},
			},
			Control{
				ID:       "fips-140-crypto-boundary",
				Title:    "All product cryptography enters through the audited crypto boundary",
				Status:   "evidenced",
				Evidence: []string{"internal/crypto boundary", "architecture linter", "isolated signing service"},
			},
			Control{
				ID:       "fips-140-approved-algorithm-profile",
				Title:    "Approved-mode algorithms and modes are enumerated for the regulated deployment profile",
				Status:   "evidenced",
				Evidence: []string{"regulated FIPS deployment profile", "approved algorithm/mode allowlist", "Go FIPS module selector pin"},
			},
			Control{
				ID:       "fips-140-non-fips-pqc-fence",
				Title:    "PQC, hybrid, and Ed25519 paths are fenced out of approved-mode FIPS claims",
				Status:   "evidenced",
				Evidence: []string{"non-FIPS fence list", "internal/crypto/pqc boundary caveat", "approved-mode algorithm decision"},
			},
			Control{
				ID:       "fips-140-hsm-kms-validation-records",
				Title:    "External key-custody boundaries name required HSM/KMS validation certificate records",
				Status:   "evidenced",
				Evidence: []string{"HSM/KMS validation certificate requirements", "operator attestation", "deployment-specific key custody boundary"},
			},
			Control{
				ID:       "fips-140-cmvp-certificate-residual",
				Title:    "NIST CMVP validation certificate for the deployed module remains an external artifact",
				Status:   "gap",
				Evidence: []string{"operator attestation", "NIST CMVP certificate", "validated module configuration"},
			},
		)
	}
	if fw == CommonCriteria {
		controls = append(controls,
			Control{
				ID:       "common-criteria-security-target-evidence",
				Title:    "Security-target evidence map covers the served TOE controls",
				Status:   "evidenced",
				Evidence: []string{"security-target evidence map", "tenant isolation", "RBAC", "tamper-evident audit", "crypto boundary"},
			},
			Control{
				ID:       "common-criteria-configuration-management-evidence",
				Title:    "Configuration and lifecycle changes are attributable and signed",
				Status:   statusIf(hasAudit),
				Evidence: []string{"signed audit evidence log", "event-sourced change trail", "release artifact evidence"},
			},
			Control{
				ID:       "common-criteria-evaluation-residual",
				Title:    "External lab evaluation and certificate remain operator responsibilities",
				Status:   "gap",
				Evidence: []string{"external evaluation lab report", "Common Criteria certificate", "evaluated configuration guide"},
			},
		)
	}
	if fw == CABFBR {
		controls = append(controls,
			Control{
				ID:       "cabf-br-profile-lint",
				Title:    "TLS server-certificate profiles are linted against CA/Browser Forum Baseline Requirements",
				Status:   "evidenced",
				Evidence: []string{"profilelint structural CA/B checks", "external zlint corpus gate"},
			},
			Control{
				ID:       "cabf-br-ca-audit-trail",
				Title:    "CA issuance, profile decision, and revocation evidence is attributable and signed",
				Status:   statusIf(hasAudit),
				Evidence: []string{"certificate issuance/revocation events", "certificate profile decision evidence", "signed audit evidence log"},
			},
			Control{
				ID:       "cabf-br-key-protection",
				Title:    "CA private-key operations stay behind an isolated signing boundary",
				Status:   "evidenced",
				Evidence: []string{"isolated signing service", "cryptographic operation boundary", "HSM-capable backend"},
			},
			Control{
				ID:       "cabf-br-public-trust-residual",
				Title:    "Public-trust policy operation, CP/CPS publication, and independent audit remain operator responsibilities",
				Status:   "gap",
				Evidence: []string{"operator attestation", "external practitioner report", "CA/Browser Forum policy program"},
			},
		)
	}
	if fw == WebTrust {
		controls = append(controls,
			Control{
				ID:       "webtrust-ca-lifecycle",
				Title:    "CA certificate lifecycle operations are attributable and audit-trailed",
				Status:   statusIf(hasAudit),
				Evidence: []string{"certificate issuance/revocation events", "signed audit evidence log"},
			},
			Control{
				ID:       "webtrust-ca-key-protection",
				Title:    "CA private-key operations stay behind an isolated signing boundary",
				Status:   "evidenced",
				Evidence: []string{"isolated signing service", "cryptographic operation boundary", "HSM-capable backend"},
			},
			Control{
				ID:       "webtrust-cps-and-independent-audit",
				Title:    "CP/CPS publication and independent WebTrust practitioner opinion remain operator responsibilities",
				Status:   "gap",
				Evidence: []string{"operator attestation", "external practitioner report"},
			},
		)
	}
	if fw == ETSI {
		controls = append(controls,
			Control{
				ID:       "etsi-en-319-411-ca-operations",
				Title:    "CA operations evidence supports ETSI EN 319 411 control review",
				Status:   statusIf(hasAudit),
				Evidence: []string{"signed audit evidence log", "certificate profile decisions", "revocation events"},
			},
			Control{
				ID:       "etsi-en-319-411-key-management",
				Title:    "Key management posture is evidenced by signer isolation and cryptographic inventory",
				Status:   statusIf(p.TotalCryptoAssets > 0),
				Evidence: []string{"isolated signing service", "CBOM cryptographic inventory"},
			},
			Control{
				ID:       "etsi-conformity-assessment-residual",
				Title:    "Qualified trust-service status and external conformity assessment remain operator responsibilities",
				Status:   "gap",
				Evidence: []string{"operator attestation", "external conformity assessment"},
			},
		)
	}
	if fw == EIDAS {
		controls = append(controls,
			Control{ID: "eidas-trust-service-security-evidence", Title: "Trust-service security and lifecycle evidence is mapped from signed audit and CA/NHI posture", Status: statusIf(hasAudit), Evidence: []string{"signed audit evidence log", "certificate lifecycle evidence", "NHI compliance mapping"}},
			Control{ID: "eidas-qualified-status-residual", Title: "Qualified trust-service status and conformity assessment remain operator responsibilities", Status: "gap", Evidence: []string{"supervisory body evidence", "qualified status attestation", "external conformity assessment"}},
		)
	}
	if fw == NIS2 {
		controls = append(controls,
			Control{ID: "nis2-article-21-risk-measures", Title: "Cybersecurity risk-management evidence for NHI assets is mapped", Status: "evidenced", Evidence: []string{"NHI inventory", "credential posture", "least-privilege posture", "signed audit evidence log"}},
			Control{ID: "nis2-governance-reporting-residual", Title: "Management-body accountability, incident notification, and national transposition duties remain operator responsibilities", Status: "gap", Evidence: []string{"operator attestation", "incident notification process", "national transposition evidence"}},
		)
	}
	return controls
}

func productEvidencesFor(fw Framework) []string {
	evidence := []string{
		"tamper-evident audit log",
		"CBOM cryptographic inventory",
		"FIPS 203/204/205 migration posture from the CBOM",
		"automated control evidence over the credential estate",
	}
	if fw == CABFBR {
		evidence = append(evidence,
			"CA/Browser Forum profile lint evidence",
			"external zlint corpus gate",
			"served CA issuance and revocation audit evidence",
			"isolated signer and HSM-capable key-management posture",
		)
	}
	if fw == FIPS140 {
		evidence = append(evidence,
			"FIPS-capable build and fail-closed POST evidence",
			"crypto boundary routes product cryptography through the Go FIPS module when active",
			"CI fips-capable build artifact verification",
			"regulated FIPS deployment profile with pinned Go module selector",
			"approved algorithm/mode allowlist and non-FIPS PQC fence",
			"HSM/KMS validation certificate requirement records",
		)
	}
	if fw == CommonCriteria {
		evidence = append(evidence,
			"security-target evidence map over served controls",
			"TOE boundary evidence for API, signer, tenant isolation, audit, and crypto boundary",
			"signed audit/change-management evidence",
		)
	}
	if fw == WebTrust || fw == ETSI {
		evidence = append(evidence,
			"CA issuance and revocation audit evidence",
			"certificate profile decision evidence",
			"isolated signer and HSM-capable key-management posture",
		)
	}
	if fw == NIST80053 || fw == NISTCSF20 || fw == FedRAMP || fw == CMMC20 || fw == EIDAS || fw == NIS2 {
		evidence = append(evidence,
			"NHI inventory and posture evidence mappings",
			"least-privilege and stale-credential posture evidence",
			"static credential and rotation posture evidence",
			"signed audit evidence mapped to framework controls",
		)
	}
	return evidence
}

func operatorAttestsFor(fw Framework) []string {
	attests := []string{
		"physical & environmental security",
		"personnel security & training",
		"organizational policies & governance",
	}
	if fw == WebTrust {
		attests = append(attests, "CP/CPS publication", "WebTrust practitioner audit opinion", "CA/Browser Forum policy program operation")
	}
	if fw == CABFBR {
		attests = append(attests,
			"CP/CPS publication",
			"independent WebTrust practitioner opinion for public-trust issuance",
			"CA/Browser Forum policy program operation",
			"domain validation and CAA procedure evidence",
		)
	}
	if fw == FIPS140 {
		attests = append(attests,
			"NIST CMVP certificate number for the deployed validated module",
			"approved FIPS deployment configuration",
			"external module validation scope and vendor certificate",
			"HSM/KMS CMVP certificate references for each configured external key-custody boundary",
			"operator confirmation that PQC, hybrid, and Ed25519 paths are outside approved-mode FIPS issuance unless backed by a validated module",
		)
	}
	if fw == CommonCriteria {
		attests = append(attests,
			"Common Criteria certificate and evaluation report",
			"protection profile and TOE security target approved by the lab",
			"evaluated configuration guide and lab verdict",
		)
	}
	if fw == ETSI {
		attests = append(attests, "ETSI conformity assessment", "qualified trust-service status where applicable", "subscriber registration authority procedures")
	}
	if fw == NIST80053 {
		attests = append(attests, "NIST SP 800-53 control tailoring", "system boundary and SSP", "assessment results and POA&M")
	}
	if fw == NISTCSF20 {
		attests = append(attests, "NIST CSF organizational profile", "risk appetite and governance strategy", "target profile acceptance")
	}
	if fw == FedRAMP {
		attests = append(attests, "FedRAMP authorization package", "agency or JAB authorization decision", "continuous monitoring package")
	}
	if fw == CMMC20 {
		attests = append(attests, "CMMC scope and CUI boundary", "assessment level and assessor package", "organization-level policy evidence")
	}
	if fw == EIDAS {
		attests = append(attests, "qualified trust-service status if claimed", "eIDAS conformity assessment", "supervisory body notification evidence")
	}
	if fw == NIS2 {
		attests = append(attests, "NIS2 entity scope and national transposition obligations", "management-body accountability evidence", "incident notification process")
	}
	return attests
}

// signedEnvelope is the signed, verifiable export form.
type signedEnvelope struct {
	Manifest  json.RawMessage `json:"manifest"`
	Signature []byte          `json:"signature"`
}

// Export marshals the report deterministically and signs the manifest, producing a
// verifiable evidence export.
func (r *Reporter) Export(rep Report) ([]byte, error) {
	manifest, err := json.Marshal(rep) // deterministic: no maps, ordered slices
	if err != nil {
		return nil, err
	}
	sig, err := crypto.SignMessage(r.signer, manifest)
	if err != nil {
		return nil, fmt.Errorf("compliance: sign export: %w", err)
	}
	return json.Marshal(signedEnvelope{Manifest: manifest, Signature: sig})
}

// Verify checks a signed export against the reporter's public key, returning the
// report manifest if valid.
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
