// Package governance produces evidence packs and posture from the tamper-evident
// audit log (F9) and the CBOM (S20.5, F62): report templates for PCI-DSS, HIPAA,
// SOC 2, FedRAMP, CNSA 2.0, WebTrust, and ETSI, posture over the live CBOM, and signed,
// reproducible exports. Reports derive from the audit log (AN-2). It does not
// overclaim — output separates what the product evidences from what the operator
// must still attest; evidence supports controls, it does not confer certification.
package governance

import (
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/graph"
)

// Framework is a compliance framework.
type Framework = api.ComplianceFramework

const (
	PCIDSS   Framework = api.CompliancePCIDSS
	HIPAA    Framework = api.ComplianceHIPAA
	SOC2     Framework = api.ComplianceSOC2
	FedRAMP  Framework = api.ComplianceFedRAMP
	CNSA2    Framework = api.ComplianceCNSA2
	WebTrust Framework = api.ComplianceWebTrust
	ETSI     Framework = api.ComplianceETSI
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
	Framework        string    `json:"framework"`
	Controls         []Control `json:"controls"`
	Posture          Posture   `json:"posture"`
	ProductEvidences []string  `json:"product_evidences"`
	OperatorAttests  []string  `json:"operator_attests"`
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
	return Report{
		Framework:        string(fw),
		Controls:         controlsFor(fw, p, len(audit) > 0),
		Posture:          p,
		ProductEvidences: productEvidencesFor(fw),
		OperatorAttests:  operatorAttestsFor(fw),
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
	return controls
}

func productEvidencesFor(fw Framework) []string {
	evidence := []string{
		"tamper-evident audit log",
		"CBOM cryptographic inventory",
		"FIPS 203/204/205 migration posture from the CBOM",
		"automated control evidence over the credential estate",
	}
	if fw == WebTrust || fw == ETSI {
		evidence = append(evidence,
			"CA issuance and revocation audit evidence",
			"certificate profile decision evidence",
			"isolated signer and HSM-capable key-management posture",
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
	if fw == ETSI {
		attests = append(attests, "ETSI conformity assessment", "qualified trust-service status where applicable", "subscriber registration authority procedures")
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
