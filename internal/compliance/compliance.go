// Package compliance produces evidence packs and posture from the tamper-evident
// audit log (F9) and the CBOM (S20.5, F62): report templates for PCI-DSS, HIPAA,
// SOC 2, FedRAMP, and CNSA 2.0, posture over the live CBOM, and signed,
// reproducible exports. Reports derive from the audit log (AN-2). It does not
// overclaim — output separates what the product evidences from what the operator
// must still attest; evidence supports controls, it does not confer certification.
package compliance

import (
	"encoding/json"
	"fmt"

	"trustctl.io/trustctl/internal/auditsink"
	"trustctl.io/trustctl/internal/crypto"
	"trustctl.io/trustctl/internal/graph"
)

// Framework is a compliance framework.
type Framework string

const (
	PCIDSS  Framework = "pci-dss"
	HIPAA   Framework = "hipaa"
	SOC2    Framework = "soc2"
	FedRAMP Framework = "fedramp"
	CNSA2   Framework = "cnsa-2.0"
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
		ProductEvidences: []string{"tamper-evident audit log (F9)", "CBOM cryptographic inventory", "automated control evidence over the credential estate"},
		OperatorAttests:  []string{"physical & environmental security", "personnel security & training", "organizational policies & governance"},
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
		{ID: string(fw) + "-audit-trail", Title: "Tamper-evident audit trail of credential operations", Status: statusIf(hasAudit), Evidence: []string{"F9 audit log"}},
		{ID: string(fw) + "-key-management", Title: "Keys managed behind a hardened boundary (HSM-capable)", Status: "evidenced", Evidence: []string{"internal/crypto boundary (AN-3)", "isolated signer (AN-4)"}},
	}
	if fw == CNSA2 {
		controls = append(controls, Control{
			ID: string(fw) + "-pqc-adoption", Title: "Post-quantum algorithms in use", Status: statusIf(p.PostQuantum > 0 && p.QuantumVulnerable == 0), Evidence: []string{"CBOM classification", "PQC migration program (S14.4)"},
		})
	}
	return controls
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
