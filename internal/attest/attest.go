// Package attest is the attestation template (S11.2, F30): it makes attestation a
// first-class entity so every credential issuance can record the verifiable proof
// — hardware, cloud, or platform — that justified it, and so each concrete
// attester (S11.3–S11.8) is a small sprint that implements *only* verification.
//
// An Attestor turns a raw proof payload into a verified Attestation or an error.
// The Verifier runs the right attestor, records the attestation in the credential
// graph (F30), binds it to the issuance event it justified (AN-2), and is
// tenant-scoped (AN-1). A forged or invalid proof is rejected and records
// nothing — the failure path is the whole point.
package attest

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/graph"
)

// Attestation is the verified proof that justified an issuance.
type Attestation struct {
	ID         string            `json:"id"`        // stable id: hash(method|subject)
	Method     string            `json:"method"`    // "tpm", "aws_iid", "k8s_sat", "github_oidc", ...
	Subject    string            `json:"subject"`   // the verified principal (instance id, SA, repo, ...)
	Selectors  []string          `json:"selectors"` // attributes derived from the proof, for entry matching
	Claims     map[string]string `json:"claims"`    // method-specific verified attributes
	VerifiedAt time.Time         `json:"verified_at"`
}

// Attestor verifies a proof payload from one source. It implements ONLY
// verification; the template handles binding, audit, and graph mapping. A genuine
// proof yields a populated Attestation (Method/Subject/Selectors set); a forged or
// malformed proof yields an error.
type Attestor interface {
	Method() string
	Attest(ctx context.Context, payload []byte) (Attestation, error)
}

// Verifier runs attestors and binds their results to issuance.
type Verifier struct {
	attestors map[string]Attestor
	audit     auditsink.Auditor
	graph     *graph.Graph
	tenantID  string
	clock     func() time.Time
}

// Config configures a Verifier.
type Config struct {
	TenantID  string
	Attestors []Attestor
	Audit     auditsink.Auditor // AN-2; nil = no-op
	Graph     *graph.Graph      // F30; nil = not mapped
	Clock     func() time.Time
}

// NewVerifier validates the configuration and constructs a Verifier.
func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("attest: TenantID is required (AN-1)")
	}
	m := make(map[string]Attestor, len(cfg.Attestors))
	for _, a := range cfg.Attestors {
		if a == nil || a.Method() == "" {
			return nil, fmt.Errorf("attest: attestor with empty method")
		}
		if _, dup := m[a.Method()]; dup {
			return nil, fmt.Errorf("attest: duplicate attestor for method %q", a.Method())
		}
		m[a.Method()] = a
	}
	if cfg.Audit == nil {
		cfg.Audit = auditsink.Nop{}
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Verifier{attestors: m, audit: cfg.Audit, graph: cfg.Graph, tenantID: cfg.TenantID, clock: cfg.Clock}, nil
}

// Verify selects the attestor for method, verifies payload, normalizes the
// result, records it in the graph, and audits it. A failed verification returns
// an error and records nothing (fail-closed).
func (v *Verifier) Verify(ctx context.Context, method string, payload []byte) (Attestation, error) {
	a, ok := v.attestors[method]
	if !ok {
		return Attestation{}, fmt.Errorf("attest: no attestor for method %q", method)
	}
	att, err := a.Attest(ctx, payload)
	if err != nil {
		_ = auditsink.Emit(ctx, v.audit, nil, "attestation.rejected", v.tenantID,
			[]byte(fmt.Sprintf(`{"method":%q,"error":%q}`, method, err.Error())))
		return Attestation{}, fmt.Errorf("attest: %s verification failed: %w", method, err)
	}
	if att.Subject == "" {
		return Attestation{}, fmt.Errorf("attest: %s returned an attestation with no subject", method)
	}
	att.Method = method
	att.VerifiedAt = v.clock().UTC()
	att.ID = AttestationID(method, att.Subject)
	sort.Strings(att.Selectors)

	if v.graph != nil {
		attrs := map[string]string{"tenant_id": v.tenantID, "method": method, "subject": att.Subject}
		v.graph.AddNode(graph.Node{ID: att.ID, Kind: graph.KindAttestation, Name: method + ":" + att.Subject, Attrs: attrs})
	}
	data, _ := json.Marshal(att)
	_ = auditsink.Emit(ctx, v.audit, nil, "attestation.verified", v.tenantID, data)
	return att, nil
}

// Bind links a verified attestation to the issuance it justified: it emits an
// audited "attestation.bound" event and, in the graph, an edge from the
// credential to the attestation it exhibits (F30).
func (v *Verifier) Bind(ctx context.Context, att Attestation, credentialID string) error {
	if att.ID == "" || credentialID == "" {
		return fmt.Errorf("attest: Bind requires both an attestation and a credential id")
	}
	if v.graph != nil {
		v.graph.AddEdge(graph.Edge{From: credentialID, To: att.ID, Type: graph.EdgeExhibits})
	}
	return v.audit.Audit(ctx, "attestation.bound", v.tenantID,
		[]byte(fmt.Sprintf(`{"attestation_id":%q,"credential_id":%q,"method":%q}`, att.ID, credentialID, att.Method)))
}

// AttestationID is the stable id for an attestation of subject by method. The
// hash is computed through the crypto boundary (AN-3).
func AttestationID(method, subject string) string {
	return "att:" + crypto.SHA256Hex([]byte(method + "|" + subject))[:32]
}

// Conform exercises an Attestor against a genuine and a forged payload and asserts
// it accepts the genuine proof (with a non-empty subject) and rejects the forgery.
// Every S11.3–S11.8 attester must pass this — the both-paths contract from the
// template.
func Conform(a Attestor, good, forged []byte) error {
	if a == nil {
		return fmt.Errorf("attest: nil attestor")
	}
	if a.Method() == "" {
		return fmt.Errorf("attest: attestor has empty method")
	}
	att, err := a.Attest(context.Background(), good)
	if err != nil {
		return fmt.Errorf("attest: %s rejected a genuine payload: %w", a.Method(), err)
	}
	if att.Subject == "" {
		return fmt.Errorf("attest: %s accepted a genuine payload but established no subject", a.Method())
	}
	if _, err := a.Attest(context.Background(), forged); err == nil {
		return fmt.Errorf("attest: %s ACCEPTED a forged payload (must fail closed)", a.Method())
	}
	return nil
}
