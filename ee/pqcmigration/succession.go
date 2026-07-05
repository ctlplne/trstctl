// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqcmigration

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	eepqc "trstctl.com/trstctl/ee/pqc"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/policy"
)

// succession.go wires the PQC migration planner (BuildPlan) to the PCAS succession
// engine (PCAS-08): instead of a bare Reissue, a quantum-vulnerable credential is
// planned as a SuccessionJob carrying the policy-decided target algorithm and a
// reproducible policy_ref that PCAS-05 verifies under claim 23. Planning spans the
// claim-9 identity/credential genus (X.509, SSH, workload-identity SVID, API token,
// secret). The target is chosen under internal/policy (OPA, bulkheaded), consumed
// read-only. The classical→hybrid posture is served today; a hybrid→pure-PQC seam
// is laid for the cutover gated by PCAS-10.

// succDecisionSchema versions the recorded decision so a policy_ref is stable and
// an auditor knows exactly which fields it digests.
const succDecisionSchema = 1

// CredentialType is a member of the claim-9 identity/credential genus that a
// succession can be planned for.
type CredentialType string

const (
	CredentialX509         CredentialType = "x509"          // X.509 certificate subject key
	CredentialSSH          CredentialType = "ssh"           // SSH host/user key
	CredentialWorkloadSVID CredentialType = "workload-svid" // SPIFFE/SPIRE workload identity
	CredentialAPIToken     CredentialType = "api-token"     // signed API token / JWT signing key
	CredentialSecret       CredentialType = "secret"        // managed secret / MAC / wrapping key
)

// PlannableCredentialTypes returns the claim-9 genus each of whose members maps to
// a plannable succession.
func PlannableCredentialTypes() []CredentialType {
	return []CredentialType{
		CredentialX509, CredentialSSH, CredentialWorkloadSVID, CredentialAPIToken, CredentialSecret,
	}
}

// Plannable reports whether c is a member of the plannable succession genus.
func (c CredentialType) Plannable() bool {
	for _, k := range PlannableCredentialTypes() {
		if c == k {
			return true
		}
	}
	return false
}

// Posture selects the target/effective algorithm pair for a succession. The
// classical→hybrid posture is the served path; the hybrid→pure-PQC posture is the
// seam whose cutover is gated by PCAS-10 (evidence-gated retirement).
type Posture string

const (
	// PostureClassicalToHybrid targets an ML-DSA-65 key deployed behind a hybrid
	// composite leaf so stock X.509/TLS clients keep verifying (served today).
	PostureClassicalToHybrid Posture = "classical->hybrid"
	// PostureHybridToPurePQC targets an ML-DSA-65 key deployed as a pure PQC leaf,
	// relaxing the hybrid-effective restriction over time (seam; cutover = PCAS-10).
	PostureHybridToPurePQC Posture = "hybrid->pure-pqc"
)

// target returns the registry target algorithm and the effective deployed leaf for
// the posture. Both postures target ML-DSA-65 as the key algorithm; the posture
// selects only the effective leaf (hybrid composite vs. pure), which is what
// relaxes over the transition (the pure-subject residual stays explicit until the
// cutover gate).
func (p Posture) target() (target, effective string) {
	switch p {
	case PostureHybridToPurePQC:
		return TargetMLDSA65, string(eepqc.MLDSA65)
	default:
		return TargetMLDSA65, EffectiveHybridTLS
	}
}

// Decision is the recorded, replayable policy decision that determines a job's
// target and authorizes it. Its digest is the job's policy_ref: an auditor
// recomputes it from this record alone, so it is reproducible and tamper-evident
// (acceptance 2). It carries only scalar fields in a fixed order — no maps — so the
// JSON encoding is deterministic.
type Decision struct {
	SchemaVersion      int            `json:"schema_version"`
	AssetID            string         `json:"asset_id"`
	IdentityID         string         `json:"identity_id"`
	CredentialType     CredentialType `json:"credential_type"`
	PredecessorAlg     string         `json:"predecessor_alg"`
	TargetAlgorithm    string         `json:"target_algorithm"`
	EffectiveAlgorithm string         `json:"effective_algorithm"`
	Posture            string         `json:"posture"`
	Allow              bool           `json:"allow"`
	Reason             string         `json:"reason"`
	PolicyModuleSHA256 string         `json:"policy_module_sha256"`
}

// PolicyRef is the reproducible reference to a recorded decision: the hex SHA-256
// of the canonical JSON encoding of d, hashed through the core AN-3 boundary. It is
// the value carried into the PCAS-04 commitment as policy_ref (claim 23). Equal
// decisions yield equal refs; any change to any field changes the ref.
func PolicyRef(d Decision) string {
	b, _ := json.Marshal(d)
	return "sha256:" + hex.EncodeToString(crypto.SHA256Sum(b))
}

// DecisionInput is the per-credential input a Decider evaluates.
type DecisionInput struct {
	TenantID       string
	AssetID        string
	IdentityID     string
	CredentialType CredentialType
	PredecessorAlg string
}

// Decider determines the succession target for a credential and authorizes it,
// returning a recorded Decision whose digest is the policy_ref.
type Decider interface {
	Decide(ctx context.Context, in DecisionInput) (Decision, error)
}

// baseDecision fills the deterministic, policy-independent fields of a decision for
// in under posture, leaving Allow/Reason to the concrete Decider.
func baseDecision(in DecisionInput, posture Posture, moduleSHA string) Decision {
	target, effective := posture.target()
	return Decision{
		SchemaVersion:      succDecisionSchema,
		AssetID:            in.AssetID,
		IdentityID:         in.IdentityID,
		CredentialType:     in.CredentialType,
		PredecessorAlg:     in.PredecessorAlg,
		TargetAlgorithm:    target,
		EffectiveAlgorithm: effective,
		Posture:            string(posture),
		PolicyModuleSHA256: moduleSHA,
	}
}

// StaticDecider decides under a fixed posture with no OPA evaluation. It authorizes
// every plannable credential unless an optional Deny veto fires. It is used offline
// (no policy engine) and in tests; the OPA-backed PolicyDecider is the served path.
type StaticDecider struct {
	Posture Posture
	// Deny optionally vetoes a credential, returning (true, reason) to deny it.
	Deny func(DecisionInput) (bool, string)
}

// Decide implements Decider.
func (s StaticDecider) Decide(_ context.Context, in DecisionInput) (Decision, error) {
	d := baseDecision(in, s.postureOrDefault(), "static")
	d.Allow, d.Reason = true, "authorized by static succession posture"
	if s.Deny != nil {
		if deny, reason := s.Deny(in); deny {
			d.Allow, d.Reason = false, reason
		}
	}
	return d, nil
}

func (s StaticDecider) postureOrDefault() Posture {
	if s.Posture == "" {
		return PostureClassicalToHybrid
	}
	return s.Posture
}

// PolicyDecider decides the succession target under an embedded OPA/Rego policy
// (internal/policy), consumed read-only. The policy authorizes the target as an
// issue-action gate; the decision records the policy module's SHA-256 so the
// policy_ref is bound to the exact policy that authorized it (reproducibility).
type PolicyDecider struct {
	engine    *policy.Engine
	moduleSHA string
	posture   Posture
}

// NewPolicyDecider compiles module into a policy engine and returns a decider under
// posture. An empty module uses policy.BaseModule (deny-by-default, issue permitted
// with a bound profile). The recorded module digest is over the effective module.
func NewPolicyDecider(module string, posture Posture) (*PolicyDecider, error) {
	eng, err := policy.New(policy.Config{Module: module})
	if err != nil {
		return nil, fmt.Errorf("pqcmigration: compile succession policy: %w", err)
	}
	effective := module
	if effective == "" {
		effective = policy.BaseModule
	}
	if posture == "" {
		posture = PostureClassicalToHybrid
	}
	sha := hex.EncodeToString(crypto.SHA256Sum([]byte(effective)))
	return &PolicyDecider{engine: eng, moduleSHA: sha, posture: posture}, nil
}

// Decide implements Decider. It evaluates the issue-action policy for the credential
// and target, then records the authorization outcome. The successor is chosen by the
// posture; the policy is a default-deny gate over it.
func (d *PolicyDecider) Decide(ctx context.Context, in DecisionInput) (Decision, error) {
	dec := baseDecision(in, d.posture, d.moduleSHA)
	pd, err := d.engine.Evaluate(ctx, policy.Input{
		Action:   policy.ActionIssue,
		TenantID: in.TenantID,
		Subject:  in.IdentityID,
		Profile:  string(in.CredentialType),
		Attrs: map[string]any{
			"current_algorithm":   in.PredecessorAlg,
			"target_algorithm":    dec.TargetAlgorithm,
			"effective_algorithm": dec.EffectiveAlgorithm,
			"credential_type":     string(in.CredentialType),
		},
	})
	if err != nil {
		return Decision{}, fmt.Errorf("pqcmigration: succession policy evaluate: %w", err)
	}
	dec.Allow, dec.Reason = pd.Allow, pd.Reason
	return dec, nil
}

// SuccessionJob is a planned algorithm succession for one credential, carrying the
// policy-decided target and a reproducible policy_ref, ready to drive a PCAS-08
// succession job (mapped to a signer MintRequest by the orchestrator glue). It
// replaces the bare Reissue on the PCAS path.
type SuccessionJob struct {
	AssetID            string
	IdentityID         string
	CredentialType     CredentialType
	PredecessorAlg     string
	TargetAlgorithm    string
	EffectiveAlgorithm string
	Protocol           string
	RollbackOnFailure  bool
	Decision           Decision
	PolicyRef          string
}

// Credential is a discovered credential to plan a succession for, spanning the
// claim-9 genus. Cert-key credentials are typically produced from a BuildPlan via
// CredentialsFromPlan; other genus members are supplied directly.
type Credential struct {
	AssetID           string
	IdentityID        string
	Type              CredentialType
	Algorithm         string
	QuantumVulnerable bool
	Protocol          string
	RollbackOnFailure bool
}

// BuildSuccessionJobs plans a succession for each quantum-vulnerable, plannable
// credential, deciding the target under decider and computing a reproducible
// policy_ref. Non-vulnerable, non-plannable, and policy-denied credentials become
// explicit residuals rather than silent drops. Planning is deterministic: the same
// inputs yield the same jobs and residuals in the same order (acceptance 3).
func BuildSuccessionJobs(ctx context.Context, creds []Credential, decider Decider) ([]SuccessionJob, []Residual, error) {
	if decider == nil {
		return nil, nil, fmt.Errorf("pqcmigration: a succession Decider is required")
	}
	jobs := make([]SuccessionJob, 0, len(creds))
	residuals := ResidualDenominator()
	for _, c := range creds {
		if !c.QuantumVulnerable {
			residuals = append(residuals, Residual{ID: c.AssetID, Status: "not_planned", Reason: "credential is not quantum-vulnerable"})
			continue
		}
		if !c.Type.Plannable() {
			residuals = append(residuals, Residual{ID: c.AssetID, Status: "not_planned", Reason: fmt.Sprintf("credential type %q is outside the plannable succession genus", c.Type)})
			continue
		}
		dec, err := decider.Decide(ctx, DecisionInput{
			TenantID:       "", // tenant is bound operationally at mint time, not in the plan
			AssetID:        c.AssetID,
			IdentityID:     c.IdentityID,
			CredentialType: c.Type,
			PredecessorAlg: c.Algorithm,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("pqcmigration: decide %s: %w", c.AssetID, err)
		}
		if !dec.Allow {
			residuals = append(residuals, Residual{ID: c.AssetID, Status: "policy_denied", Reason: dec.Reason})
			continue
		}
		jobs = append(jobs, SuccessionJob{
			AssetID:            c.AssetID,
			IdentityID:         c.IdentityID,
			CredentialType:     c.Type,
			PredecessorAlg:     c.Algorithm,
			TargetAlgorithm:    dec.TargetAlgorithm,
			EffectiveAlgorithm: dec.EffectiveAlgorithm,
			Protocol:           c.Protocol,
			RollbackOnFailure:  c.RollbackOnFailure,
			Decision:           dec,
			PolicyRef:          PolicyRef(dec),
		})
	}
	return jobs, residuals, nil
}

// CredentialsFromPlan bridges a BuildPlan result into the succession genus: each
// cert-key Reissue becomes an X.509 Credential. identityFor maps an asset id to its
// stable identity id; a nil map uses the asset id as the identity. This is the
// wiring that makes BuildPlan callers emit succession jobs instead of bare reissues.
func CredentialsFromPlan(plan Plan, identityFor func(assetID string) string) []Credential {
	out := make([]Credential, 0, len(plan.Reissues))
	for _, r := range plan.Reissues {
		identity := r.Asset.ID
		if identityFor != nil {
			if got := identityFor(r.Asset.ID); got != "" {
				identity = got
			}
		}
		out = append(out, Credential{
			AssetID:           r.Asset.ID,
			IdentityID:        identity,
			Type:              CredentialX509,
			Algorithm:         r.Asset.Algorithm,
			QuantumVulnerable: r.Asset.QuantumVulnerable,
			Protocol:          r.Protocol,
			RollbackOnFailure: r.RollbackOnFailure,
		})
	}
	return out
}
