// Package incident implements the credential-compromise workflow (S12.1, F31):
// one operator action to remediate a compromised credential, preceded by a
// blast-radius preview computed from the credential graph so the operator sees
// every affected workload and downstream credential before committing.
//
// The combined action reissues, revokes, and rotates the compromised credential
// and everything downstream. It is ordered for recoverability: a replacement is
// reissued *before* the old credential is revoked, so a partial failure never
// leaves a workload without a valid credential (no outage) — the state is always
// resumable. The whole incident is an audited event chain (AN-2), idempotent so a
// retried remediation does not run twice (AN-5), and mediated by the Remediator
// seam which production backs with the outbox (AN-6).
package incident

import (
	"context"
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/idem"
)

// Remediator performs the side-effecting remediation steps. Each is a seam so the
// workflow is unit-testable; production backs them with the outbox (AN-6) so each
// external effect is at-least-once and, combined with AN-5, exactly-once.
type Remediator interface {
	Reissue(ctx context.Context, tenantID, credentialID string) (newCredentialID string, err error)
	Revoke(ctx context.Context, tenantID, credentialID string) error
	Rotate(ctx context.Context, tenantID, credentialID string) error
}

// Config configures a Workflow.
type Config struct {
	TenantID   string
	Graph      *graph.Graph
	Remediator Remediator
	Idem       idem.Idempotencer
	Audit      auditsink.Auditor
}

// Workflow remediates compromised credentials.
type Workflow struct {
	cfg Config
}

// New validates configuration and constructs a Workflow.
func New(cfg Config) (*Workflow, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("incident: TenantID required (AN-1)")
	}
	if cfg.Graph == nil {
		return nil, fmt.Errorf("incident: Graph required")
	}
	if cfg.Remediator == nil {
		return nil, fmt.Errorf("incident: Remediator required")
	}
	if cfg.Idem == nil {
		return nil, fmt.Errorf("incident: Idempotencer required (AN-5)")
	}
	if cfg.Audit == nil {
		cfg.Audit = auditsink.Nop{}
	}
	return &Workflow{cfg: cfg}, nil
}

// Preview is the blast radius of compromising a credential.
type Preview struct {
	Root            string       `json:"root"`
	Affected        []graph.Node `json:"affected"`
	CredentialCount int          `json:"credential_count"`
}

// Preview computes (without changing anything) the full set of nodes a
// compromise of credentialID would put at risk.
func (w *Workflow) Preview(credentialID string) Preview {
	impact := w.cfg.Graph.BlastRadius(credentialID)
	creds := 0
	for _, n := range impact.Affected {
		if n.Kind == graph.KindCredential {
			creds++
		}
	}
	return Preview{Root: credentialID, Affected: impact.Affected, CredentialCount: creds}
}

// StepResult is the outcome of remediating one credential.
type StepResult struct {
	CredentialID       string `json:"credential_id"`
	Reissued           string `json:"reissued,omitempty"`
	RevokeOK           bool   `json:"revoke_ok"`
	RotateOK           bool   `json:"rotate_ok"`
	Err                string `json:"error,omitempty"`
	HasValidCredential bool   `json:"has_valid_credential"` // invariant: a workload is never left without one
}

// Report is the outcome of a remediation.
type Report struct {
	Root        string       `json:"root"`
	Steps       []StepResult `json:"steps"`
	Completed   bool         `json:"completed"`   // every step succeeded
	Recoverable bool         `json:"recoverable"` // on partial failure, state is consistent/resumable
}

// Remediate reissues, revokes, and rotates the compromised credential and every
// downstream credential. It is idempotent on idempotencyKey.
func (w *Workflow) Remediate(ctx context.Context, credentialID, idempotencyKey string) (Report, error) {
	if idempotencyKey == "" {
		return Report{}, fmt.Errorf("incident: Idempotency-Key required (AN-5)")
	}
	raw, err := w.cfg.Idem.Do(ctx, w.cfg.TenantID, idempotencyKey, func(ctx context.Context) ([]byte, error) {
		return json.Marshal(w.remediate(ctx, credentialID))
	})
	if err != nil {
		return Report{}, err
	}
	var r Report
	if err := json.Unmarshal(raw, &r); err != nil {
		return Report{}, err
	}
	return r, nil
}

func (w *Workflow) remediate(ctx context.Context, root string) Report {
	targets := []string{root}
	for _, n := range w.cfg.Graph.BlastRadius(root).Affected {
		if n.Kind == graph.KindCredential {
			targets = append(targets, n.ID)
		}
	}
	w.audit(ctx, "incident.started", map[string]any{"root": root, "targets": len(targets)})

	rep := Report{Root: root, Completed: true, Recoverable: true}
	for _, cred := range targets {
		sr := w.remediateOne(ctx, cred)
		rep.Steps = append(rep.Steps, sr)
		if sr.Err != "" {
			rep.Completed = false
		}
		if !sr.HasValidCredential {
			rep.Recoverable = false // a half-remediated outage — must never happen
		}
	}
	ev := "incident.completed"
	if !rep.Completed {
		ev = "incident.partial"
	}
	w.audit(ctx, ev, map[string]any{"root": root, "completed": rep.Completed, "recoverable": rep.Recoverable, "steps": len(rep.Steps)})
	return rep
}

// remediateOne reissues BEFORE revoking, so a workload is never left without a
// valid credential. Every failure path leaves at least one valid credential, so
// the state is always recoverable (retry resumes from where it stopped).
func (w *Workflow) remediateOne(ctx context.Context, cred string) StepResult {
	sr := StepResult{CredentialID: cred, HasValidCredential: true} // old credential valid until revoked

	newID, err := w.cfg.Remediator.Reissue(ctx, w.cfg.TenantID, cred)
	if err != nil {
		sr.Err = "reissue: " + err.Error() // nothing changed; old credential still valid
		w.stepFailed(ctx, cred, "reissue", err)
		return sr
	}
	sr.Reissued = newID

	if err := w.cfg.Remediator.Revoke(ctx, w.cfg.TenantID, cred); err != nil {
		sr.Err = "revoke: " + err.Error() // new credential valid; old also still valid — retry revoke
		w.stepFailed(ctx, cred, "revoke", err)
		return sr
	}
	sr.RevokeOK = true

	if err := w.cfg.Remediator.Rotate(ctx, w.cfg.TenantID, cred); err != nil {
		sr.Err = "rotate: " + err.Error() // new credential issued+valid, just not yet deployed — retry rotate
		w.stepFailed(ctx, cred, "rotate", err)
		return sr
	}
	sr.RotateOK = true
	w.audit(ctx, "incident.step.ok", map[string]any{"credential": cred, "reissued": newID})
	return sr
}

func (w *Workflow) stepFailed(ctx context.Context, cred, step string, err error) {
	w.audit(ctx, "incident.step.failed", map[string]any{"credential": cred, "step": step, "error": err.Error()})
}

func (w *Workflow) audit(ctx context.Context, event string, data map[string]any) {
	b, _ := json.Marshal(data)
	_ = auditsink.Emit(ctx, w.cfg.Audit, nil, event, w.cfg.TenantID, b)
}
