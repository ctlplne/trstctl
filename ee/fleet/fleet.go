// Package fleet implements fleet re-issuance for a compromised issuer (S12.2,
// F32): when an issuing authority (an X.509 CA or, in the severe case, an SSH CA
// key) is compromised, every credential it signed must be re-issued at scale.
//
// The rollout is staged (AN-7: bounded batches that cannot overwhelm the system),
// guarded by policy, resumable (AN-5/AN-6: progress is recorded so an interrupted
// run resumes without duplicate issuance), and protected by a per-stage health
// check with automatic rollback. For an SSH CA, it additionally rotates the CA
// key, re-signs under it, redistributes TrustedUserCAKeys, and publishes a KRL.
// The whole operation is an audited event chain (AN-2).
package fleet

import (
	"context"
	"fmt"
	"sync"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/graph"
)

// Reissuer re-signs one leaf credential under the (rotated) issuer.
type Reissuer interface {
	Reissue(ctx context.Context, tenantID, credentialID string) (newCredentialID string, err error)
}

// HealthCheck validates the fleet after a stage; a non-nil error triggers rollback.
type HealthCheck func(ctx context.Context, stage int) error

// Rollbacker undoes the credentials issued in a failed stage.
type Rollbacker interface {
	Rollback(ctx context.Context, tenantID string, newCredentialIDs []string) error
}

// Guard is a policy guardrail consulted before re-issuing a credential.
type Guard interface {
	Allow(ctx context.Context, tenantID, credentialID string) (bool, string)
}

// SSHReestablisher performs the SSH-specific trust re-establishment for a
// compromised SSH CA key.
type SSHReestablisher interface {
	RotateCAKey(ctx context.Context, tenantID, caID string) (newCAKeyID string, err error)
	RedistributeTrust(ctx context.Context, tenantID, caID, newCAKeyID string) error
	PublishKRL(ctx context.Context, tenantID, caID string, revoked []string) error
}

// ProgressStore records completed re-issuances per run so an interrupted run
// resumes without duplicate issuance (AN-5/AN-6).
type ProgressStore interface {
	Completed(ctx context.Context, runID string) (map[string]string, error)
	Mark(ctx context.Context, runID, credentialID, newCredentialID string) error
}

// Config configures a Fleet operation.
type Config struct {
	TenantID  string
	Graph     *graph.Graph
	Reissuer  Reissuer
	Health    HealthCheck
	Rollback  Rollbacker
	Guard     Guard            // optional policy guardrail
	SSH       SSHReestablisher // optional; set for an SSH CA compromise
	StageSize int              // batch size (AN-7); default 50
	Progress  ProgressStore
	Audit     auditsink.Auditor
}

// Fleet runs staged mass re-issuance.
type Fleet struct {
	cfg Config
}

// New validates configuration and constructs a Fleet.
func New(cfg Config) (*Fleet, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("fleet: TenantID required (AN-1)")
	}
	if cfg.Graph == nil || cfg.Reissuer == nil {
		return nil, fmt.Errorf("fleet: Graph and Reissuer required")
	}
	if cfg.Progress == nil {
		return nil, fmt.Errorf("fleet: ProgressStore required (resumability, AN-5/AN-6)")
	}
	if cfg.StageSize <= 0 {
		cfg.StageSize = 50
	}
	if cfg.Audit == nil {
		cfg.Audit = auditsink.Nop{}
	}
	return &Fleet{cfg: cfg}, nil
}

// Report summarizes a fleet re-issuance run.
type Report struct {
	IssuerID    string
	NewCAKeyID  string
	Total       int
	Reissued    int
	Skipped     int // policy-denied or already-completed
	Stages      int
	RolledBack  bool
	Completed   bool
	FailedStage int
}

// ReissueFleet re-issues every credential the compromised issuer signed, in
// guarded, health-checked, resumable stages. runID identifies the run for resume.
func (f *Fleet) ReissueFleet(ctx context.Context, issuerID, runID string) (Report, error) {
	targets := f.cfg.Graph.Neighbors(issuerID, graph.EdgeIssued)
	rep := Report{IssuerID: issuerID, Total: len(targets), FailedStage: -1}
	f.audit(ctx, "fleet.started", fmt.Sprintf(`{"issuer":%q,"total":%d,"run":%q}`, issuerID, len(targets), runID))

	// SSH CA compromise: rotate the CA key first, so re-issuance signs under the new key.
	if f.cfg.SSH != nil {
		newKey, err := f.cfg.SSH.RotateCAKey(ctx, f.cfg.TenantID, issuerID)
		if err != nil {
			return rep, fmt.Errorf("fleet: rotate SSH CA key: %w", err)
		}
		rep.NewCAKeyID = newKey
		f.audit(ctx, "fleet.ssh.ca_key_rotated", fmt.Sprintf(`{"issuer":%q,"new_key":%q}`, issuerID, newKey))
	}

	done, err := f.cfg.Progress.Completed(ctx, runID)
	if err != nil {
		return rep, fmt.Errorf("fleet: load progress: %w", err)
	}

	var revoked []string
	stage := 0
	for start := 0; start < len(targets); start += f.cfg.StageSize {
		end := start + f.cfg.StageSize
		if end > len(targets) {
			end = len(targets)
		}
		stage++
		var stageNew []string
		for _, n := range targets[start:end] {
			if _, ok := done[n.ID]; ok { // already re-issued in a prior (interrupted) run
				rep.Skipped++
				continue
			}
			if f.cfg.Guard != nil {
				if ok, reason := f.cfg.Guard.Allow(ctx, f.cfg.TenantID, n.ID); !ok {
					rep.Skipped++
					f.audit(ctx, "fleet.skipped", fmt.Sprintf(`{"credential":%q,"reason":%q}`, n.ID, reason))
					continue
				}
			}
			newID, err := f.cfg.Reissuer.Reissue(ctx, f.cfg.TenantID, n.ID)
			if err != nil {
				return rep, fmt.Errorf("fleet: reissue %s: %w", n.ID, err)
			}
			if err := f.cfg.Progress.Mark(ctx, runID, n.ID, newID); err != nil {
				return rep, fmt.Errorf("fleet: record progress: %w", err)
			}
			stageNew = append(stageNew, newID)
			revoked = append(revoked, n.ID)
			rep.Reissued++
		}
		if f.cfg.Health != nil {
			if herr := f.cfg.Health(ctx, stage); herr != nil {
				rep.RolledBack = true
				rep.FailedStage = stage
				if f.cfg.Rollback != nil {
					if rerr := f.cfg.Rollback.Rollback(ctx, f.cfg.TenantID, stageNew); rerr != nil {
						return rep, fmt.Errorf("fleet: stage %d health failed and rollback failed: %v (health: %w)", stage, rerr, herr)
					}
				}
				f.audit(ctx, "fleet.rolled_back", fmt.Sprintf(`{"issuer":%q,"stage":%d}`, issuerID, stage))
				return rep, fmt.Errorf("fleet: stage %d failed health check, rolled back: %w", stage, herr)
			}
		}
	}
	rep.Stages = stage

	// SSH: now that re-issuance is healthy, redistribute trust and publish the KRL.
	if f.cfg.SSH != nil {
		if err := f.cfg.SSH.RedistributeTrust(ctx, f.cfg.TenantID, issuerID, rep.NewCAKeyID); err != nil {
			return rep, fmt.Errorf("fleet: redistribute SSH trust: %w", err)
		}
		if err := f.cfg.SSH.PublishKRL(ctx, f.cfg.TenantID, issuerID, revoked); err != nil {
			return rep, fmt.Errorf("fleet: publish KRL: %w", err)
		}
		f.audit(ctx, "fleet.ssh.trust_reestablished", fmt.Sprintf(`{"issuer":%q,"revoked":%d}`, issuerID, len(revoked)))
	}

	rep.Completed = true
	f.audit(ctx, "fleet.completed", fmt.Sprintf(`{"issuer":%q,"reissued":%d,"skipped":%d,"stages":%d}`, issuerID, rep.Reissued, rep.Skipped, rep.Stages))
	return rep, nil
}

func (f *Fleet) audit(ctx context.Context, event, data string) {
	_ = auditsink.Emit(ctx, f.cfg.Audit, nil, event, f.cfg.TenantID, []byte(data))
}

// MemoryProgress is an in-memory ProgressStore for single-node runs and tests.
type MemoryProgress struct {
	mu   sync.Mutex
	done map[string]map[string]string // runID -> (credentialID -> newCredentialID)
}

// NewMemoryProgress constructs a MemoryProgress.
func NewMemoryProgress() *MemoryProgress {
	return &MemoryProgress{done: map[string]map[string]string{}}
}

// Completed implements ProgressStore.
func (m *MemoryProgress) Completed(_ context.Context, runID string) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]string{}
	for k, v := range m.done[runID] {
		out[k] = v
	}
	return out, nil
}

// Mark implements ProgressStore.
func (m *MemoryProgress) Mark(_ context.Context, runID, credentialID, newCredentialID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.done[runID] == nil {
		m.done[runID] = map[string]string{}
	}
	m.done[runID][credentialID] = newCredentialID
	return nil
}
