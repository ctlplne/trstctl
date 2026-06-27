// Package pqcmigration orchestrates the PQC migration program (S14.4, F57): it
// consumes the CBOM (the crypto inventory in the credential graph) to identify
// quantum-vulnerable assets, stages their reissuance to a post-quantum algorithm
// under policy, and tracks the transition to completion. It reuses the S12.2 fleet
// machinery's resumable progress store, so a migration is crash-safe and never
// double-issues (AN-5/AN-6), and every action is audited (AN-2).
package pqcmigration

import (
	"context"
	"fmt"

	"trstctl.com/trstctl/ee/fleet"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/graph"
)

// Reissuer re-issues an asset's credential under a post-quantum target algorithm.
type Reissuer interface {
	ReissueToPQC(ctx context.Context, tenantID, assetID string, target crypto.Algorithm) (newCredentialID string, err error)
}

// Asset is a quantum-vulnerable cryptographic asset from the CBOM.
type Asset struct {
	ID        string
	Algorithm crypto.Algorithm
	Family    string
}

// Config configures the migration Orchestrator.
type Config struct {
	TenantID string
	Graph    *graph.Graph // CBOM: KindCryptoAsset nodes with an "algorithm" attr
	Reissuer Reissuer
	Progress fleet.ProgressStore       // resumability (reused from S12.2); fleet.NewMemoryProgress for single-node
	Guard    func(assetID string) bool // optional policy gate on staging
	Audit    auditsink.Auditor
}

// Orchestrator runs the discover→stage→reissue→track loop.
type Orchestrator struct {
	cfg Config
}

// New validates configuration and constructs an Orchestrator.
func New(cfg Config) (*Orchestrator, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("pqcmigration: TenantID required (AN-1)")
	}
	if cfg.Graph == nil || cfg.Reissuer == nil {
		return nil, fmt.Errorf("pqcmigration: Graph and Reissuer required")
	}
	if cfg.Progress == nil {
		return nil, fmt.Errorf("pqcmigration: ProgressStore required (resumability)")
	}
	if cfg.Audit == nil {
		cfg.Audit = auditsink.Nop{}
	}
	return &Orchestrator{cfg: cfg}, nil
}

// VulnerableAssets returns the quantum-vulnerable crypto assets in the CBOM.
func (o *Orchestrator) VulnerableAssets() []Asset {
	var out []Asset
	for _, n := range o.cfg.Graph.Nodes() {
		if n.Kind != graph.KindCryptoAsset {
			continue
		}
		alg := crypto.Algorithm(n.Attrs["algorithm"])
		class, err := crypto.Classify(alg)
		if err != nil || !class.QuantumVulnerable {
			continue
		}
		out = append(out, Asset{ID: n.ID, Algorithm: alg, Family: class.Family})
	}
	return out
}

// Report summarizes a migration run.
type Report struct {
	Enrolled  int
	Migrated  int
	Skipped   int // already-done or policy-denied
	Remaining int // still quantum-vulnerable after the run
	Completed bool
}

// Migrate enrolls the vulnerable assets and re-issues each to the PQC target,
// staged, resumable, and audited, updating the CBOM as assets transition.
func (o *Orchestrator) Migrate(ctx context.Context, runID string, target crypto.Algorithm) (Report, error) {
	tc, err := crypto.Classify(target)
	if err != nil || !tc.PostQuantum {
		return Report{}, fmt.Errorf("pqcmigration: target %q is not a post-quantum algorithm", target)
	}
	assets := o.VulnerableAssets()
	rep := Report{Enrolled: len(assets)}
	o.audit(ctx, "pqc.migration.started", fmt.Sprintf(`{"run":%q,"target":%q,"enrolled":%d}`, runID, target, len(assets)))

	done, err := o.cfg.Progress.Completed(ctx, runID)
	if err != nil {
		return rep, fmt.Errorf("pqcmigration: load progress: %w", err)
	}
	for _, a := range assets {
		if _, ok := done[a.ID]; ok {
			// Already migrated in a prior (possibly interrupted) run — reconcile the
			// CBOM so transition tracking is accurate across resume.
			rep.Skipped++
			o.markMigrated(a.ID, target)
			continue
		}
		if o.cfg.Guard != nil && !o.cfg.Guard(a.ID) {
			rep.Skipped++
			o.audit(ctx, "pqc.migration.skipped", fmt.Sprintf(`{"asset":%q,"reason":"policy"}`, a.ID))
			continue
		}
		newID, err := o.cfg.Reissuer.ReissueToPQC(ctx, o.cfg.TenantID, a.ID, target)
		if err != nil {
			return rep, fmt.Errorf("pqcmigration: reissue %s: %w", a.ID, err)
		}
		if err := o.cfg.Progress.Mark(ctx, runID, a.ID, newID); err != nil {
			return rep, fmt.Errorf("pqcmigration: record progress: %w", err)
		}
		o.markMigrated(a.ID, target)
		rep.Migrated++
	}
	rep.Remaining = len(o.VulnerableAssets())
	rep.Completed = rep.Remaining == 0
	ev := "pqc.migration.completed"
	if !rep.Completed {
		ev = "pqc.migration.progress"
	}
	o.audit(ctx, ev, fmt.Sprintf(`{"run":%q,"migrated":%d,"skipped":%d,"remaining":%d}`, runID, rep.Migrated, rep.Skipped, rep.Remaining))
	return rep, nil
}

// markMigrated reconciles a CBOM asset node to the post-quantum target.
func (o *Orchestrator) markMigrated(assetID string, target crypto.Algorithm) {
	n, ok := o.cfg.Graph.Node(assetID)
	if !ok {
		return
	}
	if n.Attrs == nil {
		n.Attrs = map[string]string{}
	}
	n.Attrs["algorithm"] = string(target)
	n.Attrs["pqc_migrated"] = "true"
	o.cfg.Graph.AddNode(n)
}

func (o *Orchestrator) audit(ctx context.Context, event, data string) {
	_ = auditsink.Emit(ctx, o.cfg.Audit, nil, event, o.cfg.TenantID, []byte(data))
}
