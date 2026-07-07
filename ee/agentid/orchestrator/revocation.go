// SPDX-License-Identifier: LicenseRef-trstctl-EE

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	agidapi "trstctl.com/trstctl/ee/agentid/api"
	agidstore "trstctl.com/trstctl/ee/agentid/delegation/store"
	"trstctl.com/trstctl/ee/agentid/revoke"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	coreorch "trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
)

// revocation.go is the PRODUCTION CALLER for the cascaded-revocation path — the
// "verifiable kill". It turns the two revocation outbox destinations into real drives of
// the AGID-10/11 mechanisms nothing previously invoked:
//
//   - agentid.revoke-directive -> revoke.NewCascade(...).EnqueueDirective: determine the
//     descendant credential set from the AGID-02 projection, record the directive
//     durable-first, and commit the directive projection ⊕ one per-descendant job (and
//     one outbox job each) in ONE transaction (INV-A8).
//   - agent.revocation.job     -> revoke.NewExecutor(...).Execute: perform the effect
//     idempotently and record SIGNED per-job completion evidence (INV-A9). After a job,
//     it generates any follow-on (revoke.Cascade.GenerateFollowOn), attempts the terminal
//     transition (revoke.NewTerminalTransition(...).Transition, which mints the signed
//     aggregate evidence artifact once every job is evidenced), and runs the interval
//     monitor (revoke.NewIntervalMonitor(...).Check) to record an exceedance if the
//     cascade overran its completion interval.
//
// Every constructor here is on the live substrate: the cascade, executor, terminal, and
// interval monitor all run for real against the store/log/outbox the deps provide and the
// control-plane evidence signer (AN-3). This is the mechanism half of the AGID-INT-CALL
// bar — unlike the issuance path (whose final in-signer key op is deferred to
// AGID-INT-WIRE), the revocation path has no isolated-signer dependency, so it executes
// end-to-end here.

// cascadeWorker drives revocations. It holds the constructed cascade, executor, terminal
// transition, and interval monitor plus the live store/log/repo they run against.
type cascadeWorker struct {
	core     *corestore.Store
	repo     *agidstore.Repo
	log      *events.Log
	cascade  *revoke.Cascade
	executor *revoke.Executor
	terminal *revoke.TerminalTransition
	interval *revoke.IntervalMonitor
}

// defaultCompletionIntervalSeconds is the policy completion interval the interval monitor
// measures a cascade against (claim 23). A deployment overrides it via policy in
// AGID-INT-WIRE; a conservative one-hour default records an exceedance for a kill that
// overruns an hour without completing.
const defaultCompletionIntervalSeconds int64 = 3600

// newCascadeWorker constructs the cascade worker and, in doing so, gives every AGID-10/11
// control-plane constructor a non-test caller: revoke.NewCascade, revoke.NewExecutor,
// revoke.NewTerminalTransition, and revoke.NewIntervalMonitor. All four run against the
// live store/log/outbox and sign evidence with the control-plane signer.
func newCascadeWorker(core *corestore.Store, repo *agidstore.Repo, log *events.Log, outbox *coreorch.Outbox, signer crypto.Signer) (*cascadeWorker, error) {
	cascade, err := revoke.NewCascade(log, core, repo, outbox)
	if err != nil {
		return nil, fmt.Errorf("agentid cascade worker: new cascade: %w", err)
	}
	executor, err := revoke.NewExecutor(log, core, outbox, signer,
		revoke.WithClock(func() int64 { return time.Now().Unix() }),
		revoke.WithExecutorID("agentid-revoke-executor"),
	)
	if err != nil {
		return nil, fmt.Errorf("agentid cascade worker: new executor: %w", err)
	}
	terminal, err := revoke.NewTerminalTransition(repo, core, log, signer,
		revoke.WithTerminalClock(func() int64 { return time.Now().Unix() }),
	)
	if err != nil {
		return nil, fmt.Errorf("agentid cascade worker: new terminal transition: %w", err)
	}
	interval, err := revoke.NewIntervalMonitor(repo, log, defaultCompletionIntervalSeconds,
		revoke.WithIntervalClock(func() int64 { return time.Now().Unix() }),
	)
	if err != nil {
		return nil, fmt.Errorf("agentid cascade worker: new interval monitor: %w", err)
	}
	return &cascadeWorker{
		core: core, repo: repo, log: log,
		cascade: cascade, executor: executor, terminal: terminal, interval: interval,
	}, nil
}

// stagedRevocation mirrors the outbox payload ee/agentid/api enqueues for a directive.
type stagedRevocation struct {
	DirectiveID string `json:"directive_id"`
	agidapi.RevokeRequest
}

// deliverDirective turns one agentid.revoke-directive message into a cascade drive: it
// builds a revoke.Directive and calls EnqueueDirective, which determines descendants and
// commits the transactional per-descendant jobs. It is idempotent on the directive id.
func (w *cascadeWorker) deliverDirective(ctx context.Context, m coreorch.Message) error {
	if m.Destination != RevocationDirectiveDestination {
		return fmt.Errorf("agentid cascade worker: unexpected directive destination %q", m.Destination)
	}
	var s stagedRevocation
	if err := json.Unmarshal(m.Payload, &s); err != nil {
		return fmt.Errorf("agentid cascade worker: decode staged directive: %w", err)
	}
	if s.Subject == "" {
		return fmt.Errorf("agentid cascade worker: staged directive missing subject")
	}
	directive := revoke.Directive{
		TenantID:    m.TenantID,
		DirectiveID: s.DirectiveID,
		Subject:     s.Subject,
		Reason:      revoke.ReasonClass(s.Reason),
	}
	// The production caller for revoke.NewCascade: determine descendants + watermark and
	// commit the directive projection ⊕ per-descendant jobs (and their outbox jobs) in one
	// transaction (INV-A8). The per-descendant jobs land on agent.revocation.job, which
	// this same worker drains through the executor.
	if _, err := w.cascade.EnqueueDirective(ctx, directive); err != nil {
		return fmt.Errorf("agentid cascade worker: enqueue directive: %w", err)
	}
	return nil
}

// deliverJob turns one agent.revocation.job message into a job execution, then advances the
// directive toward its terminal state. It executes the job idempotently (the executor),
// generates any follow-on for late descendants, attempts the terminal transition (which
// mints the aggregate artifact when complete), and runs the interval monitor. A retry
// re-runs Execute, which collapses an already-recorded effect to a no-op (claim 21).
func (w *cascadeWorker) deliverJob(ctx context.Context, m coreorch.Message) error {
	if m.Destination != RevocationJobDestination {
		return fmt.Errorf("agentid cascade worker: unexpected job destination %q", m.Destination)
	}

	// (1) Execute the job: perform the effect + record signed completion evidence
	// idempotently (INV-A9). This is the production caller for revoke.NewExecutor.
	if err := w.executor.Execute(ctx, m); err != nil {
		return fmt.Errorf("agentid cascade worker: execute job: %w", err)
	}

	// The directive this job belongs to, so we can advance its terminal state.
	directiveID, tenantID := jobDirective(m)
	if directiveID == "" {
		// A payload we could execute but not attribute to a directive is unexpected; the
		// executor already recorded its effect, so return nil (ack) rather than spinning.
		return nil
	}

	// (2) Generate any follow-on jobs for descendants recorded after the directive
	// watermark (§7.2). The production caller for revoke.Cascade.GenerateFollowOn; new
	// follow-on jobs land on agent.revocation.job and this worker drains them too.
	if _, err := w.cascade.GenerateFollowOn(ctx, tenantID, directiveID); err != nil {
		// A follow-on generation failure is transient (a projection read); surface it so
		// the outbox retries. The already-executed effect is durable and idempotent, so a
		// retry does not double-execute.
		return fmt.Errorf("agentid cascade worker: generate follow-on: %w", err)
	}

	// (3) Attempt the terminal transition: when EVERY enqueued and follow-on job is
	// evidenced, flip the directive terminal and mint the SIGNED aggregate evidence
	// artifact (INV-A9 / claims 18/33). The production caller for revoke.NewTerminalTransition.
	// A still-draining directive is left non-terminal (no flip), which is not an error.
	if _, err := w.terminal.Transition(ctx, tenantID, directiveID); err != nil {
		return fmt.Errorf("agentid cascade worker: terminal transition: %w", err)
	}

	// (4) Run the interval monitor: record the DISTINCT exceedance event if the cascade
	// overran its completion interval (claim 23). The production caller for
	// revoke.NewIntervalMonitor. It records at most once per directive, so repeated job
	// deliveries do not duplicate the event.
	if _, err := w.interval.Check(ctx, tenantID, directiveID); err != nil {
		return fmt.Errorf("agentid cascade worker: interval check: %w", err)
	}
	return nil
}

// jobDirective extracts the directive id + tenant from a revocation-job message so the
// worker can advance the directive after executing the job. It decodes only the fields it
// needs from the JobPayload the cascade enqueued (the executor decodes the full payload
// itself).
func jobDirective(m coreorch.Message) (directiveID, tenantID string) {
	var p struct {
		TenantID    string `json:"tenant_id"`
		DirectiveID string `json:"directive_id"`
	}
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return "", ""
	}
	tenantID = p.TenantID
	if tenantID == "" {
		tenantID = m.TenantID
	}
	return p.DirectiveID, tenantID
}
