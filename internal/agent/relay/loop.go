// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
)

// Channel is the slice of the agent channel a relay uses. It is an interface
// held here — not an import of the transport package — so this package stays
// testable without a gRPC server and so the agent core keeps its existing
// no-transport-import shape.
type Channel interface {
	// ClaimJobs leases work. The returned payloads are reference-only intents.
	ClaimJobs(ctx context.Context, kinds []string, limit, leaseSeconds int) ([]Job, error)
	// RedeemJobCredential redeems this attempt's material, once.
	RedeemJobCredential(ctx context.Context, jobID int64, attempt int) (map[string][]byte, error)
	// ReportJobResult reports the outcome. detail must never carry credential
	// material; the control plane withholds it from durable history anyway when
	// the attempt redeemed anything, but the relay does not rely on that.
	//
	// attempt is the claim generation the report belongs to. It travels because
	// the report is SIGNED over it (epic A1): without the attempt, a receipt for
	// one attempt at a job would verify against a later attempt at the same job
	// after a lease lapse requeued it.
	ReportJobResult(ctx context.Context, jobID int64, attempt int, outcome, detail, evidenceDigest string) (bool, error)
}

// Job is one claimed unit of work as the relay sees it.
type Job struct {
	JobID   int64
	Kind    string
	Attempt int
	Payload []byte
}

// Outcome values the relay reports.
const (
	OutcomeExecuted = "executed"
	OutcomeFailed   = "failed"
)

// ClaimableKinds are the job kinds a relay asks for. Only connector work: a
// relay's whole purpose is driving things that cannot host an agent, and asking
// for host-local kinds would be asking for work it cannot do.
func ClaimableKinds() []string {
	return []string{
		"connector.deploy", "connector.test", KindConnectorRollback,
		KindRevocationProbe, KindDiscoveryRun, KindADCSInventory, KindEndpointVerify,
	}
}

// KindConnectorTest is the dry-run kind (epic D5): resolve everything a deploy
// needs, probe the target, describe what would change, mutate nothing.
const KindConnectorTest = "connector.test"

// KindConnectorRollback is the executed re-bind (epic D4): point a listener
// back at a predecessor object that is still installed on the appliance.
//
// It is a separate kind from connector.deploy because an operator must be able
// to enable rolling back without enabling deploying, and because the payload is
// genuinely different — a rollback names a fingerprint and carries no
// certificate at all.
const KindConnectorRollback = "connector.rollback"

// RunOnce claims up to limit jobs, executes each, and reports. It returns how
// many it executed. One pass, no timers: the caller owns the schedule, so a
// relay's poll cadence stays with the agent's other loops rather than becoming
// a second scheduler with its own opinions.
func RunOnce(ctx context.Context, ch Channel, client *http.Client, limit, leaseSeconds int) (int, error) {
	return RunOnceWithHost(ctx, ch, client, connector.LocalOpsConfig{}, limit, leaseSeconds)
}

// RunOnceWithHost is RunOnce with a host exec profile, so one agent can serve
// both roles in a single pass (epic D1). A relay claims appliance work, a host
// agent claims file/exec work, and an agent granted both roles claims both —
// which is the topology the roles were designed to describe.
//
// An empty profile means this agent executes no host-local connectors, which is
// the correct default: without an operator-owned allowlist there is no
// authorized set of commands, and inventing one would be the failure mode the
// profile exists to prevent.
func RunOnceWithHost(
	ctx context.Context,
	ch Channel,
	client *http.Client,
	hostProfile connector.LocalOpsConfig,
	limit, leaseSeconds int,
) (int, error) {
	if ch == nil {
		return 0, errors.New("relay: no channel")
	}
	jobs, err := ch.ClaimJobs(ctx, ClaimableKinds(), limit, leaseSeconds)
	if err != nil {
		return 0, fmt.Errorf("relay: claim: %w", err)
	}
	executed := 0
	for _, job := range jobs {
		if runJob(ctx, ch, client, hostProfile, job) {
			executed++
		}
	}
	return executed, nil
}

// runJob is one job's whole life. It reports true only when the deploy actually
// happened.
//
// Every failure path reports, so the job returns to the queue promptly rather
// than waiting out its lease: a relay that dies silently is indistinguishable
// from a slow one, and the difference matters to whoever is waiting for the
// certificate to land.
func runJob(ctx context.Context, ch Channel, client *http.Client, hostProfile connector.LocalOpsConfig, job Job) bool {
	// A revocation probe carries a different payload and needs no credential at
	// all — it reads public distribution points. Routing it before the deploy
	// path keeps it from redeeming material it has no use for (R1).
	if job.Kind == KindRevocationProbe {
		return runRevocationProbe(ctx, ch, client, job)
	}
	// A segment sweep needs no credential either — it reads what hosts serve
	// publicly. Routing it before the deploy path keeps it from redeeming
	// material it has no use for (C2).
	if job.Kind == KindDiscoveryRun {
		return runDiscoverySweep(ctx, ch, job)
	}
	// A verification sweep reads what listeners publicly present, so like the
	// two above it redeems nothing and is routed before the credential step
	// (D2).
	if job.Kind == KindEndpointVerify {
		return runEndpointVerify(ctx, ch, job)
	}

	// A rollback carries a rollback intent, not a deploy intent — no
	// certificate and no key, by design. Routing it here keeps the deploy path
	// from trying to decode a payload that will never have the fields it
	// expects.
	if job.Kind == KindConnectorRollback {
		return runRollback(ctx, ch, client, job)
	}

	var intent DeployIntent
	if err := decodeIntent(job.Payload, &intent); err != nil {
		report(ctx, ch, job, OutcomeFailed, "job payload is not a deploy intent")
		return false
	}
	// Refuse work this build cannot perform BEFORE redeeming anything. A
	// credential redeemed for an attempt that was never going to run is a
	// credential outside the seal for no reason, and it burns the attempt's one
	// redemption.
	// Which executor this job needs is decided by the connector, and refused
	// before anything is redeemed. A host agent handed appliance work, or a
	// relay handed a filesystem deploy, must not burn the attempt's one
	// credential redemption discovering that.
	hostJob := ExecutesOnHost(intent.Connector)
	if job.Kind == KindADCSInventory {
		// An AD CS inventory names no connector; its executor is the directory
		// reader. Skip the connector checks rather than failing it for not
		// naming one it has no use for.
		hostJob = false
	} else if !hostJob && !Executes(intent.Connector) {
		report(ctx, ch, job, OutcomeFailed, "connector is not executable by this agent")
		return false
	}
	if hostJob && len(hostProfile.AllowedRoots) == 0 {
		// The connector is host-executable but this agent has no operator
		// profile, so it has no authorized command set. Saying so is the point:
		// silently doing nothing would look identical to a healthy agent.
		report(ctx, ch, job, OutcomeFailed, "this agent has no host exec profile configured for file and reload deploys")
		return false
	}

	// A dry-run still redeems: the point of testing a target is to find out
	// whether the credential works, and a test that skipped it would pass right
	// up until the deploy that mattered.
	items, err := ch.RedeemJobCredential(ctx, job.JobID, job.Attempt)
	if err != nil {
		// A refused or unavailable redemption is not this relay's failure to
		// explain: the control plane holds the reason and has already recorded
		// it. Reporting a closed phrase keeps the relay from guessing.
		report(ctx, ch, job, OutcomeFailed, "credential redemption was not granted")
		return false
	}
	material, destroy, err := AdoptMaterial(items)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "redeemed material could not be taken into locked memory")
		return false
	}
	// The material's life ends here, on every path out — including a panic
	// inside a connector, which must not leave an appliance password sitting in
	// unlocked memory for the rest of the process's life.
	defer destroy()

	if job.Kind == KindConnectorTest {
		plan, planErr := DryRun(ctx, client, intent, material)
		if planErr != nil {
			report(ctx, ch, job, OutcomeFailed, "dry-run could not be evaluated")
			return false
		}
		// The plan is the answer either way: a target that cannot be reached is
		// a successful TEST with a failed step, not a failed job. Reporting it
		// as a failure would put the job back on the queue to be retried
		// forever against an appliance that is simply off.
		detail, marshalErr := json.Marshal(plan)
		if marshalErr != nil {
			report(ctx, ch, job, OutcomeFailed, "dry-run plan could not be encoded")
			return false
		}
		report(ctx, ch, job, OutcomeExecuted, string(detail))
		return plan.Ready
	}

	if job.Kind == KindADCSInventory {
		// Unlike the other probe kinds this one redeems: reading a domain's
		// template posture needs a directory bind, and anonymous reads are
		// refused. So it runs here, after the material is in locked memory.
		return runADCSInventory(ctx, ch, job, material)
	}

	var stats connector.Stats
	var execErr error
	if hostJob {
		stats, execErr = ExecuteOnHost(ctx, hostProfile, intent, material)
	} else {
		stats, execErr = Execute(ctx, client, intent, material)
	}
	if execErr != nil {
		// The connector's own error text can contain whatever the appliance
		// echoed back, including the credential. It is never forwarded: the
		// relay reports a closed phrase and keeps the detail local.
		report(ctx, ch, job, OutcomeFailed, "connector deploy failed against the target")
		return false
	}
	if stats.Denied > 0 {
		// The sandbox refused something the connector tried. That is a
		// capability-declaration bug, not a target problem, and it must not read
		// as a clean deploy.
		report(ctx, ch, job, OutcomeFailed, "connector attempted an operation outside its declared capabilities")
		return false
	}
	// D2: the deploy applied. Whether the listener is SERVING it is a different
	// question, and this is the only moment it can be asked — the redeemed
	// certificate's life ends when this function returns.
	outcome, detail, evidence := postDeployVerification(ctx, intent, material)
	reportWithEvidence(ctx, ch, job, outcome, detail, evidence)
	return outcome != transport.OutcomeVerifyFailed
}

// runRollback executes one re-bind (epic D4).
//
// It still redeems: re-pointing a listener means authenticating to the
// appliance's management interface. What it does NOT redeem is a subject key,
// because there is none to redeem and none is needed — which is exactly why
// this operation is available at all.
func runRollback(ctx context.Context, ch Channel, client *http.Client, job Job) bool {
	var intent RollbackIntent
	if err := decodeJobPayload(job.Payload, &intent); err != nil {
		report(ctx, ch, job, OutcomeFailed, transport.RollbackRefusedBadPayload)
		return false
	}
	// Refuse before redeeming, same discipline as a deploy: a credential
	// redeemed for an attempt that was never going to run is material outside
	// the seal for nothing, and it burns the attempt's one redemption.
	if !Executes(intent.Connector) {
		report(ctx, ch, job, OutcomeFailed, transport.RollbackRefusedNotExecutable)
		return false
	}
	if !connector.CanRollback(intent.Connector) {
		report(ctx, ch, job, OutcomeFailed, transport.RollbackRefusedCannotRebind)
		return false
	}
	if strings.TrimSpace(intent.PredecessorFingerprint) == "" {
		// A first deployment has no predecessor. Saying so is the useful answer;
		// retrying would never produce one.
		report(ctx, ch, job, OutcomeFailed, transport.RollbackRefusedNoPredecessor)
		return false
	}

	items, err := ch.RedeemJobCredential(ctx, job.JobID, job.Attempt)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, transport.RollbackRefusedNoCredential)
		return false
	}
	material, destroy, err := AdoptMaterial(items)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, transport.RollbackRefusedNoLockedMemory)
		return false
	}
	defer destroy()

	stats, execErr := Rollback(ctx, client, intent, material)
	switch {
	case errors.Is(execErr, connector.ErrNoPredecessorInstalled):
		// The distinction an operator acts on: the object is not there, so no
		// retry will help and somebody has to reissue rather than restore.
		report(ctx, ch, job, OutcomeFailed, transport.RollbackFailedPredecessorGone)
		return false
	case execErr != nil:
		// The connector's error can carry whatever the appliance echoed,
		// including the credential. Never forwarded.
		report(ctx, ch, job, OutcomeFailed, transport.RollbackFailedAtTarget)
		return false
	}
	if stats.Denied > 0 {
		report(ctx, ch, job, OutcomeFailed, transport.RollbackRefusedCapability)
		return false
	}
	report(ctx, ch, job, OutcomeExecuted, "")
	return true
}

func report(ctx context.Context, ch Channel, job Job, outcome, detail string) {
	reportWithEvidence(ctx, ch, job, outcome, detail, "")
}

// reportWithEvidence reports an outcome together with the digest of whatever
// transcript backs it (epic D2).
//
// The evidence digest travels inside the agent's signed statement, so a
// verification verdict is not merely asserted by the agent: an operator reading
// the receipt can prove the transcript they are looking at is the one that was
// signed. Every other kind still passes "" — an empty digest means no
// transcript was kept, which is the honest value for work that produced none.
func reportWithEvidence(ctx context.Context, ch Channel, job Job, outcome, detail, evidence string) {
	// A failed report is not retried here: the claim lease is the safety net.
	// If the control plane never hears, the lease lapses and the work returns.
	_, _ = ch.ReportJobResult(ctx, job.JobID, job.Attempt, outcome, detail, evidence)
}

func decodeIntent(payload []byte, out *DeployIntent) error {
	return decodeJobPayload(payload, out)
}

// decodeJobPayload decodes any job intent. Generic because a rollback intent is
// a different shape from a deploy intent — deliberately, since a rollback
// carries no certificate — and both need the same empty-payload refusal.
func decodeJobPayload[T any](payload []byte, out *T) error {
	if len(payload) == 0 {
		return errors.New("relay: empty job payload")
	}
	return json.Unmarshal(payload, out)
}

// connectorStatsDenied exists so the sandbox contract is referenced by name in
// this package's godoc: a relay reports a denied operation as a failure, never
// as a success with a footnote.
var _ = connector.Stats{}
