// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/aimodel"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// The served job claim protocol (epic A1).
//
// An agent asks for work over the channel it opened; the control plane answers
// with a lease. Everything that decides who gets what comes from the client
// certificate — tenant and agent identity are never request fields, because a
// field is something an agent can choose and a certificate is not.
//
// Three bounds are enforced here rather than trusted from the request: the batch
// size, the lease length, and the set of job kinds. An agent asking for a
// thousand jobs on a one-hour lease is either broken or hostile, and neither is a
// reason to give it the queue.

// agentJobKinds are the outbox destinations an agent may claim. This is an
// allowlist, not a filter: an agent cannot claim `ca.issue` or
// `notification.expiry` no matter what it asks for, because those are the
// control plane's own work and handing them to a host would move CA-adjacent
// effects into the estate.
//
// The list is deliberately short. It grows one kind at a time as each
// estate-executed capability is built, and every addition is a decision about
// what an agent is allowed to do to a customer's infrastructure.
// It is empty by default and populated only by explicit operator configuration
// (agent.claimable_job_kinds). Nothing becomes claimable because a protocol
// exists: a kind is claimable when an agent-side executor for it exists AND an
// operator has enabled it. The estate-executing epics — connector.deploy (D1),
// endpoint.verify (D2), connector.rollback (D4), discovery.run (C2),
// revocation.probe (R1), trust.distribute (H2) — each add their kind here as they
// ship. Handing out work nothing can perform is how a queue silently fills while
// the control plane's own worker stops doing it.
var agentJobKindAllowlist = map[string]bool{
	"connector.deploy":   true,
	"connector.rollback": true,
	// D5: the dry-run. It is a first-class job kind rather than a flag on
	// connector.deploy so an operator can enable testing without enabling
	// deploying — the whole point of a test is that you run it before you trust
	// the thing that mutates.
	"connector.test":   true,
	"endpoint.verify":  true,
	"discovery.run":    true,
	"revocation.probe": true,
	// F1: AD CS template inventory. In-domain only — a domain controller's LDAP
	// is not reachable from a hosted control plane, which is why this is a job
	// rather than something the brain does itself.
	"adcs.inventory":   true,
	"trust.distribute": true,
	// B2: host-generated renewal. The agent makes the key, sends a CSR up, and
	// the control plane never holds the private half. Separate from
	// connector.deploy on purpose — the two differ in custody, not in mechanics,
	// and an operator migrating an estate needs to enable the custody change
	// deliberately and target by target rather than have it arrive with a
	// version bump.
	agentJobKindEndpointRenew: true,
	// A5: agent self-upgrade. Every row is narrowed to ONE agent by
	// required_agent_id and enqueued only by the campaign dispatcher, so
	// enabling the kind does not make binary replacement fleet-claimable —
	// it makes it possible for the agents a campaign names. The agent side
	// has its own -self-upgrade opt-in on top of this one.
	agentJobKindUpgrade: true,
	// I2: relay-executed CMDB read. The relay observes; the reconcile — and
	// its never-overwrite-an-attestation rule — stays in the control plane.
	agentJobKindCMDBSync: true,
	// I5: relay-executed MDM read, same custody and vantage rules.
	agentJobKindMDMSync: true,
	// I3: relay-executed ServiceNow ticket observation. Request creation stays
	// in the control plane; the bearer token and network call do not.
	agentJobKindTicketSync: true,
}

// agentJobKindUpgrade is the self-upgrade kind (epic A5).
const agentJobKindUpgrade = "agent.upgrade"

// agentJobKindEndpointRenew is the host-generated renewal kind (epic B2).
const agentJobKindEndpointRenew = "endpoint.renew"

// agentJobKindVantage declares, per job kind, which agent roles can execute it
// (epic A2). This is what makes the role stamped in an agent's certificate mean
// something at claim time rather than just being a label on the Agents page.
//
// The cut follows what the work physically is, not what it is called:
//
//   - trust.distribute acts on the machine the agent runs on — install these
//     roots in this trust store. A relay sitting in front of an F5 has no
//     filesystem of the F5's and no business installing roots on its own box.
//   - discovery.run, endpoint.verify, and revocation.probe are observations made from a vantage:
//     connect to this listener as a client would, reach this responder across the
//     segment. That vantage is the entire reason a network agent exists.
//   - connector.deploy and connector.rollback are legitimately both. A host agent
//     deploys to the services on its own machine; a network agent deploys to an
//     appliance it can reach. Which one a given job needs is a property of the
//     connector's target, not of the kind — so the kind-level gate cannot decide
//     it. Narrowing this to per-target locality is A3's job, once connectors
//     declare whether their target can host an agent at all. Until then this is
//     open at the kind level and the honest thing is to say so rather than to
//     invent a restriction that does not hold.
var agentJobKindVantage = map[string][]string{
	// C2 changed this. discovery.run was host work when it meant "enumerate this
	// machine's filesystem"; it is now a SEGMENT sweep, which is a vantage
	// question — the ranges worth scanning are the ones behind a firewall that
	// only a relay sits inside. A host agent's own filesystem inventory travels
	// on the inventory path, not as a claimed job.
	"discovery.run":         {mtls.AgentRoleNetwork},
	relay.KindADCSInventory: {mtls.AgentRoleNetwork},
	"trust.distribute":      {mtls.AgentRoleHost},
	"endpoint.verify":       {mtls.AgentRoleNetwork},
	// R1: reads public distribution points from a vantage inside the segment,
	// because the CDPs that matter most are internal ones a SaaS control plane
	// cannot reach by design.
	"revocation.probe":   {mtls.AgentRoleNetwork},
	"connector.deploy":   {mtls.AgentRoleHost, mtls.AgentRoleNetwork},
	"connector.rollback": {mtls.AgentRoleHost, mtls.AgentRoleNetwork},
	"connector.test":     {mtls.AgentRoleHost, mtls.AgentRoleNetwork},
	// B2: HOST ONLY, and this one is not a judgement call. The kind exists so a
	// private key is generated on the machine that will serve it; a network
	// relay generating a key for an appliance it merely reaches would recreate
	// the exact custody hop the epic removes, with an extra machine in the
	// chain instead of one fewer.
	agentJobKindEndpointRenew: {mtls.AgentRoleHost},
	// A5: any enrolled agent may upgrade ITSELF — the row's required_agent_id
	// is what narrows the work to one machine, and a relay's binary needs
	// rings exactly as much as a host's. Role is the wrong axis here; identity
	// is the right one, and the claim SQL enforces it.
	agentJobKindUpgrade: {mtls.AgentRoleHost, mtls.AgentRoleNetwork},
	// I2: a CMDB read is a vantage question — the instance worth relaying to
	// is the one behind a firewall only the in-segment relay sits inside.
	agentJobKindCMDBSync: {mtls.AgentRoleNetwork},
	// I5: identical reasoning for an on-prem MDM.
	agentJobKindMDMSync:    {mtls.AgentRoleNetwork},
	agentJobKindTicketSync: {mtls.AgentRoleNetwork},
}

// agentRolePermitsKind reports whether an agent holding roles may execute kind.
// A kind with no declared vantage is refused rather than allowed: adding a job
// kind and forgetting to say who may run it should fail closed.
func agentRolePermitsKind(roles []string, kind string) bool {
	permitted, declared := agentJobKindVantage[kind]
	if !declared {
		return false
	}
	for _, role := range roles {
		for _, allowed := range permitted {
			if role == allowed {
				return true
			}
		}
	}
	return false
}

const (
	// agentJobMaxBatch caps one claim. A small batch keeps work spread across a
	// fleet and keeps a lease short enough to be meaningful.
	agentJobMaxBatch = 16
	// agentJobDefaultLease is long enough for a deploy-and-reload, short enough
	// that a dead agent's work comes back in under a minute.
	agentJobDefaultLease = 45 * time.Second
	// agentJobMaxLease bounds what an agent may ask for. A lease is a promise
	// that the holder is alive; one long enough to hide a dead agent for an hour
	// is not a promise, it is a stall.
	agentJobMaxLease = 10 * time.Minute
	// agentJobPollSeconds is the hint an agent gets for when to ask again.
	agentJobPollSeconds = 15
	// Structured observation reports are bounded again at the trust boundary,
	// after the relay's own bounded upstream read and typed parser.
	maxStructuredSyncReportBytes = 1 << 20
)

// ClaimJobs leases estate-touching work to the calling agent.
func (a *agentService) ClaimJobs(ctx context.Context, req *transport.ClaimJobsRequest) (*transport.ClaimJobsResponse, error) {
	info, err := a.peerInfo(ctx)
	if err != nil {
		return nil, err
	}
	if a.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "agent job ledger is not configured")
	}
	kinds := allowedAgentJobKinds(a.claimableJobKinds, agentClaimKinds(req))
	// The role comes off the certificate the agent authenticated with — issued
	// against an operator's grant — never off the request (epic A2). An agent that
	// reaches for work outside its vantage gets that work withheld and the reach
	// recorded, because a host agent asking for relay work is either misconfigured
	// or is the thing this gate exists to catch, and both are worth seeing.
	permitted, refused := partitionByAgentRole(info.Roles, kinds)
	if len(refused) > 0 {
		a.recordAgentJobEvent(ctx, info.TenantID, "agent.jobs.role_refused", map[string]any{
			"agent": info.CommonName, "roles": info.Roles, "refused_kinds": refused,
		})
	}
	kinds = permitted
	if len(kinds) == 0 {
		// Not an error: an agent that can execute nothing this control plane
		// hands out should keep heartbeating, not crash-loop on a refusal.
		return &transport.ClaimJobsResponse{NextPollSeconds: agentJobPollSeconds}, nil
	}

	limit := req.Limit
	if limit <= 0 || limit > agentJobMaxBatch {
		limit = agentJobMaxBatch
	}
	lease := time.Duration(req.LeaseSeconds) * time.Second
	if lease <= 0 {
		lease = agentJobDefaultLease
	}
	if lease > agentJobMaxLease {
		lease = agentJobMaxLease
	}

	// The certificate's roles reach the row predicate too (epic A3): kind-level
	// vantage said "connector.deploy may go to either role", and the per-row
	// demand stamped at enqueue says which role THIS deploy needs. Both gates
	// read the same certificate.
	claimed, err := a.store.ClaimAgentJobs(ctx, info.TenantID, agentRowID(info.TenantID, info.CommonName), kinds, info.Roles, limit, lease, time.Now().UTC())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "claim agent jobs: %v", err)
	}
	out := &transport.ClaimJobsResponse{NextPollSeconds: agentJobPollSeconds}
	for _, job := range claimed {
		// A claimed job carries a REFERENCE, never credential material or the
		// sealed container holding it (epic A3). The agent cannot open the seal
		// and must never hold it: shipping ciphertext it has no key for is
		// pointless at best, and at worst it is a copy of the credential sitting
		// on a host, waiting for a future key compromise to make it readable.
		payload, projectErr := a.projectClaimedJobPayload(job)
		if projectErr != nil {
			// A job whose envelope cannot be built is not handed out at all.
			// Leaving it claimed is correct: the lease lapses and it returns.
			a.recordAgentJobEvent(ctx, info.TenantID, "agent.jobs.envelope_refused", map[string]any{
				"agent": info.CommonName, "job_id": job.ID, "kind": job.Destination,
			})
			continue
		}
		if job.Destination == relay.KindADCSInventory {
			if startErr := a.startClaimedADCSRun(ctx, info.TenantID, info.CommonName, job.IdempotencyKey, payload); startErr != nil {
				// A run that cannot enter running is not handed out. Its lease
				// expires and the same event ID converges on the next claim.
				a.recordAgentJobEvent(ctx, info.TenantID, "agent.jobs.envelope_refused", map[string]any{
					"agent": info.CommonName, "job_id": job.ID, "kind": job.Destination,
				})
				continue
			}
		}
		out.Jobs = append(out.Jobs, transport.ClaimedJob{
			JobID: job.ID, Kind: job.Destination, Payload: payload,
			IdempotencyKey: job.IdempotencyKey, Attempt: job.ClaimAttempts,
			LeaseExpiresUnix: job.ClaimExpiresAt.Unix(),
		})
	}
	for _, job := range out.Jobs {
		a.metrics.observeClaim(job.Kind, 1)
	}
	if len(out.Jobs) > 0 {
		a.recordAgentJobEvent(ctx, info.TenantID, "agent.jobs.claimed", map[string]any{
			"agent": info.CommonName, "count": len(out.Jobs), "kinds": kinds,
		})
	}
	return out, nil
}

// startClaimedADCSRun makes running mean what it says: the exact network relay
// now holds the lease and can begin the directory read. The event ID comes from
// the durable outbox key, so an expired lease and reclaimed job cannot append a
// second start transition.
func (a *agentService) startClaimedADCSRun(ctx context.Context, tenantID, agentName, idempotencyKey string, payload []byte) error {
	if a.orch == nil || a.store == nil {
		return errors.New("AD CS discovery lifecycle is not configured")
	}
	var intent adcs.InventoryIntent
	if err := decodeStrictJSON(payload, &intent); err != nil {
		return err
	}
	agentID := agentRowID(tenantID, agentName)
	if intent.RequiredAgentID != "" && intent.RequiredAgentID != agentID {
		return errors.New("AD CS inventory claim does not match the selected relay")
	}
	run, err := a.store.GetDiscoveryRun(ctx, tenantID, intent.ID)
	if err != nil {
		return err
	}
	if run.SourceID != intent.SourceID || run.Execution != adcs.ExecutionRelay ||
		run.RequiredAgentRole != adcs.RequiredRoleNetwork || run.RequiredAgentID != intent.RequiredAgentID {
		return errors.New("AD CS inventory claim does not match its projected run")
	}
	if run.Status == "running" {
		return nil
	}
	if run.Status != "queued" {
		return errors.New("AD CS inventory claim references a terminal run")
	}
	return a.orch.StartDiscoveryRunWithEventID(ctx, tenantID, intent.ID,
		orchestrator.DiscoveryRelayEventID(tenantID, idempotencyKey, "adcs-run-started"))
}

// ReportJobResult records what the claiming agent did.
//
// A report from an agent that no longer holds the lease is refused rather than
// applied. That is the case that matters: the agent stalled, its lease lapsed,
// another agent took the work and may already have done it. Accepting the late
// report would mean two agents believing they own the same deploy.
func (a *agentService) ReportJobResult(ctx context.Context, req *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
	info, err := a.peerInfo(ctx)
	if err != nil {
		return nil, err
	}
	if a.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "agent job ledger is not configured")
	}
	if req.JobID <= 0 {
		return nil, status.Error(codes.InvalidArgument, "job_id is required")
	}
	agentID := agentRowID(info.TenantID, info.CommonName)
	now := time.Now().UTC()

	outcome := strings.TrimSpace(req.Outcome)
	// A terminal report is a claim about the world and must be signed. An
	// "extend" is a lease request that claims nothing, so it is not — see the
	// note on ReportJobResultRequest.Signature.
	if outcome != transport.JobOutcomeExtend {
		if err := a.verifyJobReceipt(ctx, info, req, now); err != nil {
			return nil, err
		}
	}

	switch outcome {
	// D2: all three mean the agent finished the work, so all three are terminal
	// and none returns the job to the queue. They differ in what was OBSERVED
	// afterwards, which the receipt and the endpoint state record — a
	// verify_failed deploy that got requeued would retry forever against a
	// listener that is serving the wrong certificate.
	case transport.JobOutcomeExecuted, transport.JobOutcomeVerified, transport.JobOutcomeVerifyFailed:
		return a.acceptExecutedReport(ctx, info, agentID, req, now)

	case transport.JobOutcomeFailed:
		return a.acceptFailedReport(ctx, info, agentID, req, now)

	case transport.JobOutcomeExtend:
		lease := time.Duration(req.LeaseSeconds) * time.Second
		if lease <= 0 {
			lease = agentJobDefaultLease
		}
		if lease > agentJobMaxLease {
			lease = agentJobMaxLease
		}
		until := now.Add(lease)
		ok, err := a.store.ExtendAgentJobClaim(ctx, info.TenantID, agentID, req.JobID, until)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "extend agent job claim: %v", err)
		}
		resp := &transport.ReportJobResultResponse{Accepted: ok}
		if ok {
			resp.LeaseExpiresUnix = until.Unix()
		}
		return resp, nil

	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown job outcome %q", req.Outcome)
	}
}

// allowedAgentJobKinds intersects what the agent asked for with what any agent is
// permitted to execute. An unknown kind is dropped silently rather than refused:
// a newer agent asking for a kind this control plane does not serve is a version
// skew, not an attack, and it should keep working on the kinds they share.
func allowedAgentJobKinds(enabled map[string]bool, requested []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, kind := range requested {
		kind = strings.TrimSpace(kind)
		if kind == "" || seen[kind] || !enabled[kind] {
			continue
		}
		seen[kind] = true
		out = append(out, kind)
	}
	return out
}

// partitionByAgentRole splits requested kinds into those the agent's roles permit
// and those they do not, preserving order so the refusal event names exactly what
// was asked for.
func partitionByAgentRole(roles []string, kinds []string) (permitted, refused []string) {
	for _, kind := range kinds {
		if agentRolePermitsKind(roles, kind) {
			permitted = append(permitted, kind)
			continue
		}
		refused = append(refused, kind)
	}
	return permitted, refused
}

// AgentClaimableJobKinds turns operator configuration into the enabled set,
// dropping anything outside the allowlist. An operator cannot enable
// `ca.issue` or `notification.expiry` by writing it in a config file: those are
// the control plane's own effects, and moving them into the estate would put
// CA-adjacent work on a host.
func AgentClaimableJobKinds(configured []string) map[string]bool {
	out := map[string]bool{}
	for _, kind := range configured {
		kind = strings.TrimSpace(kind)
		if kind != "" && agentJobKindAllowlist[kind] {
			out[kind] = true
		}
	}
	return out
}

// recordAgentJobEvent appends claim/report evidence to the tenant's event log.
// Best-effort by design: failing to record the note must not fail the job the
// operator is waiting on, and the ledger row is the authoritative state either
// way.
// acceptExecutedReport closes the claim for work an agent says it performed.
//
// Extracted from ReportJobResult so each terminal outcome is one thing with a
// name. The switch above is the shape of the protocol; what each outcome means
// belongs beside itself.
func (a *agentService) acceptExecutedReport(ctx context.Context, info mtls.PeerCertInfo,
	agentID string, req *transport.ReportJobResultRequest, now time.Time) (*transport.ReportJobResultResponse, error) {
	claim, held, err := a.store.AgentJobClaimForResult(ctx, info.TenantID, agentID, req.JobID, req.Attempt, now)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load agent job claim: %v", err)
	}
	if !held {
		return &transport.ReportJobResultResponse{Accepted: false}, nil
	}
	if a.outbox == nil {
		return nil, status.Error(codes.Internal, "agent job outbox completion is not configured")
	}

	// Apply structured observations before closing the lease. A failed or
	// interrupted projection leaves the durable job claim retryable. Receivers
	// derive stable event IDs from the outbox key, so partial retries converge.
	var ingestErr error
	switch claim.Destination {
	case agentJobKindCMDBSync:
		if a.recordCMDBSync == nil {
			ingestErr = errors.New("CMDB result receiver is not configured")
		} else {
			ingestErr = a.recordCMDBSync(ctx, info.TenantID, info.CommonName, claim.IdempotencyKey, claim.Payload, req.Detail)
		}
	case agentJobKindMDMSync:
		if a.recordMDMSync == nil {
			ingestErr = errors.New("MDM result receiver is not configured")
		} else {
			ingestErr = a.recordMDMSync(ctx, info.TenantID, info.CommonName, claim.IdempotencyKey, claim.Payload, req.Detail)
		}
	case agentJobKindTicketSync:
		if a.recordTicketSync == nil {
			ingestErr = errors.New("ticket result receiver is not configured")
		} else {
			ingestErr = a.recordTicketSync(ctx, info.TenantID, info.CommonName, claim.IdempotencyKey, claim.Payload, req.Detail)
		}
	case relay.KindDiscoveryRun:
		if a.recordDiscoveryScan == nil {
			ingestErr = errors.New("discovery result receiver is not configured")
		} else {
			ingestErr = a.recordDiscoveryScan(ctx, info.TenantID, info.CommonName, claim.IdempotencyKey, claim.Payload, req.Detail)
		}
	case relay.KindADCSInventory:
		if a.recordADCSInventory == nil {
			ingestErr = errors.New("AD CS inventory result receiver is not configured")
		} else {
			ingestErr = a.recordADCSInventory(ctx, info.TenantID, info.CommonName, claim.IdempotencyKey, claim.Payload, req.Detail)
		}
	}
	if ingestErr != nil {
		return nil, status.Errorf(codes.Internal, "ingest signed agent result: %v", ingestErr)
	}

	// Closing the exact claim and retiring its outbox intent is ONE durable
	// transition. A crash before it leaves the claim retryable; after it, both
	// claim and delivery are terminal. The outbox also records circuit success.
	ok, err := a.outbox.CompleteAgentJobClaim(ctx, info.TenantID, agentID, req.JobID, req.Attempt, now)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "complete agent job claim: %v", err)
	}
	if !ok {
		return &transport.ReportJobResultResponse{Accepted: false}, nil
	}
	destination, idemKey := claim.Destination, claim.IdempotencyKey
	// The receipt travels WITH the event, not beside it. An event that says
	// an agent executed a deploy, with the agent's own signature over that
	// exact claim in the same row, is checkable by anyone later. Store the
	// signature and the statement it covers: without the statement a reader
	// has to reconstruct the signed bytes from other columns and trust their
	// own reconstruction, which is the sort of verification nobody performs.
	executed := map[string]any{
		"agent": info.CommonName, "job_id": req.JobID, "kind": destination,
		"evidence_digest": req.EvidenceDigest,
	}
	if destination == "connector.rollback" {
		var rollback struct {
			Connector              string `json:"connector"`
			Target                 string `json:"target"`
			TargetID               string `json:"target_id"`
			PredecessorFingerprint string `json:"predecessor_fingerprint"`
			SuccessorFingerprint   string `json:"successor_fingerprint"`
			RequiredAgentID        string `json:"required_agent_id"`
			RequiredAgentRole      string `json:"required_agent_role"`
		}
		if json.Unmarshal(claim.Payload, &rollback) == nil {
			executed["connector"] = rollback.Connector
			executed["target"] = rollback.Target
			executed["target_id"] = rollback.TargetID
			executed["predecessor_fingerprint"] = rollback.PredecessorFingerprint
			executed["successor_fingerprint"] = rollback.SuccessorFingerprint
			executed["required_agent_id"] = rollback.RequiredAgentID
			executed["required_agent_role"] = rollback.RequiredAgentRole
		}
	}
	a.attachJobReceipt(executed, info, req)
	a.recordAgentJobEvent(ctx, info.TenantID, "agent.job.executed", executed)
	a.recordVerifiedReceipt(ctx, info, req, destination, now)
	// D5: a dry-run's whole output is its plan, and the relay carries it in
	// Detail. It becomes a delivery receipt an operator can read rather than
	// an event nobody looks at, and the status distinguishes "a deploy would
	// work" from "a deploy would not" — reporting only that the JOB
	// succeeded would bury the answer the operator asked for.
	if destination == "connector.test" && a.recordDryRun != nil {
		a.recordDryRun(ctx, info.TenantID, info.CommonName, idemKey, req.Detail)
	}
	// D2: a verification sweep becomes observed endpoint state. The report is
	// the whole point of the job — a sweep whose findings stayed in the job row
	// would leave the estate exactly as blind as before it ran.
	if destination == relay.KindEndpointVerify && a.recordEndpointVerification != nil {
		a.recordEndpointVerification(ctx, info.TenantID, info.CommonName, idemKey, req.Detail)
	}
	// D2, local vantage: a deploy that verified — or failed to — carries the
	// same report shape as a sweep. One decoder for both, because the one that
	// drifts is always the one exercised less, and here that would be the only
	// witness that a reload took effect.
	if destination == "connector.deploy" && a.recordDeployVerification != nil &&
		(req.Outcome == transport.JobOutcomeVerified || req.Outcome == transport.JobOutcomeVerifyFailed) {
		payload, _, _ := a.store.AgentJobPayload(ctx, info.TenantID, req.JobID)
		a.recordDeployVerification(ctx, info.TenantID, info.CommonName, idemKey, req.Detail, payload)
	}
	if destination == "connector.rollback" && a.recordDeployVerification != nil &&
		(req.Outcome == transport.JobOutcomeVerified || req.Outcome == transport.JobOutcomeVerifyFailed) {
		a.recordDeployVerification(ctx, info.TenantID, info.CommonName, idemKey, req.Detail, claim.Payload)
	}
	// B2: a host-generated renewal reports the same three outcomes a deploy
	// does, and needs the same two things done with them.
	//
	// The lifecycle transition is the load-bearing one. The dispatcher hands
	// this renewal off and returns WITHOUT moving the identity out of
	// StateRenewing — deliberately, because the certificate does not exist yet
	// — so nothing else in the system will ever move it. An identity left in
	// renewing is not merely mislabelled: the scheduler will not renew it
	// again, so the endpoint silently stops being renewed and expires months
	// later with every surface reporting the rotation as succeeded.
	if destination == agentJobKindEndpointRenew {
		payload, _, _ := a.store.AgentJobPayload(ctx, info.TenantID, req.JobID)
		if a.recordDeployVerification != nil &&
			(req.Outcome == transport.JobOutcomeVerified || req.Outcome == transport.JobOutcomeVerifyFailed) {
			a.recordDeployVerification(ctx, info.TenantID, info.CommonName, idemKey, req.Detail, payload)
		}
		if a.completeHostRenewal != nil {
			a.completeHostRenewal(ctx, info.TenantID, payload, req.Outcome)
		}
	}
	// D2 + D4: the deploy applied and the listener is not serving it. That is
	// the one condition under which a rollback is unambiguously the right
	// response, and it is the decision D4's executed re-bind was waiting for.
	// Opt-in per target — see maybeAutoRollbackAfterVerifyFailure.
	if destination == "connector.deploy" && req.Outcome == transport.JobOutcomeVerifyFailed {
		a.maybeAutoRollbackAfterVerifyFailure(ctx, info.TenantID, agentID, req.JobID)
	}
	// D4: a re-bind that actually happened. The receipt is written from the
	// JOB payload rather than from the agent's report, because the payload
	// is what the control plane itself queued — an agent cannot name a
	// different target in its result and have that recorded as fact.
	if destination == "connector.rollback" && a.recordRollback != nil {
		a.recordRollbackFromJob(ctx, info.TenantID, info.CommonName, req.JobID, idemKey, req.Outcome, "")
	}
	return &transport.ReportJobResultResponse{Accepted: true}, nil
}

// acceptFailedReport releases — or permanently retires — work an agent could not
// perform.
func (a *agentService) acceptFailedReport(ctx context.Context, info mtls.PeerCertInfo,
	agentID string, req *transport.ReportJobResultRequest, now time.Time) (*transport.ReportJobResultResponse, error) {

	detail := strings.TrimSpace(req.Detail)
	// A rollback that can never succeed leaves the queue instead of being
	// retried forever. The claim path has no attempts predicate, so a
	// requeued job is re-claimed every poll — and each rollback attempt
	// redeems an appliance credential out of the seal. Retrying an
	// impossible operation would hold material outside the seal
	// indefinitely, which is exactly what single-use redemption exists to
	// prevent.
	permanent := false
	if dest, derr := a.store.AgentJobDestination(ctx, info.TenantID, req.JobID); derr == nil &&
		dest == "connector.rollback" && transport.RollbackReasonIsPermanent(detail) {
		permanent = true
	}
	var ok bool
	var err error
	if permanent {
		ok, err = a.store.FailAgentJobTerminally(ctx, info.TenantID, agentID, req.JobID, detail, now)
	} else {
		ok, err = a.store.ReleaseAgentJob(ctx, info.TenantID, agentID, req.JobID, req.Detail)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "release agent job: %v", err)
	}
	if ok && a.recordRollback != nil {
		if dest, derr := a.store.AgentJobDestination(ctx, info.TenantID, req.JobID); derr == nil && dest == "connector.rollback" {
			// The agent's reported detail is a closed-set reason for this
			// kind, so it classifies contact. It is not free text and is
			// not rendered as the agent's words.
			a.recordRollbackFromJob(ctx, info.TenantID, info.CommonName, req.JobID, "",
				transport.JobOutcomeFailed, strings.TrimSpace(req.Detail))
		}
	}
	if ok {
		failed := map[string]any{
			"agent": info.CommonName, "job_id": req.JobID,
			"detail": a.agentDetailForHistory(ctx, info.TenantID, agentID, req),
		}
		// A failure receipt matters more than a success one, not less: it is
		// the record that says a machine tried and could not, and it is the
		// record somebody will dispute.
		a.attachJobReceipt(failed, info, req)
		a.recordAgentJobEvent(ctx, info.TenantID, "agent.job.failed", failed)
		a.recordVerifiedReceipt(ctx, info, req, "", now)
	}
	return &transport.ReportJobResultResponse{Accepted: ok}, nil
}

// receiptSkew bounds how far a receipt's own timestamp may sit from the
// server's clock.
//
// It is wide enough that ordinary drift on an unsynchronized host does not
// reject honest work, and narrow enough that a captured receipt cannot be held
// and replayed later in the day. A signature stays valid forever; this is what
// gives it an expiry.
const receiptSkew = 10 * time.Minute

// verifyJobReceipt checks that a terminal report was signed by the agent whose
// certificate is on this connection, over exactly the facts it is reporting.
//
// Everything identifying goes into the statement from the CERTIFICATE, not from
// the request: tenant and agent name. So there is no forged-receipt case to
// handle separately and no cross-tenant case to handle separately — both are
// the same check. A receipt signed by a different key does not verify. A receipt
// signed for a different tenant was signed over different bytes than the ones
// rebuilt here, and does not verify either. Fail-closed, with an audit event,
// because a rejected receipt is a security event whether it was an attack or a
// clock: somebody's agent believes it did work the ledger will not record.
func (a *agentService) verifyJobReceipt(ctx context.Context, info mtls.PeerCertInfo,
	req *transport.ReportJobResultRequest, now time.Time) error {
	reject := func(reason string) error {
		a.recordAgentJobEvent(ctx, info.TenantID, "agent.job.receipt.rejected", map[string]any{
			"agent": info.CommonName, "job_id": req.JobID,
			"outcome": strings.TrimSpace(req.Outcome), "reason": reason,
			"agent_fingerprint": info.FingerprintSHA256,
		})
		// And into the read model, so a refusal is a number on the Operations
		// page rather than a line in a stream nobody replays. reason comes from
		// this closed set, never from the agent.
		//
		// Only for work this agent actually holds. The audit event above takes
		// every refusal unconditionally — it is the security record — but the
		// ledger drives an operator-facing count of refused work, and an agent
		// naming job ids it never claimed would fill that count with jobs that
		// do not exist.
		if a.store != nil {
			if held, herr := a.store.AgentJobIsClaimedBy(ctx, info.TenantID,
				agentRowID(info.TenantID, info.CommonName), req.JobID); herr == nil && held {
				_ = a.store.RecordAgentJobReceipt(ctx, info.TenantID, store.AgentJobReceipt{
					JobID: req.JobID, Attempt: req.Attempt, Agent: info.CommonName,
					Outcome: strings.TrimSpace(req.Outcome), State: store.AgentJobReceiptRejected,
					Reason: reason, SignerFingerprint: info.FingerprintSHA256, ObservedAt: now,
				})
			}
		}
		return status.Errorf(codes.PermissionDenied, "job receipt rejected: %s", reason)
	}
	if len(req.Signature) == 0 {
		return reject("unsigned")
	}
	if req.IssuedAtUnix <= 0 {
		return reject("no issued-at")
	}
	issued := time.Unix(req.IssuedAtUnix, 0).UTC()
	if delta := now.Sub(issued); delta > receiptSkew || delta < -receiptSkew {
		return reject("issued-at outside the accepted window")
	}
	statement := transport.JobReceiptStatement{
		TenantID:        info.TenantID,
		AgentCommonName: info.CommonName,
		JobID:           req.JobID,
		Attempt:         req.Attempt,
		Outcome:         strings.TrimSpace(req.Outcome),
		EvidenceDigest:  req.EvidenceDigest,
		DetailDigest:    transport.DetailDigest(req.Detail),
		IssuedAtUnix:    req.IssuedAtUnix,
	}
	if err := statement.Validate(); err != nil {
		return reject("statement is not canonicalizable")
	}
	if err := mtls.VerifyStatement(info.LeafDER, statement.Canonical(), req.Signature); err != nil {
		return reject("signature does not verify against the presented certificate")
	}
	return nil
}

// attachJobReceipt adds the verified receipt to an event payload.
//
// The statement is stored as the canonical bytes the agent actually signed,
// rebuilt from the certificate exactly as verifyJobReceipt rebuilt them, so a
// reader verifies what was signed rather than a paraphrase of it. The detail
// digest inside it is what lets an operator prove the failure text they are
// reading is the text the agent committed to — the text itself is stored
// separately and can be edited by anyone with database access; the digest
// cannot be edited to match without the agent's key.
func (a *agentService) attachJobReceipt(payload map[string]any, info mtls.PeerCertInfo,
	req *transport.ReportJobResultRequest) {
	if len(req.Signature) == 0 {
		return
	}
	statement := transport.JobReceiptStatement{
		TenantID:        info.TenantID,
		AgentCommonName: info.CommonName,
		JobID:           req.JobID,
		Attempt:         req.Attempt,
		Outcome:         strings.TrimSpace(req.Outcome),
		EvidenceDigest:  req.EvidenceDigest,
		DetailDigest:    transport.DetailDigest(req.Detail),
		IssuedAtUnix:    req.IssuedAtUnix,
	}
	payload["receipt_statement"] = string(statement.Canonical())
	payload["receipt_signature"] = base64.StdEncoding.EncodeToString(req.Signature)
	// The certificate fingerprint names WHICH key to verify against. An agent
	// re-enrolls and gets a new certificate; without this, a receipt signed by
	// the old one becomes unverifiable the moment the new one is issued.
	payload["receipt_signer_fingerprint"] = info.FingerprintSHA256
}

// recordVerifiedReceipt stores a receipt that passed verification.
//
// It is stored whole — statement, signature, signer fingerprint — so the check
// can be repeated later by someone who does not trust that it happened. A read
// model that recorded only "verified: true" would be the control plane vouching
// for itself again, which is the exact thing the signature exists to replace.
// recordRollbackFromJob reads the queued job's own payload and records the
// re-bind result from it.
//
// From the PAYLOAD, never from the agent's report. The payload is what this
// control plane queued; a receipt built from what an agent said would let an
// agent name a target it was never given and have that written into the
// tenant's evidence chain as fact.
func (a *agentService) recordRollbackFromJob(ctx context.Context, tenantID, agentName string, jobID int64, idemKey, outcome, reason string) {
	if a.store == nil || a.recordRollback == nil {
		return
	}
	payload, key, err := a.store.AgentJobPayload(ctx, tenantID, jobID)
	if err != nil {
		return
	}
	if idemKey == "" {
		idemKey = key
	}
	a.recordRollback(ctx, tenantID, agentName, idemKey, string(payload), outcome, reason)
}

func (a *agentService) recordVerifiedReceipt(ctx context.Context, info mtls.PeerCertInfo,
	req *transport.ReportJobResultRequest, kind string, now time.Time) {
	if a.store == nil || len(req.Signature) == 0 {
		return
	}
	statement := transport.JobReceiptStatement{
		TenantID:        info.TenantID,
		AgentCommonName: info.CommonName,
		JobID:           req.JobID,
		Attempt:         req.Attempt,
		Outcome:         strings.TrimSpace(req.Outcome),
		EvidenceDigest:  req.EvidenceDigest,
		DetailDigest:    transport.DetailDigest(req.Detail),
		IssuedAtUnix:    req.IssuedAtUnix,
	}
	_ = a.store.RecordAgentJobReceipt(ctx, info.TenantID, store.AgentJobReceipt{
		JobID: req.JobID, Attempt: req.Attempt, Agent: info.CommonName, Kind: kind,
		Outcome: strings.TrimSpace(req.Outcome), State: store.AgentJobReceiptVerified,
		SignerFingerprint: info.FingerprintSHA256,
		Statement:         string(statement.Canonical()),
		Signature:         base64.StdEncoding.EncodeToString(req.Signature),
		ObservedAt:        now,
	})
}

func (a *agentService) recordAgentJobEvent(ctx context.Context, tenantID, eventType string, data map[string]any) {
	if a.log == nil {
		return
	}
	body, err := json.Marshal(data)
	if err != nil {
		return
	}
	_, _ = a.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: body})
}

// GetKinds is the nil-safe read the handler uses.
func agentClaimKinds(req *transport.ClaimJobsRequest) []string {
	if req == nil {
		return nil
	}
	return req.Kinds
}

// agentJobPosture reads live job-ledger health for the operations surface (A1).
//
// It separates three things an empty queue could mean: the channel is not
// mounted at all, it is mounted but no kind is enabled, or it is mounted and
// enabled and the work has simply drained. An operator staring at zeros needs to
// know which.
func (s *Server) agentJobPosture(ctx context.Context) (api.AgentJobPosture, error) {
	out := api.AgentJobPosture{
		GeneratedAt: time.Now().UTC(),
		Served:      s.AgentChannelServed(),
		Queues:      []api.AgentJobQueue{},
	}
	svc, _ := s.agentSvc.(*bulkheadedAgentService)
	var enabled map[string]bool
	if svc != nil {
		if inner, ok := svc.next.(*agentService); ok {
			enabled = inner.claimableJobKinds
		}
	}
	for kind := range enabled {
		out.ClaimableKinds = append(out.ClaimableKinds, kind)
	}
	sort.Strings(out.ClaimableKinds)

	if s.store == nil {
		return out, nil
	}
	// Every allowlisted kind is reported, enabled or not: a kind that exists but
	// is switched off should read as switched off, not as absent.
	kinds := make([]string, 0, len(agentJobKindAllowlist))
	for kind := range agentJobKindAllowlist {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)

	// Credential custody first: how much material is outside the seal right now
	// is the number an operator most needs when relays hold credentials (A3).
	now := time.Now().UTC()
	if redemptions, redErr := s.store.AgentJobRedemptions(ctx, now); redErr == nil {
		out.Redemptions = api.AgentJobRedemptions{Live: redemptions.Live, Total: redemptions.Total}
		if redemptions.OldestLiveAt != nil {
			if age := int(now.Sub(*redemptions.OldestLiveAt).Seconds()); age > 0 {
				out.Redemptions.OldestLiveSeconds = age
			}
		}
	}

	// Receipt integrity (A1). It sits beside credential custody because the two
	// answer the same kind of question about the fabric: what is outside the
	// seal right now, and is what comes back trustworthy.
	if receipts, recErr := s.store.AgentJobReceiptSummary(ctx); recErr == nil {
		out.Receipts = api.AgentJobReceipts{
			Verified: receipts.Verified, Rejected: receipts.Rejected,
			LastRejectedReason: receipts.LastRejectedReason,
			LastRejectedAt:     receipts.LastRejectedAt,
		}
	}

	depths, err := s.store.AgentJobQueueDepths(ctx, kinds)
	if err != nil {
		return out, err
	}
	byKind := make(map[string]store.AgentJobQueueDepth, len(depths))
	for _, d := range depths {
		byKind[d.Destination] = d
	}
	for _, kind := range kinds {
		q := api.AgentJobQueue{Kind: kind, Enabled: enabled[kind]}
		if d, ok := byKind[kind]; ok {
			q.Pending, q.Claimed = d.Pending, d.Claimed
			if d.OldestUnclaimedAt != nil {
				if age := now.Sub(d.OldestUnclaimedAt.UTC()); age > 0 {
					q.OldestUnclaimedSeconds = int(age.Seconds())
				}
			}
		}
		out.Queues = append(out.Queues, q)
	}
	// A6: publish the same levels this read just computed, so the Prometheus
	// series and the Operations console can never disagree about what the fabric
	// is doing. Reusing the posture read rather than adding a second query also
	// means the metrics carry the same tenant-free shape the API surface does.
	s.agentMetrics.observeJobLedger(out)
	return out, nil
}

// projectClaimedJobPayload builds the envelope an agent actually receives.
//
// Connector jobs are projected to a reference-only intent: what to deploy and
// where, with every credential replaced by the name of a reference the agent can
// redeem for one attempt. Everything else passes through — no other job kind
// carries credential material, and rewriting their payloads would break A1's
// contract for no gain.
func (a *agentService) projectClaimedJobPayload(job store.AgentJob) ([]byte, error) {
	// D4: a rollback payload is a different shape and carries no key material by
	// construction — that is the whole reason it is executable. It is projected
	// separately so the predecessor fingerprint, which is the ONE thing a
	// rollback needs, is not dropped by a projection built for deploys.
	if job.Destination == "connector.rollback" {
		return projectRollbackIntent(job)
	}
	switch job.Destination {
	case "connector.deploy", "connector.test":
	default:
		// Every other kind's payload is already reference-only by construction:
		// a sweep names ranges, a revocation probe names URLs, an AD CS
		// inventory names a directory and a credential REFERENCE. None carries
		// material, so none needs projecting.
		return job.Payload, nil
	}
	intent, err := relayDeployIntentFromSealed(job)
	if err != nil {
		return nil, err
	}
	return json.Marshal(intent)
}

// agentDetailForHistory decides what an agent's own words may become in the
// tenant's permanent event log (epic A3).
//
// The rule is about what the agent was HOLDING, not about what it wrote. If this
// attempt redeemed a credential, the agent's free text is untrusted in a way no
// redactor can repair: an appliance password is short and word-shaped, so it is
// indistinguishable from ordinary prose, and an appliance that echoes it back in
// an error body would write it into history that cannot be wiped (AN-8). No
// entropy floor catches "hunter2-lab", and pretending otherwise would be the
// kind of control that reads as protection while providing none.
//
// So a credential-bearing attempt records a closed-set marker instead. The
// operator is not left blind: the failure reason, the redemption's audit ref,
// and the evidence digest all remain, and the agent's transcript stays on the
// agent where an operator with access to that host can read it.
//
// An attempt that redeemed nothing never held a secret to echo, so its detail
// flows through redaction as before.
func (a *agentService) agentDetailForHistory(ctx context.Context, tenantID, agentID string, req *transport.ReportJobResultRequest) string {
	if a.store != nil {
		redeemed, err := a.store.AgentJobAttemptRedeemedCredential(ctx, tenantID, req.JobID)
		if err != nil || redeemed {
			// A classification error fails closed: unknown custody is treated as
			// credential-bearing.
			return agentDetailCredentialBearing
		}
	}
	return redactAgentDetail(req.Detail)
}

// redactAgentDetail strips secret-shaped material out of agent-supplied text
// before it becomes durable history.
//
// It deliberately uses only the secret redactor, NOT the PII redactor: an
// operator debugging a failed deploy needs to read "connect to
// lb-01.prod.internal:443 refused", and rewriting hostnames and addresses would
// turn the one field that explains a failure into noise. If the redactor still
// leaves secret-like material, the text is dropped entirely rather than stored —
// the same fail-closed stance the support bundle takes with a whole artifact.
func redactAgentDetail(detail string) string {
	detail = strings.TrimSpace(detail)
	if detail == "" {
		return ""
	}
	if len(detail) > agentDetailMaxRunes {
		detail = detail[:agentDetailMaxRunes]
	}
	redacted := aimodel.DefaultRedactor(detail)
	if aimodel.ResidualSecret(redacted) {
		return agentDetailWithheld
	}
	return redacted
}

const (
	// agentDetailMaxRunes bounds how much agent-supplied text becomes durable.
	// An appliance that returns its whole configuration in an error body should
	// not be able to write it into the event log.
	agentDetailMaxRunes = 2048
	// agentDetailWithheld replaces text that still looks secret-bearing after
	// redaction. It is a closed-set marker, like the failure reasons.
	agentDetailWithheld = "withheld: agent detail still contained secret-like material after redaction"
	// agentDetailCredentialBearing replaces the detail of an attempt that
	// redeemed a credential. See agentDetailForHistory.
	agentDetailCredentialBearing = "withheld: this attempt held redeemed credential material; see the redemption audit ref and the agent's local transcript"
)
