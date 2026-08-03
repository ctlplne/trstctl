// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/aimodel"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
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
	"trust.distribute": true,
}

// agentJobKindVantage declares, per job kind, which agent roles can execute it
// (epic A2). This is what makes the role stamped in an agent's certificate mean
// something at claim time rather than just being a label on the Agents page.
//
// The cut follows what the work physically is, not what it is called:
//
//   - discovery.run and trust.distribute act on the machine the agent runs on —
//     enumerate this filesystem, install these roots in this trust store. A relay
//     sitting in front of an F5 has no filesystem of the F5's to scan and no
//     business installing roots on its own box on someone else's behalf.
//   - endpoint.verify and revocation.probe are observations made from a vantage:
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
	"discovery.run":      {mtls.AgentRoleHost},
	"trust.distribute":   {mtls.AgentRoleHost},
	"endpoint.verify":    {mtls.AgentRoleNetwork},
	"revocation.probe":   {mtls.AgentRoleNetwork},
	"connector.deploy":   {mtls.AgentRoleHost, mtls.AgentRoleNetwork},
	"connector.rollback": {mtls.AgentRoleHost, mtls.AgentRoleNetwork},
	"connector.test":     {mtls.AgentRoleHost, mtls.AgentRoleNetwork},
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

	switch strings.TrimSpace(req.Outcome) {
	case transport.JobOutcomeExecuted:
		// Two leases have to agree: the agent still holds its claim, and no
		// dispatch worker holds the entry. Closing the claim proves the first;
		// the orchestrator's CompleteByKey proves the second and records the
		// destination's circuit success, which a hand-rolled status flip here
		// would skip (AN-6).
		destination, idemKey, ok, err := a.store.MarkAgentJobCompleted(ctx, info.TenantID, agentID, req.JobID, now)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "close agent job claim: %v", err)
		}
		if !ok {
			return &transport.ReportJobResultResponse{Accepted: false}, nil
		}
		if a.outbox != nil {
			if _, err := a.outbox.CompleteByKey(ctx, info.TenantID, destination, idemKey); err != nil {
				return nil, status.Errorf(codes.Internal, "complete outbox entry: %v", err)
			}
		}
		a.recordAgentJobEvent(ctx, info.TenantID, "agent.job.executed", map[string]any{
			"agent": info.CommonName, "job_id": req.JobID, "kind": destination,
			"evidence_digest": req.EvidenceDigest,
		})
		// D5: a dry-run's whole output is its plan, and the relay carries it in
		// Detail. It becomes a delivery receipt an operator can read rather than
		// an event nobody looks at, and the status distinguishes "a deploy would
		// work" from "a deploy would not" — reporting only that the JOB
		// succeeded would bury the answer the operator asked for.
		if destination == "connector.test" && a.recordDryRun != nil {
			a.recordDryRun(ctx, info.TenantID, info.CommonName, idemKey, req.Detail)
		}
		return &transport.ReportJobResultResponse{Accepted: true}, nil

	case transport.JobOutcomeFailed:
		ok, err := a.store.ReleaseAgentJob(ctx, info.TenantID, agentID, req.JobID, req.Detail)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "release agent job: %v", err)
		}
		if ok {
			a.recordAgentJobEvent(ctx, info.TenantID, "agent.job.failed", map[string]any{
				"agent": info.CommonName, "job_id": req.JobID,
				"detail": a.agentDetailForHistory(ctx, info.TenantID, agentID, req),
			})
		}
		return &transport.ReportJobResultResponse{Accepted: ok}, nil

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
	switch job.Destination {
	case "connector.deploy", "connector.rollback", "connector.test":
	default:
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
