// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
)

// Signing a CSR an agent generated for work it holds (epic B2).
//
// This is the direction reversal the epic is built on. Every other call on this
// service sends material DOWN to an agent; this one accepts a public request
// coming UP, and its existence is what lets a private key be born on the host
// that will serve it and never travel.
//
// The authorization rule is the interesting part, and it is not "may this agent
// request certificates". It is narrower: this agent holds THIS job, the job was
// queued for a particular binding, and the CSR may assert only what that binding
// already names. An agent free to name extra SANs would have found a way to mint
// a certificate for someone else's service using nothing but a legitimately
// claimed renewal — a worse hole than the one this epic closes, opened by the
// fix for it.

// signJobCSRNameLimit bounds how many names one request may assert.
//
// Not a policy limit — the profile gate downstream is that. This exists so a
// malformed or hostile CSR cannot make the comparison below quadratic on
// attacker-chosen input.
const signJobCSRNameLimit = 64

// SignJobCSR signs a subject CSR for a job the calling agent holds.
func (a *agentService) SignJobCSR(ctx context.Context, req *transport.SignJobCSRRequest) (*transport.SignJobCSRResponse, error) {
	info, err := a.peerInfo(ctx)
	if err != nil {
		return nil, err
	}
	if a.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "agent job ledger is not configured")
	}
	if a.signSubjectCSR == nil {
		// Fails closed, like the credential resolver: a control plane with no
		// issuing path must refuse rather than appear to serve host-generated
		// renewal and strand every agent that tries it.
		return nil, status.Error(codes.FailedPrecondition, "host-generated renewal is not configured on this control plane")
	}
	if req == nil || req.JobID <= 0 {
		return nil, status.Error(codes.InvalidArgument, "job_id is required")
	}
	if len(req.CSRDER) == 0 {
		return nil, status.Error(codes.InvalidArgument, "csr_der is required")
	}

	// Check the claim before loading its subject binding. The signing dispatcher
	// rechecks it under the identity's signing/revocation fence, including the
	// current identity state; holding an old job alone does not permit signing.
	agentID := agentRowID(info.TenantID, info.CommonName)
	job, ok, err := a.store.GetAgentJobForRedemption(ctx, info.TenantID, agentID, req.JobID, time.Now().UTC())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load agent job: %v", err)
	}
	if !ok {
		// Deliberately not "not found": an agent asking about work it does not
		// hold has either lost its lease or is probing, and both get the same
		// answer rather than a distinction to enumerate against.
		return nil, status.Error(codes.PermissionDenied, "this agent does not hold that job")
	}
	// The attempt must MATCH, with no opt-out. The earlier form guarded on
	// `req.Attempt > 0 && job.ClaimAttempts > 0`, so an agent sending Attempt=0
	// skipped the comparison entirely — a check a caller can decline is not a
	// check. What it protects: a CSR built under a lapsed lease being signed
	// after the work was reassigned, leaving two hosts holding live
	// certificates for one endpoint.
	if req.Attempt != job.ClaimAttempts {
		return nil, status.Error(codes.PermissionDenied, "this agent does not hold that job on that attempt")
	}

	if job.Destination != agentJobKindEndpointRenew {
		// Only the renewal kind carries a subject binding. Signing against any
		// other payload would mean signing against a permitted-name set that was
		// never established.
		return nil, status.Errorf(codes.FailedPrecondition,
			"job kind %q does not authorize certificate issuance", job.Destination)
	}

	permitted := signJobCSRPermittedNames(job.Payload)
	if len(permitted) == 0 {
		return nil, status.Error(codes.FailedPrecondition,
			"this renewal job names no subject, so there is nothing it authorizes")
	}

	resp, err := a.signSubjectCSR(ctx, info.TenantID, info.CommonName, job, req.JobID, req.CSRDER, permitted, job.ClaimAttempts)
	if err != nil {
		return nil, err
	}
	a.recordAgentJobEvent(ctx, info.TenantID, "agent.jobs.csr_signed", map[string]any{
		"agent": info.CommonName, "job_id": req.JobID,
		"names": permitted, "fingerprint": resp.Fingerprint,
	})
	return resp, nil
}

// SignJobCSR on the bulkhead wrapper dispatches into the agent-channel pool.
//
// AN-7: a new RPC without a matching wrapper method would be served and
// permanently unimplemented — the interface assertion in agentchannel.go exists
// to make that a compile error rather than a runtime surprise.
func (b *bulkheadedAgentService) SignJobCSR(ctx context.Context, req *transport.SignJobCSRRequest) (*transport.SignJobCSRResponse, error) {
	return runAgentBulkhead(ctx, b.pool, "sign_job_csr", b.metrics, func(ctx context.Context) (*transport.SignJobCSRResponse, error) {
		return b.next.SignJobCSR(ctx, req)
	})
}

// signJobCSRPermittedNames reads the names this job's binding authorizes.
//
// From the JOB PAYLOAD, never from the request. A permitted-name set derived
// from the CSR would let the request authorize itself, which is the same as no
// authorization at all.
func signJobCSRPermittedNames(payload []byte) []string {
	var intent RelayDeployIntent
	if err := json.Unmarshal(payload, &intent); err != nil {
		return nil
	}
	out := make([]string, 0, len(intent.SubjectDNSNames)+1)
	seen := map[string]bool{}
	add := func(n string) {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" || seen[n] || len(out) >= signJobCSRNameLimit {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	for _, n := range intent.SubjectDNSNames {
		add(n)
	}
	add(intent.SubjectCommonName)
	return out
}

// csrNamesWithinBinding reports whether every name the CSR asserts is one the
// job's binding already names.
//
// SUBSET, not equality. A host renewing a certificate for a subset of the names
// it is bound to is doing something narrower than authorized, which is fine; a
// host asserting one extra name is the attack. Comparison is case-insensitive
// because DNS is, and an agent that varied case would otherwise slip a name
// past a case-sensitive check.
func csrNamesWithinBinding(requested, permitted []string) (string, bool) {
	allowed := make(map[string]bool, len(permitted))
	for _, n := range permitted {
		allowed[strings.ToLower(strings.TrimSpace(n))] = true
	}
	if len(requested) > signJobCSRNameLimit {
		return "this request asserts more names than a renewal binding may carry", false
	}
	for _, n := range requested {
		if !allowed[strings.ToLower(strings.TrimSpace(n))] {
			return n, false
		}
	}
	return "", true
}
