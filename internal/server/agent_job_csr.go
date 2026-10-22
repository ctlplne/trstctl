// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net"
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
	ctx, info, release, err := a.beginPeerWork(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
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
	permittedIPs := signJobCSRPermittedIPAddresses(job.Payload)
	permittedEmails, permittedURIs := signJobCSRPermittedEmailAndURIs(job.Payload)
	if len(permitted) == 0 && len(permittedIPs) == 0 && len(permittedEmails) == 0 && len(permittedURIs) == 0 {
		return nil, status.Error(codes.FailedPrecondition,
			"this renewal job names no subject, so there is nothing it authorizes")
	}

	resp, err := a.signSubjectCSR(ctx, info.TenantID, info.CommonName, job, req.JobID, req.CSRDER, permitted, job.ClaimAttempts)
	if err != nil {
		return nil, err
	}
	a.recordAgentJobEvent(ctx, info.TenantID, "agent.jobs.csr_signed", map[string]any{
		"agent": info.CommonName, "job_id": req.JobID,
		"names": append(append(append(append([]string(nil), permitted...), permittedIPs...), permittedEmails...), permittedURIs...), "fingerprint": resp.Fingerprint,
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
	// A common name that is an IP literal belongs to the iPAddress half of the
	// binding; offering it here would let a CSR assert it as a dNSName.
	if cn := strings.TrimSpace(intent.SubjectCommonName); net.ParseIP(cn) == nil {
		add(cn)
	}
	return out
}

// signJobCSRPermittedIPAddresses is the iPAddress half of the binding (A35):
// the job's subject_ip_addresses parsed and spelled canonically, so a CSR
// writing the same address differently still matches, de-duplicated and
// bounded like the DNS set. An entry net.ParseIP cannot read authorizes
// nothing; an authorization that cannot be read must never be read widely.
func signJobCSRPermittedIPAddresses(payload []byte) []string {
	var intent RelayDeployIntent
	if err := json.Unmarshal(payload, &intent); err != nil {
		return nil
	}
	return canonicalBoundIPAddresses(intent.SubjectIPAddresses)
}

func canonicalBoundIPAddresses(raw []string) []string {
	out := make([]string, 0, len(raw))
	seen := map[string]bool{}
	for _, entry := range raw {
		ip := net.ParseIP(strings.TrimSpace(entry))
		if ip == nil || len(out) >= signJobCSRNameLimit {
			continue
		}
		if key := ip.String(); !seen[key] {
			seen[key] = true
			out = append(out, key)
		}
	}
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

// signJobCSRPermittedEmailAndURIs reads the rfc822Name and URI halves of the
// binding (A35 extension) from the job payload, never from the request.
func signJobCSRPermittedEmailAndURIs(payload []byte) (emails, uris []string) {
	var intent RelayDeployIntent
	if err := json.Unmarshal(payload, &intent); err != nil {
		return nil, nil
	}
	return canonicalBoundEmailAddresses(intent.SubjectEmailAddresses), canonicalBoundURIs(intent.SubjectURIs)
}

// canonicalBoundEmailAddresses trims and de-duplicates rfc822Names
// case-insensitively (the mailbox part is compared as spelled by the binding;
// matching happens through csrIdentifiersWithinBinding), bounded like the DNS
// set.
func canonicalBoundEmailAddresses(raw []string) []string {
	out := make([]string, 0, len(raw))
	seen := map[string]bool{}
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		key := strings.ToLower(entry)
		if entry == "" || seen[key] || len(out) >= signJobCSRNameLimit {
			continue
		}
		seen[key] = true
		out = append(out, entry)
	}
	return out
}

// canonicalBoundURIs trims and de-duplicates URIs exactly as spelled: a URI
// identifier is opaque to the binding and is matched byte for byte.
func canonicalBoundURIs(raw []string) []string {
	out := make([]string, 0, len(raw))
	seen := map[string]bool{}
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry == "" || seen[entry] || len(out) >= signJobCSRNameLimit {
			continue
		}
		seen[entry] = true
		out = append(out, entry)
	}
	return out
}
