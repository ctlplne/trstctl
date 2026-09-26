// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/reportstate"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/custody"
)

// relayChannel adapts the transport client to the relay runtime's Channel
// (epic A3). It is the only place the two meet: internal/agent/relay holds an
// interface so it can be exercised without a gRPC server, and this binary owns
// the translation — the same shape channelAdapter uses for the heartbeat and
// renewal loops.
type relayChannel struct {
	c *transport.AgentClient
	// id yields the identity that signs job receipts, read fresh on each report
	// rather than captured. It is the SAME identity behind the channel
	// certificate, which is what makes the signature checkable: the server
	// verifies against the certificate the connection presented, so a receipt
	// signed by any other key is refused (epic A1). A renewal swaps the
	// identity mid-flight, which is why this is a function and not a value.
	id func() *mtls.AgentIdentity
	// now is injectable so the receipt's issued-at can be exercised.
	now          func() time.Time
	leaseSeconds int
	pending      *reportstate.Store
}

func (r relayChannel) ExtendJobClaim(ctx context.Context, jobID int64, attempt int) (time.Time, error) {
	lease := r.leaseSeconds
	if lease <= 0 {
		lease = int(relayMinLease.Seconds())
	}
	resp, err := r.c.ReportJobResult(ctx, &transport.ReportJobResultRequest{
		JobID: jobID, Attempt: attempt, Outcome: transport.JobOutcomeExtend, LeaseSeconds: lease,
	})
	if err != nil {
		return time.Time{}, err
	}
	if !resp.Accepted || resp.LeaseExpiresUnix <= r.clock().Unix() {
		return time.Time{}, relay.ErrJobClaimLost
	}
	return time.Unix(resp.LeaseExpiresUnix, 0), nil
}

var _ relay.JobLeaseMaintainer = relayChannel{}

func (r relayChannel) ClaimJobs(ctx context.Context, kinds []string, limit, leaseSeconds int) ([]relay.Job, error) {
	if err := r.recoverPendingReport(ctx); err != nil {
		return nil, err
	}
	resp, err := r.c.ClaimJobs(ctx, &transport.ClaimJobsRequest{
		Kinds: kinds, Limit: limit, LeaseSeconds: leaseSeconds,
	})
	if err != nil {
		return nil, err
	}
	out := make([]relay.Job, 0, len(resp.Jobs))
	for _, job := range resp.Jobs {
		out = append(out, relay.Job{
			JobID: job.JobID, Kind: job.Kind, Attempt: job.Attempt, Payload: job.Payload,
		})
	}
	return out, nil
}

func (r relayChannel) RedeemJobCredential(ctx context.Context, jobID int64, attempt int) (map[string][]byte, error) {
	resp, err := r.c.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{
		JobID: jobID, Attempt: attempt,
	})
	if err != nil {
		return nil, err
	}
	// The values are handed straight to relay.AdoptMaterial, which moves each
	// into a locked buffer and wipes the wire copy. Nothing is retained here.
	items := make(map[string][]byte, len(resp.Items))
	for _, item := range resp.Items {
		items[item.Name] = item.Value
	}
	return items, nil
}

func (r relayChannel) ReportJobResult(ctx context.Context, jobID int64, attempt int, outcome, detail, evidenceDigest string) (bool, error) {
	if terminalReport(outcome) {
		value := reportstate.Observation{JobID: jobID, Attempt: attempt, Outcome: outcome, Detail: []byte(detail), EvidenceDigest: evidenceDigest}
		defer value.Destroy()
		return r.retainAndSendReport(ctx, value)
	}
	// The tenant and the name come off the agent's OWN certificate, not off
	// config: the server rebuilds the signed statement from the certificate it
	// verified, so anything else would produce a receipt that cannot verify —
	// and an agent signing for a tenant it was not issued for.
	id := r.id()
	if id == nil {
		return false, errors.New("trstctl-agent: cannot sign a job receipt before enrollment")
	}
	req, err := transport.SignedReport(id, id.TenantID(), id.CommonName(),
		jobID, attempt, outcome, detail, evidenceDigest, r.clock().Unix())
	if err != nil {
		return false, err
	}
	return r.sendSignedReport(ctx, req)
}

func (r relayChannel) ReportJobResultWithCustody(ctx context.Context, jobID int64, attempt int,
	outcome, detail, evidenceDigest, credentialFingerprint string, record custody.Record) (bool, error) {
	id := r.id()
	if id == nil {
		return false, errors.New("trstctl-agent: cannot sign a job receipt before enrollment")
	}
	if record.Origin == custody.OriginHostAgent && record.GeneratedBy == "" {
		record.GeneratedBy = id.CommonName()
	}
	if terminalReport(outcome) {
		value := reportstate.Observation{JobID: jobID, Attempt: attempt, Outcome: outcome, Detail: []byte(detail), EvidenceDigest: evidenceDigest, CredentialFingerprint: credentialFingerprint, Custody: &record}
		defer value.Destroy()
		return r.retainAndSendReport(ctx, value)
	}
	req, err := transport.SignedReportWithCustody(id, id.TenantID(), id.CommonName(),
		jobID, attempt, outcome, detail, evidenceDigest, credentialFingerprint, record, r.clock().Unix())
	if err != nil {
		return false, err
	}
	return r.sendSignedReport(ctx, req)
}

var _ relay.CustodyReceiptChannel = relayChannel{}

// sendSignedReport retries only terminal observations, never permission to do
// more work. Every attempt sends the same signed bytes and original claim
// generation. A temporary reporting failure must not rerun the external effect.
// The caller persists terminal observations before sending. This inner loop
// retains identical signed bytes; later recovery freshly attests the stored facts.
func (r relayChannel) sendSignedReport(ctx context.Context, req *transport.ReportJobResultRequest) (bool, error) {
	switch req.Outcome {
	case transport.JobOutcomeExecuted, transport.JobOutcomeVerified,
		transport.JobOutcomeVerifyFailed, transport.JobOutcomeFailed:
	default:
		resp, err := r.c.ReportJobResult(ctx, req)
		if err != nil {
			return false, err
		}
		return resp.Accepted, nil
	}

	// Bound each RPC as well as the whole reporting window so a stuck channel
	// cannot occupy an agent worker indefinitely. Backoff includes jitter to
	// avoid synchronized retries when many agents lose the same control plane.
	reportCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	delay := 250 * time.Millisecond
	for attempt := 0; ; attempt++ {
		if err := reportCtx.Err(); err != nil {
			return false, err
		}
		callCtx, endCall := context.WithTimeout(reportCtx, 10*time.Second)
		resp, err := r.c.ReportJobResult(callCtx, req)
		endCall()
		if err == nil {
			return resp.Accepted || resp.ReceiptRecorded, nil
		}
		if ctxErr := reportCtx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		switch status.Code(err) {
		case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted:
		default:
			return false, err
		}
		if attempt == 5 {
			return false, err
		}
		jitter, err := crypto.RandomBytes(1)
		if err != nil {
			return false, err
		}
		timer := time.NewTimer(delay/2 + time.Duration(jitter[0])*(delay/2)/256)
		select {
		case <-reportCtx.Done():
			timer.Stop()
			return false, reportCtx.Err()
		case <-timer.C:
		}
		delay = min(2*delay, 4*time.Second)
	}
}

func (r relayChannel) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now().UTC()
}

// SignJobCSR sends a locally generated CSR up for signing (epic B2).
//
// This method is what makes relayChannel satisfy relay.CSRSigner, and its
// absence would be silent: the renewal executor checks for the interface and
// refuses the work when it is missing, so a build without this method would
// claim renewal jobs and fail every one of them with a message about the build
// rather than about the estate. That is the D2 defect class — a capability
// shipped and never reachable — which is exactly what this epic's sibling fix
// went and repaired one layer up.
func (r relayChannel) SignJobCSR(ctx context.Context, jobID int64, attempt int, csrDER []byte) ([]byte, []byte, string, error) {
	resp, err := r.c.SignJobCSR(ctx, &transport.SignJobCSRRequest{
		JobID: jobID, Attempt: attempt, CSRDER: csrDER,
	})
	if err != nil {
		return nil, nil, "", err
	}
	return resp.CertificatePEM, resp.ChainPEM, resp.Fingerprint, nil
}
