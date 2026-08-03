// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
)

// relayChannel adapts the transport client to the relay runtime's Channel
// (epic A3). It is the only place the two meet: internal/agent/relay holds an
// interface so it can be exercised without a gRPC server, and this binary owns
// the translation — the same shape channelAdapter uses for the heartbeat and
// renewal loops.
type relayChannel struct{ c *transport.AgentClient }

func (r relayChannel) ClaimJobs(ctx context.Context, kinds []string, limit, leaseSeconds int) ([]relay.Job, error) {
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

func (r relayChannel) ReportJobResult(ctx context.Context, jobID int64, outcome, detail, evidenceDigest string) (bool, error) {
	resp, err := r.c.ReportJobResult(ctx, &transport.ReportJobResultRequest{
		JobID: jobID, Outcome: outcome, Detail: detail, EvidenceDigest: evidenceDigest,
	})
	if err != nil {
		return false, err
	}
	return resp.Accepted, nil
}
