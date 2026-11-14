// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
)

// A227-L1 Done-when (agent): a relay schedules a job lease from the server's
// remaining time on its own monotonic clock, never by comparing the server's
// wall-clock expiry with its own. Against a server whose clock is ten minutes
// behind, a fresh five-minute lease is kept (it read as already lapsed);
// against one ten minutes ahead, the relay renews within five minutes (it
// read as fifteen); an older server that sends no remaining time keeps the
// absolute expiry.
func TestRelayLeaseFollowsTheServersRemainingTimeA227L1(t *testing.T) {
	const lease = 5 * time.Minute
	for name, c := range map[string]struct {
		serverOffset time.Duration
		sendsRemain  bool
	}{
		"server ten minutes behind": {-10 * time.Minute, true},
		"server ten minutes ahead":  {10 * time.Minute, true},
		"older server":              {0, false},
	} {
		t.Run(name, func(t *testing.T) {
			answer := func() (int64, int64) {
				expires := time.Now().Add(c.serverOffset).Add(lease).Unix()
				if !c.sendsRemain {
					return expires, 0
				}
				return expires, lease.Milliseconds()
			}
			ch := newReceiptRetryChannel(t, func(_ context.Context, req *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
				if req.Outcome != transport.JobOutcomeExtend {
					return &transport.ReportJobResultResponse{Accepted: true}, nil
				}
				expires, remaining := answer()
				return &transport.ReportJobResultResponse{Accepted: true, LeaseExpiresUnix: expires, LeaseRemainingMillis: remaining}, nil
			}, func(s *receiptRetryChannelServer) {
				s.claim = func(context.Context, *transport.ClaimJobsRequest) (*transport.ClaimJobsResponse, error) {
					expires, remaining := answer()
					return &transport.ClaimJobsResponse{Jobs: []transport.ClaimedJob{{JobID: 7, Kind: "endpoint.verify", Attempt: 1,
						LeaseExpiresUnix: expires, LeaseRemainingMillis: remaining}}}, nil
				}
			})
			ctx := context.Background()
			until, err := ch.ExtendJobClaim(ctx, 7, 1)
			if !c.sendsRemain {
				if err != nil || until.Unix() != time.Now().Add(lease).Unix() && until.Unix() != time.Now().Add(lease).Unix()-1 {
					t.Fatalf("older server: extend = %v %v; want its absolute expiry", until, err)
				}
				return
			}
			if errors.Is(err, relay.ErrJobClaimLost) || err != nil {
				t.Fatalf("a fresh %s lease was given up: %v", lease, err)
			}
			if left := time.Until(until); left <= lease-10*time.Second || left > lease {
				t.Fatalf("extend: the relay holds the lease for %s; want about %s on its own clock", left, lease)
			}
			jobs, err := ch.ClaimJobs(ctx, []string{"endpoint.verify"}, 1, int(lease.Seconds()))
			if err != nil || len(jobs) != 1 {
				t.Fatalf("claim = %+v %v", jobs, err)
			}
			if left := time.Until(jobs[0].LeaseUntil()); left <= lease-10*time.Second || left > lease {
				t.Fatalf("claim: the relay holds the lease for %s; want about %s on its own clock", left, lease)
			}
		})
	}
}
