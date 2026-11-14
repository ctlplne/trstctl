// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// A227-L1 Done-when (served): the server tells a relay how long its job lease
// has left by its own clock, on the claim and on every extend, so the relay
// never compares the server's wall-clock expiry with its own.
func TestServedJobLeasesCarryTheirRemainingTimeA227L1(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindEndpointVerify)
	token := seedScopedToken(t, h.store, h.tenant, "discovery:write", "risk:read")
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	fingerprint := strings.Repeat("ab", 32)
	if code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/pqc/pilots", token, "a227l1-pilot", map[string]any{
		"name": "lease remaining", "authority_id": "pq-issuing-ca",
		"waves": []map[string]any{{"name": "canary", "targets": []map[string]any{{"target_id": "t-1", "address": "127.0.0.1:1", "fingerprint": fingerprint}}}},
	}); code != http.StatusCreated {
		t.Fatalf("start pilot = %d %s", code, body)
	}
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindEndpointVerify}, Limit: 1, LeaseSeconds: 60})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim = %+v %v", claimed, err)
	}
	job := claimed.Jobs[0]
	if job.LeaseRemainingMillis <= 50_000 || job.LeaseRemainingMillis > 60_000 {
		t.Fatalf("the claim says %d ms remain; want about the 60 s lease", job.LeaseRemainingMillis)
	}
	if left := time.Until(time.Unix(job.LeaseExpiresUnix, 0)); left < 50*time.Second || left > 61*time.Second {
		t.Fatalf("the absolute expiry is %s away; the remaining time and it disagree", left)
	}
	extended, err := h.client.ReportJobResult(ctx, &transport.ReportJobResultRequest{JobID: job.JobID, Attempt: job.Attempt,
		Outcome: transport.JobOutcomeExtend, LeaseSeconds: 120})
	if err != nil || !extended.Accepted || extended.LeaseRemainingMillis <= 110_000 || extended.LeaseRemainingMillis > 120_000 {
		t.Fatalf("extend = %+v %v; want about 120 s remaining", extended, err)
	}
	t.Logf("A227L1_OK claim_remaining_ms=%d extend_remaining_ms=%d", job.LeaseRemainingMillis, extended.LeaseRemainingMillis)
}
