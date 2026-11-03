// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/store"
)

// The two AD CS relay kinds used to share a case and reach their handlers
// through a hop that named the revocation and sent anything else to the CA
// database read, and ingestExecutedReport accepted any kind it did not name:
// a kind added to the allowlist without an ingest step would have closed its
// job with the result unrecorded.
func TestIngestExecutedReportNamesEveryClaimableKind(t *testing.T) {
	a := &agentService{recordMigrationResult: func(context.Context, string, string, string, string, int, []byte, string, string, string) (bool, error) {
		return false, nil
	}}
	info := mtls.PeerCertInfo{TenantID: "11111111-1111-1111-1111-111111111111", CommonName: "relay-a"}
	ingest := func(kind, outcome string) (err error) {
		defer func() {
			if recover() != nil {
				err = errors.New("reached a handler that needs dependencies this bare service lacks")
			}
		}()
		return a.ingestExecutedReport(context.Background(), info, "agent-a",
			store.AgentJobResultClaim{Destination: kind, Payload: []byte(`{}`)},
			&transport.ReportJobResultRequest{Outcome: outcome, Detail: "{}"})
	}
	for kind := range agentJobKindAllowlist {
		if err := ingest(kind, transport.JobOutcomeExecuted); errors.Is(err, errUnknownAgentJobKind) {
			t.Errorf("claimable kind %q has no case in ingestExecutedReport", kind)
		}
	}
	if err := ingest("relay.unlisted", transport.JobOutcomeExecuted); !errors.Is(err, errUnknownAgentJobKind) {
		t.Errorf("an unlisted kind: %v; want it refused, not accepted", err)
	}
	if err := ingest(relay.KindADCSDatabase, transport.JobOutcomeExecuted); err == nil || !strings.Contains(err.Error(), "CA database result receiver is not configured") {
		t.Errorf("the CA database read reached %v, not its own receiver", err)
	}
	if err := ingest(relay.KindADCSRevoke, transport.JobOutcomeVerified); err == nil || !strings.Contains(err.Error(), "AD CS revocation result needs a terminal executed report") {
		t.Errorf("the AD CS revocation reached %v, not its own check", err)
	}
	assertOwnCases(t, "agent_jobs.go", "ingestExecutedReport", "claim.Destination", []ownCase{
		{"KindADCSDatabase", "a.recordADCSDatabase"},
		{"KindADCSRevoke", "validateADCSRevokeResult"},
	})
}
