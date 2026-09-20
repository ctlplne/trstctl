// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/observ"
)

type stubAgentChannelService struct{}

func (stubAgentChannelService) Heartbeat(context.Context, *transport.HeartbeatRequest) (*transport.HeartbeatResponse, error) {
	return &transport.HeartbeatResponse{TenantID: "tenant-a", NextHeartbeatSeconds: 30}, nil
}

func (stubAgentChannelService) Renew(context.Context, *transport.RenewRequest) (*transport.RenewResponse, error) {
	return &transport.RenewResponse{CertChainPEM: []byte("chain"), NotAfterUnix: 123}, nil
}

func (stubAgentChannelService) ReportInventory(context.Context, *transport.InventoryRequest) (*transport.InventoryResponse, error) {
	return &transport.InventoryResponse{TenantID: "tenant-a", RunID: "run-a", Recorded: 1}, nil
}

// A1 put the job RPCs behind the same fire door: a fleet all asking for work at
// once is the expected case, not the exceptional one.
func (stubAgentChannelService) ClaimJobs(context.Context, *transport.ClaimJobsRequest) (*transport.ClaimJobsResponse, error) {
	return &transport.ClaimJobsResponse{NextPollSeconds: 15}, nil
}

func (stubAgentChannelService) ReportJobResult(context.Context, *transport.ReportJobResultRequest) (*transport.ReportJobResultResponse, error) {
	return &transport.ReportJobResultResponse{Accepted: true}, nil
}

func (stubAgentChannelService) RedeemJobCredential(context.Context, *transport.RedeemJobCredentialRequest) (*transport.RedeemJobCredentialResponse, error) {
	return &transport.RedeemJobCredentialResponse{}, nil
}

func (stubAgentChannelService) SignJobCSR(context.Context, *transport.SignJobCSRRequest) (*transport.SignJobCSRResponse, error) {
	return &transport.SignJobCSRResponse{}, nil
}

func (stubAgentChannelService) FetchWorkloadSVID(context.Context, *transport.FetchWorkloadSVIDRequest) (*transport.FetchWorkloadSVIDResponse, error) {
	return &transport.FetchWorkloadSVIDResponse{}, nil
}

func TestAgentBulkheadShedsWithoutStarvingOtherSubsystems(t *testing.T) {
	set := bulkhead.NewSet(
		bulkhead.Config{Name: bulkhead.SubsystemAgent, Workers: 1, Queue: 0},
		bulkhead.Config{Name: bulkhead.SubsystemAPI, Workers: 1, Queue: 0},
		bulkhead.Config{Name: bulkhead.SubsystemProtocols, Workers: 1, Queue: 0},
		bulkhead.Config{Name: bulkhead.SubsystemOutbox, Workers: 1, Queue: 0},
	)
	release := make(chan struct{})
	occupied := make(chan struct{})
	if err := submitUntilAccepted(t, set.Pool(bulkhead.SubsystemAgent), func() {
		close(occupied)
		<-release
	}); err != nil {
		t.Fatalf("occupy agent pool: %v", err)
	}
	<-occupied
	defer func() {
		close(release)
		set.Close()
	}()

	svc, err := newBulkheadedAgentService(stubAgentChannelService{}, set.Pool(bulkhead.SubsystemAgent), nil)
	if err != nil {
		t.Fatalf("wrap agent service: %v", err)
	}
	if _, err := svc.Heartbeat(context.Background(), &transport.HeartbeatRequest{AgentID: "edge"}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("saturated heartbeat error = %v, want ResourceExhausted", err)
	}
	if _, err := svc.Renew(context.Background(), &transport.RenewRequest{CSRDER: []byte{0x30, 0x01}}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("saturated renew error = %v, want ResourceExhausted", err)
	}
	if _, err := svc.ReportInventory(context.Background(), &transport.InventoryRequest{Findings: []transport.InventoryFinding{{Kind: "secret", Ref: "ref"}}}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("saturated inventory error = %v, want ResourceExhausted", err)
	}

	for _, subsystem := range []string{bulkhead.SubsystemAPI, bulkhead.SubsystemProtocols, bulkhead.SubsystemOutbox} {
		done := make(chan struct{})
		if err := submitUntilAccepted(t, set.Pool(subsystem), func() { close(done) }); err != nil {
			t.Fatalf("%s pool should remain independent while agent is saturated: %v", subsystem, err)
		}
		<-done
	}
}

func submitUntilAccepted(t *testing.T, pool *bulkhead.Pool, task func()) error {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	var last error
	for time.Now().Before(deadline) {
		if err := pool.Submit(task); err != nil {
			last = err
			time.Sleep(time.Millisecond)
			continue
		}
		return nil
	}
	return last
}

func TestAgentBulkheadRejectsMissingPool(t *testing.T) {
	if _, err := newBulkheadedAgentService(stubAgentChannelService{}, nil, nil); err == nil {
		t.Fatal("agent channel accepted a missing agent bulkhead")
	}
	pools := bulkhead.Default()
	defer pools.Close()
	if pools.Pool(bulkhead.SubsystemAgent) == nil {
		t.Fatal("default bulkhead set does not include the agent subsystem")
	}
}

func TestAgentBulkheadRejectionMetricRecordsSaturation(t *testing.T) {
	set := bulkhead.NewSet(bulkhead.Config{Name: bulkhead.SubsystemAgent, Workers: 1, Queue: 0})
	defer set.Close()
	release := make(chan struct{})
	occupied := make(chan struct{})
	if err := submitUntilAccepted(t, set.Pool(bulkhead.SubsystemAgent), func() {
		close(occupied)
		<-release
	}); err != nil {
		t.Fatalf("occupy agent pool: %v", err)
	}
	<-occupied
	defer close(release)

	reg := observ.NewRegistry()
	metrics := newAgentChannelMetrics(reg)
	svc, err := newBulkheadedAgentService(stubAgentChannelService{}, set.Pool(bulkhead.SubsystemAgent), metrics)
	if err != nil {
		t.Fatalf("wrap agent service: %v", err)
	}
	if _, err := svc.Heartbeat(context.Background(), &transport.HeartbeatRequest{AgentID: "edge"}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("saturated heartbeat error = %v, want ResourceExhausted", err)
	}

	var prom strings.Builder
	if err := reg.WriteProm(&prom); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prom.String(), `trstctl_agent_bulkhead_rejections_total{method="heartbeat"} 1`) {
		t.Fatalf("agent bulkhead rejection metric missing:\n%s", prom.String())
	}
}
