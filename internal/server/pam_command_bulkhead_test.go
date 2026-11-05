// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/bulkhead"
)

type blockedCommandService struct {
	stubAgentChannelService
	entered, release chan struct{}
}

func (s blockedCommandService) EvaluateGatewayAction(ctx context.Context, _ *transport.EvaluateGatewayActionRequest) (*transport.EvaluateGatewayActionResponse, error) {
	close(s.entered)
	select {
	case <-s.release:
		return &transport.EvaluateGatewayActionResponse{}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func TestGatewayCommandBulkheadShedsAndDrainsWithoutHoldingHeartbeatA262(t *testing.T) {
	set := bulkhead.NewSet(bulkhead.Config{Name: bulkhead.SubsystemAgent, Workers: 1, Queue: 0}, bulkhead.Config{Name: bulkhead.SubsystemGatewayCommands, Workers: 1, Queue: 0})
	probe := blockedCommandService{entered: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(probe.release) }) }
	t.Cleanup(func() { release(); set.Close() })
	service, err := newBulkheadedAgentService(probe, set.Pool(bulkhead.SubsystemAgent), nil, set.Pool(bulkhead.SubsystemGatewayCommands))
	if err != nil {
		t.Fatal(err)
	}
	command := service.(transport.AgentGatewayCommandServiceServer)
	done := make(chan error, 1)
	go func() {
		_, err := command.EvaluateGatewayAction(context.Background(), &transport.EvaluateGatewayActionRequest{})
		done <- err
	}()
	select {
	case <-probe.entered:
	case <-time.After(time.Second):
		t.Fatal("command worker did not start")
	}
	if _, err := command.EvaluateGatewayAction(context.Background(), &transport.EvaluateGatewayActionRequest{}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("full command pool did not reject immediately: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := service.Heartbeat(ctx, &transport.HeartbeatRequest{}); err != nil {
		t.Fatalf("command pressure starved heartbeat: %v", err)
	}
	closed := make(chan struct{})
	go func() { set.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("shutdown did not drain its live command worker")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("released command did not finish")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("command owner did not finish draining")
	}
	if _, err := command.EvaluateGatewayAction(ctx, &transport.EvaluateGatewayActionRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("closed command pool accepted work or lost structured closure: %v", err)
	}
}
