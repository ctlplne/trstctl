// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/usage"
)

func TestNewAgentHeartbeatHonorsProviderQuotaWithoutStoppingExistingAgent(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	channelCtx, cancelChannel := context.WithCancel(context.Background())
	channelDone := make(chan struct{})
	go func() { defer close(channelDone); h.srv.serveAgentChannel(channelCtx, ln) }()
	t.Cleanup(func() { cancelChannel(); <-channelDone })

	const agentName = "quota-new-agent"
	a := enrollAgent(t, h, agentName, "agent.trstctl.local")
	creds, err := a.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(ln.Addr().String(), creds)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := transport.NewAgentClient(conn)
	checker := &cappedQuota{refuse: true}
	usage.SetQuotaChecker(checker)
	t.Cleanup(func() { usage.SetQuotaChecker(nil) })

	beat := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := client.Heartbeat(ctx, &transport.HeartbeatRequest{Version: "quota-test", Status: "active"})
		return err
	}
	before := servedEventCount(t, h, projections.EventAgentHeartbeat)
	if err := beat(); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("new agent at cap heartbeat = %v, want ResourceExhausted", err)
	}
	if checker.consults != 1 {
		t.Fatalf("new agent checked quota %d times, want 1", checker.consults)
	}
	if after := servedEventCount(t, h, projections.EventAgentHeartbeat); after != before {
		t.Fatalf("quota refused agent appended %d heartbeat events", after-before)
	}
	if _, err := h.store.GetAgent(context.Background(), h.tenant, agentRowID(h.tenant, agentName)); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("quota refused agent has a projected row: %v", err)
	}

	checker.refuse = false
	if err := beat(); err != nil {
		t.Fatalf("agent admitted under cap: %v", err)
	}
	checker.refuse = true
	if err := beat(); err != nil {
		t.Fatalf("existing agent heartbeat after lower cap: %v", err)
	}
	if checker.consults != 2 {
		t.Fatalf("existing agent rechecked creation quota: %d consultations, want 2", checker.consults)
	}
}
