// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

func TestTenantServiceAgentRPCWorkExcludesLifecycleChanges(t *testing.T) {
	type heldRPC struct {
		entered, release chan struct{}
		once             sync.Once
	}
	lanes := []string{"heartbeat", "renew", "inventory", "claim"}
	held := map[string]*heldRPC{}
	for _, lane := range lanes {
		held[lane] = &heldRPC{entered: make(chan struct{}), release: make(chan struct{})}
	}
	h := newServedHarness(t, config.Protocols{}, withAgentChannel, func(d *Deps) {
		d.TenantServiceCheck = func(ctx context.Context, _ string) error {
			md, _ := metadata.FromIncomingContext(ctx)
			values := md.Get("x-qa-hold-tenant-work")
			if len(values) != 1 {
				return nil
			}
			pause := held[values[0]]
			if pause == nil {
				return nil
			}
			pause.once.Do(func() { close(pause.entered) })
			select {
			case <-pause.release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	channelCtx, stopChannel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); h.srv.serveAgentChannel(channelCtx, ln) }()
	t.Cleanup(func() { stopChannel(); <-done })
	a := enrollAgent(t, h, "tenant-work-agent", "agent.trstctl.local")
	credentials, err := a.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(ln.Addr().String(), credentials)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := transport.NewAgentClient(conn)
	csr := newAgentCSR(t, "tenant-work-agent")
	for _, lane := range lanes {
		t.Run(lane, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			ctx = metadata.AppendToOutgoingContext(ctx, "x-qa-hold-tenant-work", lane)
			pause := held[lane]
			var once sync.Once
			unblock := func() { once.Do(func() { close(pause.release) }) }
			defer unblock()
			finished := make(chan error, 1)
			go func() {
				var err error
				switch lane {
				case "heartbeat":
					var response *transport.HeartbeatResponse
					response, err = client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: "ignored-untrusted-id", Version: "test", Status: "active"})
					if err == nil && response.TenantID != h.tenant {
						err = errors.New("heartbeat lost authenticated tenant")
					}
				case "renew":
					var response *transport.RenewResponse
					response, err = client.Renew(ctx, &transport.RenewRequest{CSRDER: csr})
					if err == nil && len(response.CertChainPEM) == 0 {
						err = errors.New("renewal returned no certificate")
					}
				case "inventory":
					var response *transport.InventoryResponse
					response, err = client.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: "filesystem", Findings: []transport.InventoryFinding{{Kind: "x509_certificate", Ref: "/etc/ssl/tenant-work.pem", Provenance: "filesystem:/etc/ssl/tenant-work.pem", Fingerprint: "sha256:tenant-work", Metadata: map[string]string{"host": "tenant-work-agent"}}}})
					if err == nil && (response.Recorded != 1 || response.Rejected != 0 || response.TenantID != h.tenant) {
						err = errors.New("inventory did not record exact tenant observation")
					}
				case "claim":
					_, err = client.ClaimJobs(ctx, &transport.ClaimJobsRequest{})
				}
				finished <- err
			}()
			joined := false
			defer func() {
				unblock()
				if !joined {
					<-finished
				}
			}()
			select {
			case <-pause.entered:
			case err := <-finished:
				joined = true
				t.Fatalf("RPC did not reach tenant admission: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			called := false
			barrierErr := h.store.WithTenantServiceBarrier(ctx, h.tenant, func(context.Context) error { called = true; return nil })
			unblock()
			result := <-finished
			joined = true
			if result != nil {
				t.Fatalf("real mTLS RPC failed after release: %v", result)
			}
			if called || !errors.Is(barrierErr, store.ErrTenantServiceBusy) {
				t.Fatalf("lifecycle crossed active agent RPC: called=%v err=%v", called, barrierErr)
			}
			if err := h.store.WithTenantServiceBarrier(ctx, h.tenant, func(context.Context) error { return nil }); err != nil {
				t.Fatalf("completed RPC retained service lock: %v", err)
			}
		})
	}
}
