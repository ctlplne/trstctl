// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"trstctl.com/trstctl/internal/agent/enroll"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/tenancy"
)

type heldRedeemedTenantToken struct {
	storeTokenStore
	entered chan struct{}
	release chan struct{}
}

func (s heldRedeemedTenantToken) Redeem(ctx context.Context, hash string) (enroll.RedeemedToken, error) {
	token, err := s.storeTokenStore.Redeem(ctx, hash)
	if err != nil {
		return token, err
	}
	close(s.entered)
	select {
	case <-s.release:
		return token, nil
	case <-ctx.Done():
		return enroll.RedeemedToken{}, ctx.Err()
	}
}

func offboardServedTestTenant(t *testing.T, h *servedHarness) {
	t.Helper()
	ctx := events.ContextWithActor(t.Context(), events.Actor{Subject: "owned-qa-offboard", Roles: []string{"admin"}})
	registration, err := orchestrator.ResolveLiveTenantRegistrationAuthority(ctx, h.log, h.store, h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenantServiceBarrier(ctx, h.tenant, func(work context.Context) error {
		_, err := h.srv.orch.OffboardTenant(work, orchestrator.TenantOffboardCommand{TenantID: h.tenant, RegistrationIdentity: registration.EventID})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.GetTenant(ctx, h.tenant); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("tenant was not erased: %v", err)
	}
}

func TestDeletedTenantCannotUseExistingAgentConnection(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel)
	registerServedTenant(t, h, "Agent deletion")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	channelCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); h.srv.serveAgentChannel(channelCtx, ln) }()
	t.Cleanup(func() { stop(); <-done })
	a := enrollAgent(t, h, "deleted-tenant-agent", "agent.trstctl.local")
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
	if _, err := client.Heartbeat(ctx, &transport.HeartbeatRequest{Status: "active"}); err != nil {
		t.Fatalf("active heartbeat failed: %v", err)
	}
	offboardServedTestTenant(t, h)
	if _, err := client.Heartbeat(ctx, &transport.HeartbeatRequest{Status: "active"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("deleted tenant heartbeat was not refused: %v", err)
	}
	if _, err := client.Renew(ctx, &transport.RenewRequest{CSRDER: newAgentCSR(t, "deleted-tenant-agent")}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("deleted tenant renewal was not refused: %v", err)
	}
	if _, err := client.ClaimJobs(ctx, &transport.ClaimJobsRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("deleted tenant claim was not refused: %v", err)
	}
}

func TestDeletedTenantCannotFinishRedeemedBootstrap(t *testing.T) {
	for _, recreate := range []bool{false, true} {
		name := "absent"
		if recreate {
			name = "re-registered"
		}
		t.Run(name, func(t *testing.T) {
			h := newServedHarness(t, config.Protocols{}, withAgentChannel)
			registerServedTenant(t, h, "Queued bootstrap deletion")
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			token, err := h.srv.agentEnroll.IssueBootstrapToken(ctx, h.tenant, "")
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Wipe(token)
			held := heldRedeemedTenantToken{storeTokenStore: storeTokenStore{st: h.store}, entered: make(chan struct{}), release: make(chan struct{})}
			var once sync.Once
			unblock := func() { once.Do(func() { close(held.release) }) }
			defer unblock()
			authority, err := enroll.NewAuthorityWithIssuer(agentCAIssuer{caSigner: h.srv.agentCASigner, caCertDER: h.srv.agentCACertDER}, held,
				enroll.WithTenantServiceWork(h.store.BeginTenantService), enroll.WithTenantServiceCheck(h.srv.tenantServiceCheck), enroll.WithClientCertificateBinding(agentCertificateBinding(h.store, h.log)))
			if err != nil {
				t.Fatal(err)
			}
			csr := newAgentCSR(t, "queued-deleted-agent")
			result := make(chan error, 1)
			go func() { _, err := authority.EnrollBootstrap(ctx, token, csr); result <- err }()
			joined := false
			defer func() {
				unblock()
				if !joined {
					<-result
				}
			}()
			select {
			case <-held.entered:
			case err := <-result:
				joined = true
				t.Fatalf("redemption was not reached: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			offboardServedTestTenant(t, h)
			if recreate {
				registerServedTenant(t, h, "Replacement registration")
				fresh, err := h.srv.agentEnroll.IssueBootstrapToken(ctx, h.tenant, "")
				if err != nil {
					t.Fatal(err)
				}
				defer secret.Wipe(fresh)
				if _, err := h.srv.agentEnroll.EnrollBootstrap(ctx, fresh, newAgentCSR(t, "fresh-tenant-agent")); err != nil {
					t.Fatalf("new tenant cannot enroll: %v", err)
				}
			}
			unblock()
			err = <-result
			joined = true
			if !errors.Is(err, tenancy.ErrServiceUnavailable) && !errors.Is(err, enroll.ErrBadToken) {
				t.Fatalf("redeemed token minted after tenant deletion: %v", err)
			}

		})
	}
}

func TestReregisteredTenantRejectsPreviousAgentCertificate(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel)
	registerServedTenant(t, h, "Original agent tenant")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	channelCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); h.srv.serveAgentChannel(channelCtx, ln) }()
	t.Cleanup(func() { stop(); <-done })
	a := enrollAgent(t, h, "deleted-tenant-agent", "agent.trstctl.local")
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
	if _, err := client.Heartbeat(ctx, &transport.HeartbeatRequest{Status: "active"}); err != nil {
		t.Fatalf("active heartbeat failed: %v", err)
	}
	offboardServedTestTenant(t, h)
	registerServedTenant(t, h, "Replacement agent tenant")
	fresh := enrollAgent(t, h, "fresh-tenant-agent", "agent.trstctl.local")
	heartbeatEnrolledAgent(t, h, fresh)
	if _, err := client.Heartbeat(ctx, &transport.HeartbeatRequest{Status: "active"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("replacement tenant accepted old heartbeat was not refused: %v", err)
	}
	if _, err := client.Renew(ctx, &transport.RenewRequest{CSRDER: newAgentCSR(t, "deleted-tenant-agent")}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("replacement tenant accepted old renewal was not refused: %v", err)
	}
	if _, err := client.ClaimJobs(ctx, &transport.ClaimJobsRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("replacement tenant accepted old claim was not refused: %v", err)
	}
}
