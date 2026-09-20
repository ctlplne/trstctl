// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/tenancy"
)

func TestTenantServiceServedRESTAndExistingAgentConnection(t *testing.T) {
	var paused atomic.Bool
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, nil, func(d *Deps) {
		d.TenantServiceCheck = func(context.Context, string) error {
			if paused.Load() {
				return tenancy.ErrServiceUnavailable
			}
			return nil
		}
	})
	token := seedScopedToken(t, h.store, h.tenant, "owners:read")
	ctx := t.Context()
	if code, _ := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/owners", token, nil); code != http.StatusOK {
		t.Fatalf("active REST = %d", code)
	}
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{Status: "active"}); err != nil {
		t.Fatal(err)
	}
	paused.Store(true)
	if code, _ := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/owners", token, nil); code != http.StatusForbidden {
		t.Fatalf("paused REST = %d", code)
	}
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{Status: "active"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("paused established gRPC = %v", err)
	}
	if _, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("paused claim = %v", err)
	}
	paused.Store(false)
	if code, _ := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/owners", token, nil); code != http.StatusOK {
		t.Fatalf("resumed REST = %d", code)
	}
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{Status: "active"}); err != nil {
		t.Fatalf("resumed established gRPC = %v", err)
	}
}
