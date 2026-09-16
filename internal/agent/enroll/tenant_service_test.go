// SPDX-License-Identifier: MPL-2.0

package enroll_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/agent/enroll"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/tenancy"
)

func TestTenantServiceStopsBootstrapAndExistingAgentRenewal(t *testing.T) {
	active := true
	a, err := enroll.NewAuthority("tenant-service-test", enroll.NewMemoryTokenStore(), enroll.WithTenantServiceCheck(func(_ context.Context, tenant string) error {
		if tenant != tenantA {
			t.Fatalf("wrong tenant %q", tenant)
		}
		if !active {
			return tenancy.ErrServiceUnavailable
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	csr := newCSR(t, "existing-agent")
	token, err := a.IssueBootstrapToken(ctx, tenantA, "")
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(token)
	chain, err := a.EnrollBootstrap(ctx, token, csr)
	if err != nil {
		t.Fatal(err)
	}
	peer := [][]byte{leafDER(t, chain)}
	unused, err := a.IssueBootstrapToken(ctx, tenantA, "")
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(unused)
	active = false
	if _, err := a.EnrollBootstrap(ctx, unused, csr); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Fatalf("paused bootstrap = %v", err)
	}
	if _, err := a.EnrollRenewal(ctx, peer, csr); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Fatalf("paused renewal = %v", err)
	}
	active = true
	if _, err := a.EnrollRenewal(ctx, peer, csr); err != nil {
		t.Fatalf("resumed renewal = %v", err)
	}
	if _, err := a.EnrollBootstrap(ctx, unused, csr); !errors.Is(err, enroll.ErrBadToken) {
		t.Fatalf("refused bootstrap token unexpectedly reusable = %v", err)
	}
}
