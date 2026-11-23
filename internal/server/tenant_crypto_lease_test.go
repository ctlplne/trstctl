// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/tenantseal"
)

type cr044Cipher struct{}

func (cr044Cipher) Seal(plaintext, _ []byte) ([]byte, error) {
	return append([]byte(nil), plaintext...), nil
}
func (cr044Cipher) Open(sealed, _ []byte) ([]byte, error) { return append([]byte(nil), sealed...), nil }

type cr044Access struct {
	calls int
	deny  string
}

func (a *cr044Access) WithTenant(_ context.Context, tenantID string, fn func(tenantseal.Cipher) error) error {
	a.calls++
	if tenantID == a.deny {
		return errors.New("tenant sealed")
	}
	return fn(cr044Cipher{})
}

func TestCR044BorrowedTenantCipherCannotOutliveItsLeaseOrCrossTenants(t *testing.T) {
	const tenantA, tenantB = "tenant-a", "tenant-b"
	access := &cr044Access{deny: tenantB}
	var borrowed context.Context
	err := withTenantCipher(context.Background(), access, nil, tenantA, func(ctx context.Context, _ tenantseal.Cipher) error {
		borrowed = ctx
		return withTenantCipher(ctx, access, nil, tenantB, func(context.Context, tenantseal.Cipher) error {
			t.Error("borrowed tenant A cipher opened sealed tenant B")
			return nil
		})
	})
	if err == nil {
		t.Fatal("cross-tenant nested access bypassed tenant B custody")
	}
	access.deny = tenantA
	if err := withTenantCipher(borrowed, access, nil, tenantA, func(context.Context, tenantseal.Cipher) error {
		t.Error("expired borrowed cipher reopened sealed tenant A")
		return nil
	}); err == nil {
		t.Fatal("borrowed cipher remained valid after its lease ended")
	}
	if access.calls != 3 {
		t.Fatalf("custody checks = %d, want outer A, nested B, and later A", access.calls)
	}
}
