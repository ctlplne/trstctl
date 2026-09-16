// SPDX-License-Identifier: LicenseRef-trstctl-EE

package kmip

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/tenancy"
)

func TestTenantServiceBlocksExistingKMIPKeyAndNewKey(t *testing.T) {
	s := New("customer-a", certAuth{}, &auditsink.Recorder{})
	defer s.Close()
	ctx := t.Context()
	good := []byte("good-client")
	id, err := s.Create(ctx, good, "AES")
	if err != nil {
		t.Fatal(err)
	}
	s.tenantServiceCheck = func(_ context.Context, tenant string) error {
		if tenant != "customer-a" {
			t.Fatalf("wrong tenant %s", tenant)
		}
		return tenancy.ErrServiceUnavailable
	}
	if key, err := s.Get(ctx, good, id); !errors.Is(err, tenancy.ErrServiceUnavailable) || len(key) != 0 {
		secret.Wipe(key)
		t.Fatalf("paused get = %v", err)
	}
	if _, err := s.Create(ctx, good, "AES"); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Fatalf("paused create = %v", err)
	}
	s.tenantServiceCheck = func(context.Context, string) error { return errors.New("authority unavailable") }
	if key, err := s.Get(ctx, good, id); err == nil || len(key) != 0 {
		secret.Wipe(key)
		t.Fatal("authority failure returned key")
	}
	s.tenantServiceCheck = nil
	key, err := s.Get(ctx, good, id)
	defer secret.Wipe(key)
	if err != nil || len(key) != 32 {
		t.Fatalf("resumed get = %d/%v", len(key), err)
	}
}
