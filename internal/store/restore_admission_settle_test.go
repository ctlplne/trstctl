// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/store"
)

// A worker may be canceled just after its SQL effect commits. Its nil callback
// result is definite completion evidence; the exact activity must settle even
// though the caller's request context is already canceled.
func TestCompletedRestoreActivitySettlesAfterCallerCancellation(t *testing.T) {
	s := newStore(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	const tenant = "49900000-0000-4000-8000-0000000000f4"
	const activity = "49900000-0000-4000-8000-0000000000f5"
	err := s.WithRestoreActivity(ctx, tenant, activity, "worker", "projection-tail", func(admitted context.Context) error {
		if err := s.UpsertTenant(admitted, store.Tenant{TenantID: tenant, Name: "settled", EventSeq: 1}); err != nil {
			return err
		}
		cancel()
		return nil
	})
	if err != nil {
		t.Fatalf("completed worker did not settle: %v", err)
	}
	var phase string
	if err := s.SystemPool().QueryRow(t.Context(), `SELECT phase FROM trstctl_recovery.restore_activity_tokens
		WHERE tenant_id=$1 AND operation_id=$2 AND lane='projection-tail'`, tenant, activity).Scan(&phase); err != nil {
		t.Fatal(err)
	}
	if phase != "terminal" {
		t.Fatalf("completed worker phase = %s, want terminal", phase)
	}
}

func TestAmbiguousRestoreActivityStaysUnresolvedAfterCancellation(t *testing.T) {
	s := newStore(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	const tenant = "49900000-0000-4000-8000-0000000000f6"
	const activity = "49900000-0000-4000-8000-0000000000f7"
	uncertain := errors.New("effect outcome unknown")
	err := s.WithRestoreActivity(ctx, tenant, activity, "effect", "external-call", func(context.Context) error {
		cancel()
		return uncertain
	})
	if !errors.Is(err, uncertain) {
		t.Fatalf("ambiguous effect error = %v, want original cause", err)
	}
	var phase string
	if err := s.SystemPool().QueryRow(t.Context(), `SELECT phase FROM trstctl_recovery.restore_activity_tokens
		WHERE tenant_id=$1 AND operation_id=$2 AND lane='external-call'`, tenant, activity).Scan(&phase); err != nil {
		t.Fatal(err)
	}
	if phase != "started" {
		t.Fatalf("ambiguous effect phase = %s, want started", phase)
	}
}
