// SPDX-License-Identifier: LicenseRef-trstctl-EE

package managedkeys

import (
	"context"
	"errors"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/store"
)

// TestDurableWaitKeepsTheReceiptWhenAReadSpendsItsBudgetA261O1 is A261-O1:
// the command is already in the durable outbox when the wait runs. When a
// read fails because the wait's own budget ran out, the caller gets the
// exact pollable operation, as the wait's timer already gives it. That holds
// whether the driver reports the expiry as cancellation, or the completed
// key's read crosses the budget. A read that fails before the budget runs
// out, and the caller's own cancellation, stay failures.
func TestDurableWaitKeepsTheReceiptWhenAReadSpendsItsBudgetA261O1(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	const operation = "managedkey:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	completed := store.ManagedKeyOperation{Status: "completed", Provider: "gcp-kms", ResultKeyID: "public-key-id"}
	for _, stage := range []string{"operation read reports cancellation", "completed key read"} {
		t.Run(stage, func(t *testing.T) {
			svc := &durableService{waitDuration: 5 * time.Millisecond}
			svc.loadOperation = func(ctx context.Context, _, _ string) (store.ManagedKeyOperation, error) {
				if stage == "operation read reports cancellation" {
					<-ctx.Done()
					return store.ManagedKeyOperation{}, context.Canceled
				}
				return completed, nil
			}
			svc.loadKey = func(ctx context.Context, _, _, _ string) (store.ManagedKey, error) {
				<-ctx.Done()
				return store.ManagedKey{}, ctx.Err()
			}
			_, err := svc.wait(context.Background(), tenant, operation)
			var pending *api.ManagedKeyOperationPendingError
			if !errors.As(err, &pending) || pending.OperationID != operation {
				t.Fatalf("the wait's own budget spent in the %s returned %v; want the exact pollable operation", stage, err)
			}
		})
	}
	for _, stage := range []string{"operation", "key"} {
		t.Run("a failure before the budget runs out in the "+stage+" read", func(t *testing.T) {
			failure := errors.New("database read failed before the wait's budget ran out")
			svc := &durableService{waitDuration: time.Second}
			svc.loadOperation = func(context.Context, string, string) (store.ManagedKeyOperation, error) {
				if stage == "operation" {
					return store.ManagedKeyOperation{}, failure
				}
				return completed, nil
			}
			svc.loadKey = func(context.Context, string, string, string) (store.ManagedKey, error) {
				return store.ManagedKey{}, failure
			}
			_, err := svc.wait(context.Background(), tenant, operation)
			var pending *api.ManagedKeyOperationPendingError
			if !errors.Is(err, failure) || errors.As(err, &pending) {
				t.Fatalf("a real %s read failure became a receipt: %v", stage, err)
			}
		})
	}
	t.Run("the caller's cancellation is not a receipt", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		svc := &durableService{waitDuration: time.Second, loadOperation: func(context.Context, string, string) (store.ManagedKeyOperation, error) {
			cancel()
			return store.ManagedKeyOperation{}, context.Canceled
		}}
		_, err := svc.wait(ctx, tenant, operation)
		var pending *api.ManagedKeyOperationPendingError
		if !errors.Is(err, context.Canceled) || errors.As(err, &pending) {
			t.Fatalf("the caller's cancellation became a receipt: %v", err)
		}
	})
}
