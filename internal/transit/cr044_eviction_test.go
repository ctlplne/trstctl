// SPDX-License-Identifier: BUSL-1.1

package transit_test

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/transit"
)

type countingTenantSealer struct {
	*kekSealer
	mu    sync.Mutex
	opens int
}

func (c *countingTenantSealer) OpenTenantKeyring(ctx context.Context, tenantID string, sealed, aad []byte) ([]byte, error) {
	c.mu.Lock()
	c.opens++
	c.mu.Unlock()
	return c.kekSealer.OpenTenantKeyring(ctx, tenantID, sealed, aad)
}

func (c *countingTenantSealer) openCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.opens
}

// Every completed operation releases its plaintext keyring. An idle replica
// therefore has nothing to retain after another replica seals the tenant.
func TestCR044SharedReplicaReopensAfterEveryOperation(t *testing.T) {
	ctx := context.Background()
	store := newMemKeyringStore()
	sealer := &countingTenantSealer{kekSealer: newKEKSealer(t)}
	svc := sharedReplica(t, store, sealer)
	if _, err := svc.CreateKey(ctx, tenantA, "orders", transit.KindAEAD); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		before := sealer.openCount()
		if _, err := svc.Encrypt(ctx, tenantA, "orders", []byte("message"), nil); err != nil {
			t.Fatal(err)
		}
		if after := sealer.openCount(); after != before+1 {
			t.Fatalf("operation %d reused an idle plaintext ring: open count %d -> %d", i, before, after)
		}
	}
}

func TestCR044ConcurrentOperationsDoNotWipeAnActiveKeyring(t *testing.T) {
	ctx := context.Background()
	svc := sharedReplica(t, newMemKeyringStore(), newKEKSealer(t))
	if _, err := svc.CreateKey(ctx, tenantA, "orders", transit.KindAEAD); err != nil {
		t.Fatal(err)
	}
	const workers, rounds = 8, 30
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				ciphertext, err := svc.Encrypt(ctx, tenantA, "orders", []byte("concurrent"), nil)
				if err != nil {
					errs <- fmt.Errorf("encrypt: %w", err)
					return
				}
				plaintext, err := svc.Decrypt(ctx, tenantA, "orders", ciphertext, nil)
				matches := bytes.Equal(plaintext, []byte("concurrent"))
				secret.Wipe(plaintext)
				if err != nil || !matches {
					errs <- fmt.Errorf("decrypt: plaintext mismatch, err=%v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
