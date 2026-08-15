// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

// TestConcurrentCreatesNeverLoseAnAcknowledgedKey is the regression guard for
// AUD-201 follow-up B1/V3. Every checkpoint used to write one FIXED temp path
// with no store-level serialisation, and checkpoints run outside Service.mu, so
// two concurrent CreateKey checkpoints could interleave their WriteFile/Rename
// pairs: the staler snapshot renames last and the sealed file loses a key whose
// creation already returned success — or a truncating write lands mid-rename
// and commits a torn blob that Load refuses, blocking the next startup. Either
// way a key the caller was told exists is gone after restart, and every
// ciphertext under it with it.
func TestConcurrentCreatesNeverLoseAnAcknowledgedKey(t *testing.T) {
	ctx := context.Background()
	const rounds = 4
	const workers = 24
	for round := 0; round < rounds; round++ {
		dir := t.TempDir()
		wrapper := testWrapper(t)
		svc := &Service{audit: auditsink.Nop{}}
		store := NewStore(dir, wrapper)
		if store == nil {
			t.Fatal("NewStore returned nil for a configured dir and wrapper")
		}
		svc.SetPersist(func() error { return store.Save(svc) })

		names := make([]string, workers)
		errs := make([]error, workers)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			names[i] = fmt.Sprintf("key-%02d", i)
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				_, errs[i] = svc.CreateKey(ctx, "t1", names[i], KindAEAD)
			}(i)
		}
		close(start)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d: create %s: %v", round, names[i], err)
			}
		}

		// Restart: every ACKNOWLEDGED key must be present in the sealed file.
		reloaded := &Service{audit: auditsink.Nop{}}
		if err := NewStore(dir, wrapper).Load(reloaded); err != nil {
			t.Fatalf("round %d: reload keyring: %v (a concurrent Save committed a torn or truncated file)", round, err)
		}
		for _, name := range names {
			if _, err := reloaded.Encrypt(ctx, "t1", name, []byte("x"), nil); err != nil {
				t.Fatalf("round %d: key %s was acknowledged but is gone after reload: %v", round, name, err)
			}
		}
	}
}
