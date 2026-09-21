// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
)

// inPackageTestKEK mirrors keystore_test.go's helper, which lives in the external
// signing_test package; these tests are in-package because they read srv.mu and
// srv.keys directly to observe the publish/persist ordering.
func inPackageTestKEK(t *testing.T) *seal.LocalKEK {
	t.Helper()
	raw, err := seal.GenerateKEK()
	if err != nil {
		t.Fatalf("GenerateKEK: %v", err)
	}
	k, err := seal.NewLocalKEK(raw)
	if err != nil {
		t.Fatalf("NewLocalKEK: %v", err)
	}
	t.Cleanup(k.Destroy)
	return k
}

// TestFailedPersistLeavesNoResolvableHandle is the regression guard for the
// publish-before-persist window.
//
// The key used to be inserted into s.keys, the lock released, and only then
// saved. Between those the handle resolved to a key no restart would recover, and
// a concurrent caller could sign with it before the save returned — something the
// compensating delete-and-destroy on failure cannot undo once a signature exists.
func TestFailedPersistLeavesNoResolvableHandle(t *testing.T) {
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	srv, err := NewPersistentServer(NewKeyStore(keysDir, inPackageTestKEK(t)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Shutdown)

	// Now replace the keystore directory with a regular file, so Save's
	// os.MkdirAll fails. Breaking it after construction rather than before keeps
	// the failure on the SAVE path, which is what this test is about — and avoids
	// a permission trick that a root-run CI would defeat.
	if err := os.Remove(keysDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := srv.GenerateSuccessorKey("successor-1", crypto.ECDSAP256); err == nil {
		t.Fatal("minting succeeded even though the key could not be persisted")
	} else if !strings.Contains(err.Error(), "persist successor key") {
		t.Errorf("error = %v, want it to name the persist failure", err)
	}

	srv.mu.Lock()
	_, resolvable := srv.keys["successor-1"]
	srv.mu.Unlock()
	if resolvable {
		t.Error("a key whose save failed is still resolvable by handle")
	}
}

// TestHandleNeverResolvesBeforeItIsPersisted probes the window directly: a
// concurrent reader taking the same mutex must never observe the handle at a
// moment when it is not yet on disk.
//
// With the save inside the critical section a reader cannot interleave at all.
// With the old ordering the handle was published, the lock dropped, and the save
// ran afterward — so a reader could see a handle with no file behind it.
func TestHandleNeverResolvesBeforeItIsPersisted(t *testing.T) {
	dir := t.TempDir()
	srv, err := NewPersistentServer(NewKeyStore(dir, inPackageTestKEK(t)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Shutdown)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		orphaned int
		done     = make(chan struct{})
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			srv.mu.Lock()
			_, resolvable := srv.keys["successor-race"]
			srv.mu.Unlock()
			if resolvable {
				// Visible by handle — something must be on disk for it.
				entries, _ := os.ReadDir(dir)
				if len(entries) == 0 {
					mu.Lock()
					orphaned++
					mu.Unlock()
				}
			}
		}
	}()

	if _, err := srv.GenerateSuccessorKey("successor-race", crypto.ECDSAP256); err != nil {
		close(done)
		wg.Wait()
		t.Fatalf("GenerateSuccessorKey: %v", err)
	}
	close(done)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if orphaned > 0 {
		t.Errorf("the handle resolved %d times while nothing was persisted; a concurrent caller "+
			"could sign with a key no restart would recover", orphaned)
	}

	// And the happy path must actually work.
	srv.mu.Lock()
	_, resolvable := srv.keys["successor-race"]
	srv.mu.Unlock()
	if !resolvable {
		t.Error("a successfully persisted key is not resolvable")
	}
}
