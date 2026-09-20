// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// These mirror minter_persist_order_test.go for the PRIMARY GenerateKey RPC
// (AUD-201 follow-up C1/V19): the commit that fixed GenerateSuccessorKey's
// publish-before-persist ordering — and wrote the comment condemning it — left
// the RPC itself on the old ordering, with a caller-chosen handle
// (req.RequestedId, always set by client.go), a resolvable window, and a
// compensating delete that cannot undo a signature already produced.

// TestGenerateKeyFailedPersistLeavesNoResolvableHandle: a key whose save
// failed must not remain resolvable by handle.
func TestGenerateKeyFailedPersistLeavesNoResolvableHandle(t *testing.T) {
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

	// Break the keystore AFTER construction so the failure lands on the SAVE
	// path (same trick as the successor test).
	if err := os.Remove(keysDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keysDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = srv.GenerateKey(context.Background(), &signerpb.GenerateKeyRequest{
		Algorithm:   signerpb.Algorithm_ALGORITHM_ECDSA_P256,
		RequestedId: "rpc-key-1",
	})
	if err == nil {
		t.Fatal("GenerateKey succeeded even though the key could not be persisted")
	} else if !strings.Contains(err.Error(), "persist key") {
		t.Errorf("error = %v, want it to name the persist failure", err)
	}

	srv.mu.Lock()
	_, resolvable := srv.keys["rpc-key-1"]
	srv.mu.Unlock()
	if resolvable {
		t.Error("a key whose save failed is still resolvable by handle; a concurrent Sign could use it and a restart would drop it")
	}
}

// TestGenerateKeyHandleNeverResolvesBeforeItIsPersisted probes the window a
// concurrent reader could exploit: the handle must never be visible at a
// moment when nothing is on disk for it.
func TestGenerateKeyHandleNeverResolvesBeforeItIsPersisted(t *testing.T) {
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
			_, resolvable := srv.keys["rpc-key-race"]
			srv.mu.Unlock()
			if resolvable {
				entries, _ := os.ReadDir(dir)
				if len(entries) == 0 {
					mu.Lock()
					orphaned++
					mu.Unlock()
				}
			}
		}
	}()

	if _, err := srv.GenerateKey(context.Background(), &signerpb.GenerateKeyRequest{
		Algorithm:   signerpb.Algorithm_ALGORITHM_ECDSA_P256,
		RequestedId: "rpc-key-race",
	}); err != nil {
		close(done)
		wg.Wait()
		t.Fatalf("GenerateKey: %v", err)
	}
	close(done)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if orphaned > 0 {
		t.Errorf("the handle resolved %d times while nothing was persisted; a concurrent caller "+
			"could sign with a key no restart would recover", orphaned)
	}

	srv.mu.Lock()
	_, resolvable := srv.keys["rpc-key-race"]
	srv.mu.Unlock()
	if !resolvable {
		t.Error("the minted key is not resolvable after a successful GenerateKey")
	}
}
