// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The intent and completed-result files retain their own durability flushes.
// Creating their containing directory needs one parent flush per directory
// identity, rather than another parent flush for every signing operation.
func TestSignJournalDirectorySyncsOncePerIdentityAndRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	ks := NewKeyStore(dir, nil)
	calls := 0
	flush := func(path string) error { calls++; return syncDirectory(path) }
	ensure := func(want int) {
		t.Helper()
		if err := ks.ensureSignJournalDirectory(flush); err != nil {
			t.Fatal(err)
		}
		if calls != want {
			t.Fatalf("parent directory flushes=%d, want %d", calls, want)
		}
	}
	ensure(1)
	ensure(1)
	if err := os.Rename(ks.signJournalDir(), ks.signJournalDir()+".old"); err != nil {
		t.Fatal(err)
	}
	ensure(2)
	ensure(2)
	if err := os.Rename(dir, dir+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Preserve the journal inode while replacing only its parent.
	if err := os.Rename(filepath.Join(dir+".old", "sign-operations"), ks.signJournalDir()); err != nil {
		t.Fatal(err)
	}
	ensure(3)
	ensure(3)
	// A new signer cannot inherit an in-memory claim that its parent was synced.
	ks = NewKeyStore(dir, nil)
	ensure(4)
	ensure(4)
}

func TestSignJournalDirectoryRetriesFailedDurability(t *testing.T) {
	ks := NewKeyStore(t.TempDir(), nil)
	want := errors.New("injected directory sync failure")
	if err := ks.ensureSignJournalDirectory(func(string) error { return want }); !errors.Is(err, want) {
		t.Fatalf("directory sync failure lost: %v", err)
	}
	calls := 0
	flush := func(path string) error { calls++; return syncDirectory(path) }
	for i := 0; i < 2; i++ {
		if err := ks.ensureSignJournalDirectory(flush); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("successful retry flushes=%d, want 1", calls)
	}
}

func TestSignJournalDirectoryConcurrentCallsWaitForDurability(t *testing.T) {
	ks := NewKeyStore(t.TempDir(), nil)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	var calls atomic.Int32
	flush := func(path string) error {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return syncDirectory(path)
	}
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { first <- ks.ensureSignJournalDirectory(flush) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first caller did not enter directory sync")
	}
	go func() { second <- ks.ensureSignJournalDirectory(flush) }()
	select {
	case err := <-second:
		t.Errorf("concurrent caller did not share the pending initialization flush: %v", err)
		second <- err
	case <-time.After(100 * time.Millisecond):
	}
	unblock()
	for _, result := range []<-chan error{first, second} {
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("directory initialization did not finish")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("concurrent initialization flushed parent %d times, want 1", calls.Load())
	}
}

func TestSignJournalDirectoryReplacementDuringSyncRefusesThenRetries(t *testing.T) {
	ks := NewKeyStore(t.TempDir(), nil)
	err := ks.ensureSignJournalDirectory(func(path string) error {
		if err := os.Rename(ks.signJournalDir(), ks.signJournalDir()+".old"); err != nil {
			return err
		}
		if err := os.Mkdir(ks.signJournalDir(), 0o700); err != nil {
			return err
		}
		return syncDirectory(path)
	})
	if err == nil {
		t.Fatal("accepted a journal directory replaced during initialization")
	}
	calls := 0
	flush := func(path string) error { calls++; return syncDirectory(path) }
	for i := 0; i < 2; i++ {
		if err := ks.ensureSignJournalDirectory(flush); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("replacement retry flushes=%d, want 1", calls)
	}
}

func TestSignJournalDirectoryRefusesNonDirectory(t *testing.T) {
	ks := NewKeyStore(t.TempDir(), nil)
	if err := os.WriteFile(ks.signJournalDir(), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := ks.ensureSignJournalDirectory(func(string) error {
		t.Error("attempted to sync after failed directory creation")
		return nil
	})
	if err == nil {
		t.Fatal("accepted a file as the signing journal directory")
	}
}
