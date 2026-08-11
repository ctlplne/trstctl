// SPDX-License-Identifier: MPL-2.0

package relay_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
)

// AUD32/G1: a host rollback is possible only if the host agent, and nobody
// else, retained the predecessor bundle. The store survives a process restart,
// keeps only two generations, and encrypts both the certificate and key at
// rest. The control plane never appears in this test because it never receives
// either bundle.
func TestHostRollbackStorePersistsEncryptedBoundedPredecessorAcrossRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "host-rollbacks")
	st, err := relay.NewHostRollbackStore(root, "tenant-a")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	firstCert, firstKey := []byte("first-certificate-canary"), []byte("first-private-key-canary")
	secondCert, secondKey := []byte("second-certificate-canary"), []byte("second-private-key-canary")
	if err := st.RecordDeploy("nginx", "target-a", "sha256:first", firstCert, firstKey); err != nil {
		t.Fatalf("record first: %v", err)
	}
	if err := st.RecordDeploy("nginx", "target-a", "sha256:second", secondCert, secondKey); err != nil {
		t.Fatalf("record second: %v", err)
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 { // one sealing key and one bounded target ledger
		t.Fatalf("state files = %d, want sealing key + one target ledger", len(entries))
	}
	for _, entry := range entries {
		raw, readErr := os.ReadFile(filepath.Join(root, entry.Name())) // #nosec G304 -- test-owned temporary directory (CWE-22)
		if readErr != nil {
			t.Fatal(readErr)
		}
		for _, canary := range [][]byte{firstCert, firstKey, secondCert, secondKey} {
			if bytes.Contains(raw, canary) {
				t.Fatalf("%s contains plaintext predecessor material", entry.Name())
			}
		}
	}

	// A new object models a new OS process: no in-memory predecessor survives.
	otherTenant, err := relay.NewHostRollbackStore(root, "tenant-b")
	if err != nil {
		t.Fatalf("open same machine root for another enrolled tenant: %v", err)
	}
	if err := otherTenant.Restore("nginx", "target-a", "sha256:first", func([]byte, []byte) (bool, error) {
		return true, nil
	}); !errors.Is(err, relay.ErrHostRollbackPredecessorMissing) {
		t.Fatalf("other tenant reached tenant-a predecessor: %v", err)
	}

	restarted, err := relay.NewHostRollbackStore(root, "tenant-a")
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	var restored bool
	err = restarted.Restore("nginx", "target-a", "sha256:first", func(certPEM, keyPEM []byte) (bool, error) {
		restored = bytes.Equal(certPEM, firstCert) && bytes.Equal(keyPEM, firstKey)
		return true, nil
	})
	if err != nil || !restored {
		t.Fatalf("restore predecessor after restart: restored=%v err=%v", restored, err)
	}

	// A third deploy rotates one slot. The generation older than the currently
	// active predecessor is gone, rather than growing an agent-side key archive.
	if err := restarted.RecordDeploy("nginx", "target-a", "sha256:third", []byte("third-cert"), []byte("third-key")); err != nil {
		t.Fatalf("record third: %v", err)
	}
	if err := restarted.Restore("nginx", "target-a", "sha256:second", func([]byte, []byte) (bool, error) {
		return true, nil
	}); !errors.Is(err, relay.ErrHostRollbackPredecessorMissing) {
		t.Fatalf("restore evicted generation err = %v, want missing predecessor", err)
	}
}

// One process can receive a redelivery while another poll goroutine is still
// restoring the same listener. The second callback must not begin until the
// first has finished; the database lane supplies the same exclusion across
// processes and agents.
func TestHostRollbackStoreSerializesOneTarget(t *testing.T) {
	st, err := relay.NewHostRollbackStore(filepath.Join(t.TempDir(), "state"), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordDeploy("nginx", "target-a", "first", []byte("cert-1"), []byte("key-1")); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordDeploy("nginx", "target-a", "second", []byte("cert-2"), []byte("key-2")); err != nil {
		t.Fatal(err)
	}

	entered, release := make(chan struct{}), make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- st.Restore("nginx", "target-a", "first", func([]byte, []byte) (bool, error) {
			close(entered)
			<-release
			return false, errors.New("test stop")
		})
	}()
	<-entered
	var secondEntered atomic.Bool
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- st.Restore("nginx", "target-a", "first", func([]byte, []byte) (bool, error) {
			secondEntered.Store(true)
			return false, nil
		})
	}()
	time.Sleep(25 * time.Millisecond)
	if secondEntered.Load() {
		t.Fatal("two restores for one target executed concurrently")
	}
	close(release)
	if err := <-firstDone; err == nil {
		t.Fatal("first restore unexpectedly succeeded")
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second restore: %v", err)
	}
}

// Generated parity in the small: the platform catalog and the agent executor
// must agree on every host family. A static four-family appliance list cannot
// silently remain the advertised rollback surface.
func TestEveryHostConnectorAdvertisesAgentLocalRollback(t *testing.T) {
	want := relay.HostConnectorKinds()
	got := connector.HostRollbackCapableConnectors()
	if len(got) != len(want) {
		t.Fatalf("host rollback census = %v, host executors = %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("host rollback census = %v, host executors = %v", got, want)
		}
	}
}
