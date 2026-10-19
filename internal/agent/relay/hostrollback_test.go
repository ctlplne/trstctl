// SPDX-License-Identifier: BUSL-1.1

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

func TestHostRollbackStorePinsExactUnmanagedPredecessorAcrossRenewal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "host-rollbacks")
	st, err := relay.NewHostRollbackStore(root, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	oldCert, oldKey := []byte("unmanaged-rsa-cert"), []byte("unmanaged-rsa-key")
	if err := st.PinPQCPredecessor("apache", "target-a", "run-a", "sha256:old", oldCert, oldKey); err != nil {
		t.Fatal(err)
	}
	if err := st.PinPQCPredecessor("apache", "target-a", "run-a", "old", oldCert, oldKey); err != nil {
		t.Fatalf("idempotent adoption: %v", err)
	}
	for _, changed := range []struct {
		fp        string
		cert, key []byte
	}{
		{"other", oldCert, oldKey}, {"old", []byte("other-cert"), oldKey}, {"old", oldCert, []byte("other-key")},
	} {
		if err := st.PinPQCPredecessor("apache", "target-a", "run-a", changed.fp, changed.cert, changed.key); !errors.Is(err, relay.ErrHostRollbackStateMismatch) {
			t.Fatalf("changed predecessor accepted: %v", err)
		}
	}
	if err := st.PinPQCPredecessor("apache", "target-a", "run-b", "old", oldCert, oldKey); !errors.Is(err, relay.ErrHostRollbackStateMismatch) {
		t.Fatalf("different run displaced unresolved predecessor: %v", err)
	}
	restarted, err := relay.NewHostRollbackStore(root, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.RecordDeploy("apache", "target-a", "new", []byte("mldsa-cert"), []byte("mldsa-key")); err != nil {
		t.Fatal(err)
	}
	if err := restarted.RecordDeploy("apache", "target-a", "renewed", []byte("renewed-cert"), []byte("renewed-key")); err != nil {
		t.Fatal(err)
	}
	if err := restarted.RestorePQC("apache", "target-a", "run-a", "old", func(cert, key []byte) (bool, error) {
		if !bytes.Equal(cert, oldCert) || !bytes.Equal(key, oldKey) {
			t.Fatal("rollback lost the original predecessor after renewal")
		}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := restarted.RestorePQC("apache", "target-a", "run-a", "old", func([]byte, []byte) (bool, error) {
		return true, nil
	}); err != nil {
		t.Fatalf("restore after a lost signed report must remain retryable: %v", err)
	}
	if err := restarted.FinalizePQCRestore("apache", "target-a", "run-a", "old"); err != nil {
		t.Fatal(err)
	}
	if err := restarted.RestorePQC("apache", "target-a", "run-a", "old", func([]byte, []byte) (bool, error) {
		return true, nil
	}); !errors.Is(err, relay.ErrHostRollbackPredecessorMissing) {
		t.Fatalf("committed rollback left pinned key behind: %v", err)
	}
}

func TestHostRollbackStorePinsReprotectPredecessorAcrossRestartAndRenewal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "host-rollbacks")
	st, err := relay.NewHostRollbackStore(root, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	oldCert, oldKey := []byte("reprotect-original-cert"), []byte("reprotect-original-key")
	if err := st.PinReprotectPredecessor("apache", "target-a", "job-a", "sha256:old", oldCert, oldKey); err != nil {
		t.Fatal(err)
	}
	if err := st.PinReprotectPredecessor("apache", "target-a", "job-a", "old", oldCert, oldKey); err != nil {
		t.Fatalf("same job redelivery: %v", err)
	}
	for _, changed := range []struct {
		job, fp   string
		cert, key []byte
	}{
		{"job-b", "old", oldCert, oldKey},
		{"job-a", "different", oldCert, oldKey},
		{"job-a", "old", []byte("different-cert"), oldKey},
		{"job-a", "old", oldCert, []byte("different-key")},
	} {
		if err := st.PinReprotectPredecessor("apache", "target-a", changed.job, changed.fp, changed.cert, changed.key); !errors.Is(err, relay.ErrHostRollbackStateMismatch) {
			t.Fatalf("changed predecessor accepted: %v", err)
		}
	}
	if err := st.PinPQCPredecessor("apache", "target-a", "run-a", "old", oldCert, oldKey); !errors.Is(err, relay.ErrHostRollbackStateMismatch) {
		t.Fatalf("concurrent PQC migration accepted: %v", err)
	}
	if err := st.UseReprotectPredecessor("apache", "target-a", "job-b", "old", func([]byte, []byte) error {
		t.Fatal("wrong job accessed private predecessor")
		return nil
	}); !errors.Is(err, relay.ErrHostRollbackPredecessorMissing) {
		t.Fatalf("wrong job predecessor read: %v", err)
	}
	for _, entry := range []string{"reprotect-original-cert", "reprotect-original-key"} {
		files, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			raw, err := os.ReadFile(filepath.Join(root, file.Name())) // #nosec G304 -- test-owned state root (CWE-22)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(raw, []byte(entry)) {
				t.Fatalf("host state stored plaintext %s", entry)
			}
		}
	}
	restarted, err := relay.NewHostRollbackStore(root, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.UseReprotectPredecessor("apache", "target-a", "job-a", "old", func(cert, key []byte) error {
		if !bytes.Equal(cert, oldCert) || !bytes.Equal(key, oldKey) {
			t.Fatal("reopened predecessor differs from installed material")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := restarted.RecordDeploy("apache", "target-a", "new", []byte("new-cert"), oldKey); err != nil {
		t.Fatal(err)
	}
	if err := restarted.RecordDeploy("apache", "target-a", "renewed", []byte("renewed-cert"), oldKey); err != nil {
		t.Fatal(err)
	}
	if err := restarted.FinalizeReprotect("apache", "target-a", "job-a", "old", "not-served"); !errors.Is(err, relay.ErrHostRollbackStateMismatch) {
		t.Fatalf("unverified active fingerprint cleared pin: %v", err)
	}
	if err := restarted.RestoreReprotect("apache", "target-a", "job-a", "old", func([]byte, []byte) (bool, error) {
		return false, errors.New("listener still serves successor")
	}); err == nil {
		t.Fatal("failed listener verification committed rollback")
	}
	if err := restarted.RestoreReprotect("apache", "target-a", "job-a", "old", func(cert, key []byte) (bool, error) {
		if !bytes.Equal(cert, oldCert) || !bytes.Equal(key, oldKey) {
			t.Fatal("re-protection rollback lost the exact predecessor")
		}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	// A lost completion report must be safe to redeliver after another restart.
	restarted, err = relay.NewHostRollbackStore(root, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.RestoreReprotect("apache", "target-a", "job-a", "old", func([]byte, []byte) (bool, error) {
		return true, nil
	}); err != nil {
		t.Fatalf("lost-response restore: %v", err)
	}
	if err := restarted.FinalizeReprotect("apache", "target-a", "job-a", "old", "old"); err != nil {
		t.Fatal(err)
	}
	if err := restarted.RestoreReprotect("apache", "target-a", "job-a", "old", func([]byte, []byte) (bool, error) {
		return true, nil
	}); !errors.Is(err, relay.ErrHostRollbackPredecessorMissing) {
		t.Fatalf("finalized predecessor retained: %v", err)
	}
}

func TestHostRollbackStoreRetainsOneBoundReprotectCSRAndLeafAcrossRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "host-rollbacks")
	st, err := relay.NewHostRollbackStore(root, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PinReprotectPredecessor("apache", "target-a", "job-a", "old", []byte("old-cert"), []byte("old-private-key")); err != nil {
		t.Fatal(err)
	}
	csr := []byte("public-retained-key-csr")
	if err := st.RecordReprotectCSR("apache", "target-a", "job-a", csr); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordReprotectCSR("apache", "target-a", "job-a", csr); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordReprotectCSR("apache", "target-a", "job-a", []byte("second-csr")); !errors.Is(err, relay.ErrHostRollbackStateMismatch) {
		t.Fatalf("second CSR admitted: %v", err)
	}
	restarted, err := relay.NewHostRollbackStore(root, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	pending, err := restarted.LoadReprotectPending("apache", "target-a", "job-a")
	if err != nil || pending == nil || !bytes.Equal(pending.CSRDER, csr) {
		t.Fatalf("pending CSR after restart: %v %#v", err, pending)
	}
	if err := restarted.RecordReprotectCertificate("apache", "target-a", "job-a", []byte("new-cert"), []byte("chain"), "new"); err != nil {
		t.Fatal(err)
	}
	restarted, err = relay.NewHostRollbackStore(root, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	pending, err = restarted.LoadReprotectPending("apache", "target-a", "job-a")
	if err != nil || pending == nil || !bytes.Equal(pending.CertPEM, []byte("new-cert")) || pending.Fingerprint != "new" {
		t.Fatalf("signed leaf after restart: %v %#v", err, pending)
	}
	for _, entry := range []string{"old-private-key", "public-retained-key-csr", "new-cert"} {
		files, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			raw, err := os.ReadFile(filepath.Join(root, file.Name())) // #nosec G304 -- test-owned state root (CWE-22)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(raw, []byte(entry)) {
				t.Fatalf("pending state stored plaintext %s", entry)
			}
		}
	}
}

func TestHostRollbackStoreReprotectPinRefusesExistingMismatchAndConcurrentPQC(t *testing.T) {
	st, err := relay.NewHostRollbackStore(filepath.Join(t.TempDir(), "state"), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordDeploy("nginx", "target-a", "active", []byte("active-cert"), []byte("active-key")); err != nil {
		t.Fatal(err)
	}
	if err := st.PinReprotectPredecessor("nginx", "target-a", "job-a", "other", []byte("other-cert"), []byte("other-key")); !errors.Is(err, relay.ErrHostRollbackStateMismatch) {
		t.Fatalf("mismatched installed bundle adopted: %v", err)
	}
	if err := st.PinReprotectPredecessor("nginx", "target-a", "job-a", "active", []byte("active-cert"), []byte("active-key")); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordDeploy("nginx", "target-a", "successor", []byte("successor-cert"), []byte("active-key")); err != nil {
		t.Fatal(err)
	}
	if err := st.FinalizeReprotect("nginx", "target-a", "job-a", "active", "successor"); err != nil {
		t.Fatalf("verified successor could not release predecessor: %v", err)
	}
	if err := st.PinPQCPredecessor("nginx", "target-a", "pqc-run", "successor", []byte("successor-cert"), []byte("active-key")); err != nil {
		t.Fatalf("finalized re-protection left false PQC conflict: %v", err)
	}
	if err := st.PinReprotectPredecessor("nginx", "target-a", "job-b", "successor", []byte("successor-cert"), []byte("active-key")); !errors.Is(err, relay.ErrHostRollbackStateMismatch) {
		t.Fatalf("concurrent PQC migration allowed CA re-protection: %v", err)
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
