// SPDX-License-Identifier: BUSL-1.1

package reportstate

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/custody"
)

func observation() Observation {
	return Observation{JobID: 7, Attempt: 2, Outcome: "executed", Detail: []byte("owned sensitive terminal observation"), EvidenceDigest: "exact-evidence", CredentialFingerprint: "original-fingerprint", Custody: &custody.Record{Origin: custody.OriginHostAgent, GeneratedBy: "original-agent"}}
}

func openStore(t *testing.T, path, binding string) *Store {
	t.Helper()
	s, err := Open(path, binding)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestRestartPreservesEncryptedOriginalAndExactAcknowledgement(t *testing.T) {
	dir := t.TempDir()
	s := openStore(t, dir, "original-authority")
	v := observation()
	if err := s.Put(v); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(v); err != nil {
		t.Fatal(err)
	}
	root := openReportTestRoot(t, dir)
	disk, err := root.ReadFile("pending.state")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(disk, v.Detail) || bytes.Contains(disk, []byte(v.EvidenceDigest)) {
		t.Fatal("observation leaked in plaintext")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openStore(t, dir, "original-authority")
	pending, err := s.Pending()
	if err != nil || pending == nil || !same(*pending, v) {
		t.Fatalf("original observation not recovered: %v", err)
	}
	defer pending.Destroy()
	wrong := v
	wrong.Attempt++
	if err := s.Acknowledge(wrong); err == nil {
		t.Fatal("different attempt acknowledged")
	}
	if err := s.Acknowledge(v); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openStore(t, dir, "original-authority")
	if pending, err := s.Pending(); pending != nil || err != nil {
		t.Fatalf("acknowledged observation reappeared: %v", err)
	}
}

func TestInvalidRecoveryPreservesOriginalBytes(t *testing.T) {
	for _, kind := range []string{"authority", "corruption", "missing-key", "oversized", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			s := openStore(t, dir, "original")
			if err := s.Put(observation()); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			root := openReportTestRoot(t, dir)
			path := filepath.Join(dir, "pending.state")
			binding := "original"
			switch kind {
			case "authority":
				binding = "different"
			case "corruption":
				data, err := root.ReadFile("pending.state")
				if err != nil {
					t.Fatal(err)
				}
				data[len(data)-1] ^= 1
				if err := root.WriteFile("pending.state", data, 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing-key":
				if err := os.Remove(filepath.Join(dir, "sealing.key")); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.Truncate(path, maxRecordBytes+65); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				original := filepath.Join(dir, "preserved.state")
				if err := os.Rename(path, original); err != nil {
					t.Fatal(err)
				}
				if err := root.Symlink("preserved.state", "pending.state"); err != nil {
					t.Fatal(err)
				}
			}
			before, err := root.ReadFile("pending.state")
			if err != nil {
				t.Fatal(err)
			}
			opened, err := Open(dir, binding)
			if err == nil {
				_ = opened.Close()
				t.Fatal("invalid state accepted")
			}
			after, err := root.ReadFile("pending.state")
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("failed recovery changed retained bytes: %v", err)
			}
			if kind == "missing-key" {
				if _, err := os.Stat(filepath.Join(dir, "sealing.key")); !os.IsNotExist(err) {
					t.Fatal("missing key silently replaced")
				}
			}
		})
	}
}

func TestStoreLockAndPersistenceFailurePreventFurtherWork(t *testing.T) {
	dir := t.TempDir()
	s := openStore(t, dir, "identity")
	if other, err := Open(dir, "identity"); err == nil {
		_ = other.Close()
		t.Fatal("concurrent process store ownership accepted")
	}
	if err := os.Mkdir(filepath.Join(dir, "pending.next"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(observation()); err == nil {
		t.Fatal("unwritable state accepted")
	}
	if _, err := s.Pending(); err == nil {
		t.Fatal("claim admission can continue after unpersisted result")
	}
}

func TestPendingResultCannotBeReplaced(t *testing.T) {
	dir := t.TempDir()
	s := openStore(t, dir, "identity")
	v := observation()
	if err := s.Put(v); err != nil {
		t.Fatal(err)
	}
	v.JobID++
	if err := s.Put(v); err == nil {
		t.Fatal("pending observation overwritten")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openStore(t, dir, "identity")
	p, err := s.Pending()
	if err != nil || p == nil || !same(*p, observation()) {
		t.Fatalf("original lost: %v", err)
	}
	p.Destroy()
}

// Open the owned fixture directory once; byte comparisons and corruption writes
// cannot escape it, including when the test deliberately supplies a symlink.
func openReportTestRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	return root
}
