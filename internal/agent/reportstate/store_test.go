// SPDX-License-Identifier: BUSL-1.1

package reportstate

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

// B13-R1: an operator who re-enrolled an agent (or changed its CA bundle or
// server name) holds a pending report the new registration can never open.
// Open still refuses it and keeps its bytes; SetAsideUnopenable is the explicit
// decision that moves it aside intact, so the agent can claim again under the
// new registration. A report that opens is never moved, and the set-aside
// copy still opens under the registration that sealed it.
func TestSetAsideMovesOnlyAReportThisRegistrationCannotOpen(t *testing.T) {
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
			binding, want := "original", ErrUnopenable
			switch kind {
			case "authority":
				binding = "re-enrolled"
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
				if err := root.Remove("sealing.key"); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				want = ErrInvalidPending
				if err := os.Truncate(filepath.Join(dir, "pending.state"), maxRecordBytes+65); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				want = ErrInvalidPending
				if err := root.Rename("pending.state", "preserved.state"); err != nil {
					t.Fatal(err)
				}
				if err := root.Symlink("preserved.state", "pending.state"); err != nil {
					t.Fatal(err)
				}
			}
			before, err := root.Lstat("pending.state")
			if err != nil {
				t.Fatal(err)
			}
			var beforeBytes []byte
			if before.Mode().IsRegular() {
				if beforeBytes, err = root.ReadFile("pending.state"); err != nil {
					t.Fatal(err)
				}
			}
			if opened, err := Open(dir, binding); err == nil {
				_ = opened.Close()
				t.Fatal("unopenable report accepted")
			} else if !errors.Is(err, want) {
				t.Fatalf("Open refusal = %v, want %v", err, want)
			}
			moved, err := SetAsideUnopenable(dir, binding)
			if err != nil {
				t.Fatal(err)
			}
			if filepath.Dir(moved) != dir || !strings.HasPrefix(filepath.Base(moved), "set-aside-") {
				t.Fatalf("set aside at %q, want a set-aside-* file in %s", moved, dir)
			}
			if _, err := root.Lstat("pending.state"); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("pending report still in place after set-aside: %v", err)
			}
			after, err := root.Lstat(filepath.Base(moved))
			if err != nil || after.Mode().Type() != before.Mode().Type() {
				t.Fatalf("set-aside file changed type: %v", err)
			}
			if before.Mode().IsRegular() {
				if afterBytes, err := root.ReadFile(filepath.Base(moved)); err != nil || !bytes.Equal(beforeBytes, afterBytes) {
					t.Fatalf("set-aside changed the retained bytes: %v", err)
				}
				if info, err := root.Stat(filepath.Base(moved)); err != nil || info.Mode().Perm() != 0o600 {
					t.Fatalf("set-aside file mode = %v (%v), want 0600", info.Mode().Perm(), err)
				}
			}
			if kind == "missing-key" {
				if _, err := root.Lstat("sealing.key"); !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("set-aside created a sealing key; only a later Open may")
				}
			}
			// The new registration claims again: nothing pending, and a new
			// result is retained and acknowledged as usual.
			s = openStore(t, dir, binding)
			if pending, err := s.Pending(); pending != nil || err != nil {
				t.Fatalf("pending after set-aside = %v (%v), want none", pending, err)
			}
			next := observation()
			next.JobID = 8
			if err := s.Put(next); err != nil {
				t.Fatal(err)
			}
			if err := s.Acknowledge(next); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if kind == "authority" {
				// Restoring the previous registration and the file recovers the
				// original report, which was never sent.
				if err := root.Rename(filepath.Base(moved), "pending.state"); err != nil {
					t.Fatal(err)
				}
				s = openStore(t, dir, "original")
				pending, err := s.Pending()
				if err != nil || pending == nil || !same(*pending, observation()) {
					t.Fatalf("set-aside report not recoverable under its own registration: %v", err)
				}
				pending.Destroy()
			}
		})
	}
}

func TestSetAsideLeavesADeliverableReportAndHonoursTheBound(t *testing.T) {
	dir := t.TempDir()
	s := openStore(t, dir, "original")
	if err := s.Put(observation()); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	root := openReportTestRoot(t, dir)
	before, err := root.ReadFile("pending.state")
	if err != nil {
		t.Fatal(err)
	}
	if moved, err := SetAsideUnopenable(dir, "original"); err != nil || moved != "" {
		t.Fatalf("deliverable report set aside at %q (%v); it must stay for the agent to send", moved, err)
	}
	if after, err := root.ReadFile("pending.state"); err != nil || !bytes.Equal(before, after) {
		t.Fatalf("deliverable report changed: %v", err)
	}
	if moved, err := SetAsideUnopenable(t.TempDir(), "original"); err != nil || moved != "" {
		t.Fatalf("empty store set aside %q (%v)", moved, err)
	}
	for i := range setAsideLimit {
		if err := root.WriteFile(fmt.Sprintf("set-aside-2026010%dT000000.000000000Z.state", i+1), []byte("kept"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if moved, err := SetAsideUnopenable(dir, "re-enrolled"); err == nil || moved != "" {
		t.Fatalf("set-aside beyond the bound = %q (%v), want a refusal", moved, err)
	} else if !strings.Contains(err.Error(), "already set aside") {
		t.Fatalf("bound refusal %v does not say why", err)
	}
	if after, err := root.ReadFile("pending.state"); err != nil || !bytes.Equal(before, after) {
		t.Fatalf("refused set-aside changed the report: %v", err)
	}
	held := openStore(t, dir, "original")
	if _, err := SetAsideUnopenable(dir, "re-enrolled"); err == nil || !strings.Contains(err.Error(), "another process owns") {
		t.Fatalf("set-aside while the agent runs = %v, want the process-lock refusal", err)
	}
	_ = held.Close()
}
