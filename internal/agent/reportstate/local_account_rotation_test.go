// SPDX-License-Identifier: BUSL-1.1
package reportstate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/winaccounts"
)

const accountGeneration = "58800000-0000-4000-8000-000000000001"
const nextAccountGeneration = "58800000-0000-4000-8000-000000000002"

func journalAccountBinding() winaccounts.RotationBinding {
	return winaccounts.RotationBinding{Machine: winaccounts.Machine{Name: "OWNED", SID: "S-1-5-21-1-2-3", Role: 3}, Account: winaccounts.Account{Name: "OwnedAdmin", SID: "S-1-5-21-1-2-3-1001", Enabled: true, PasswordRequired: true}}
}

type localAccountFixture struct {
	afterFence        func()
	block             <-chan struct{}
	entered           chan<- struct{}
	calls, resets     int
	unknown, badProof bool
	exitAfterFence    bool
}

func (f *localAccountFixture) Rotate(ctx context.Context, b winaccounts.RotationBinding, generation string, old, next []byte, fence winaccounts.RotationFence) (winaccounts.RotationProof, error) {
	f.calls++
	fresh, err := fence.Begin(ctx, b, generation)
	if err != nil || !fresh {
		return winaccounts.RotationProof{}, winaccounts.ErrRotationUncertain
	}
	f.resets++
	if f.afterFence != nil {
		f.afterFence()
	}
	if f.entered != nil {
		close(f.entered)
	}
	if f.block != nil {
		<-f.block
	}
	if f.exitAfterFence {
		os.Exit(0)
	}
	if f.unknown {
		return winaccounts.RotationProof{}, winaccounts.ErrRotationUncertain
	}
	p := winaccounts.RotationProof{Binding: b, GenerationID: generation, NewAuthenticated: true, OldRefused: true, ObservedAt: time.Now().UTC()}
	if f.badProof {
		p.Binding.Account.Name = "ForeignName"
	}
	if err = fence.Complete(ctx, p); err != nil {
		return winaccounts.RotationProof{}, err
	}
	return p, nil
}
func openAccountStore(t *testing.T, root string) *Store {
	t.Helper()
	s, e := Open(root, "tenant/agent/server")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func accountObservation(job int64, p winaccounts.RotationProof) Observation {
	return Observation{JobID: job, Attempt: 1, Outcome: "verified", Detail: []byte("owned public receipt"), LocalAccountRotation: &p}
}
func TestLocalAccountRotationJournalRetainsExactProofAcrossRestartA268(t *testing.T) {
	root := t.TempDir()
	s := openAccountStore(t, root)
	f := &localAccountFixture{}
	b := journalAccountBinding()
	old := bytes.Repeat([]byte{'x'}, 32)
	next := bytes.Repeat([]byte{'z'}, 32)
	defer secret.Wipe(old)
	defer secret.Wipe(next)
	p, e := s.ExecuteLocalAccountRotationOnce(t.Context(), 71, b, accountGeneration, "", old, next, f)
	if e != nil || f.resets != 1 || !p.NewAuthenticated || !p.OldRefused {
		t.Fatal("exact native proof was not retained", e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s = openAccountStore(t, root)
	replay, found, e := s.ReplayLocalAccountRotation(t.Context(), 71, b, accountGeneration, "")
	if e != nil || !found || !sameAccountRotationProof(replay, p) {
		t.Fatal("lost reply did not recover exact original proof", e)
	}
	replay, e = s.ExecuteLocalAccountRotationOnce(t.Context(), 71, b, accountGeneration, "", nil, nil, f)
	if e != nil || !sameAccountRotationProof(replay, p) || f.calls != 1 {
		t.Fatal("replay reset or authenticated again", e)
	}
	if _, e = s.ExecuteLocalAccountRotationOnce(t.Context(), 72, b, nextAccountGeneration, accountGeneration, old, next, f); e == nil || f.calls != 1 {
		t.Fatal("unacknowledged generation was replaced", e)
	}
	changed := b
	changed.Account.Name = "Renamed"
	changed.Machine.Name = "RENAMED-HOST"
	if _, e = s.ExecuteLocalAccountRotationOnce(t.Context(), 71, changed, accountGeneration, "", old, next, f); e == nil || f.calls != 1 {
		t.Fatal("name change reused old native authority", e)
	}
	report := accountObservation(71, p)
	if e = s.Put(report); e != nil {
		t.Fatal(e)
	}
	wrongReport := report
	altered := *report.LocalAccountRotation
	altered.GenerationID = nextAccountGeneration
	wrongReport.LocalAccountRotation = &altered
	if e = s.Acknowledge(wrongReport); e == nil {
		t.Fatal("another generation acknowledged the retained original")
	}
	if _, e = s.ExecuteLocalAccountRotationOnce(t.Context(), 72, b, nextAccountGeneration, accountGeneration, old, next, f); e == nil || f.calls != 1 {
		t.Fatal("inexact acknowledgement released next native generation")
	}
	if e = s.Acknowledge(report); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s = openAccountStore(t, root)
	if _, e = s.ExecuteLocalAccountRotationOnce(t.Context(), 71, b, accountGeneration, "", nil, nil, f); e != nil || f.calls != 1 {
		t.Fatal("accepted result forgot its replay fence", e)
	}
	second, e := s.ExecuteLocalAccountRotationOnce(t.Context(), 72, changed, nextAccountGeneration, accountGeneration, old, next, f)
	if e != nil || f.resets != 2 || second.Binding != changed {
		t.Fatal("acknowledged account could not rotate its next generation", e)
	}
	if _, e = s.ExecuteLocalAccountRotationOnce(t.Context(), 71, b, accountGeneration, "", old, next, f); e == nil || f.resets != 2 {
		t.Fatal("older job reset a newer native generation", e)
	}
	// A second SID has an independent queue order; a newer job on one account
	// must not reject an older queued job on another account.
	other := b
	other.Account.SID = "S-1-5-21-1-2-3-1002"
	other.Account.Name = "OtherAdmin"
	if _, e = s.ExecuteLocalAccountRotationOnce(t.Context(), 70, other, accountGeneration, "", old, next, f); e != nil || f.resets != 3 {
		t.Fatal("one account blocked independent native work", e)
	}
	privateRoot := openReportTestRoot(t, root)
	entries, e := os.ReadDir(filepath.Join(root, localAccountRotationDirectory))
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		raw, e := privateRoot.ReadFile(filepath.Join(localAccountRotationDirectory, entry.Name()))
		if e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(raw, old) || bytes.Contains(raw, next) || bytes.Contains(raw, []byte(accountGeneration)) {
			t.Fatal("private values or public authority escaped sealed journal")
		}
	}
	t.Log("A268_LOCAL_ROTATION_JOURNAL_OK: exact proof replay, durable acknowledgement and next generation; account queue order remains independent; sealed files contain no passwords")
}
func TestLocalAccountRotationUnknownAttemptSurvivesFailedReportAckA268(t *testing.T) {
	root := t.TempDir()
	s := openAccountStore(t, root)
	f := &localAccountFixture{unknown: true}
	b := journalAccountBinding()
	if p, e := s.ExecuteLocalAccountRotationOnce(t.Context(), 81, b, accountGeneration, "", nil, nil, f); !errors.Is(e, winaccounts.ErrRotationUncertain) || p.NewAuthenticated {
		t.Fatal("unknown native reset claimed success", e)
	}
	failed := Observation{JobID: 81, Attempt: 1, Outcome: "failed", Detail: []byte("native outcome unknown")}
	if e := s.Put(failed); e != nil {
		t.Fatal(e)
	}
	if e := s.Acknowledge(failed); e != nil {
		t.Fatal(e)
	}
	_ = s.Close()
	s = openAccountStore(t, root)
	for _, job := range []int64{81, 82} {
		if _, e := s.ExecuteLocalAccountRotationOnce(t.Context(), job, b, accountGeneration, "", nil, nil, f); !errors.Is(e, winaccounts.ErrRotationUncertain) || f.calls != 1 || f.resets != 1 {
			t.Fatal("failed report acknowledgement released unknown reset", e)
		}
	}
}
func TestLocalAccountRotationJournalRefusesForgedCompletionAndAcknowledgementA268(t *testing.T) {
	for _, kind := range []string{"native-proof", "ack-proof", "failed-proof"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			s := openAccountStore(t, root)
			f := &localAccountFixture{badProof: kind == "native-proof"}
			b := journalAccountBinding()
			p, e := s.ExecuteLocalAccountRotationOnce(t.Context(), 91, b, accountGeneration, "", nil, nil, f)
			if kind == "native-proof" {
				if e == nil || p.NewAuthenticated {
					t.Fatal("foreign native proof retained")
				}
				if _, e = s.ExecuteLocalAccountRotationOnce(t.Context(), 91, b, accountGeneration, "", nil, nil, f); e == nil || f.calls != 1 {
					t.Fatal("foreign completion released fence")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			report := accountObservation(91, p)
			if kind == "ack-proof" {
				report.LocalAccountRotation.GenerationID = nextAccountGeneration
			} else {
				report.Outcome = "failed"
			}
			if e = s.Put(report); e == nil {
				t.Fatal("unproven receipt could authorize generation retirement")
			}
		})
	}
}
func TestLocalAccountRotationJournalRejectsDamageAndMissingKeyA268(t *testing.T) {
	for _, kind := range []string{"tail", "key", "binding", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			s := openAccountStore(t, root)
			b := journalAccountBinding()
			f := &localAccountFixture{unknown: true}
			_, _ = s.ExecuteLocalAccountRotationOnce(t.Context(), 101, b, accountGeneration, "", nil, nil, f)
			_ = s.Close()
			privateRoot := openReportTestRoot(t, root)
			name := filepath.Join(localAccountRotationDirectory, localAccountRotationName(b))
			original, e := privateRoot.ReadFile(name)
			if e != nil {
				t.Fatal(e)
			}
			binding := "tenant/agent/server"
			switch kind {
			case "tail":
				if e = privateRoot.WriteFile(name, append(original, 1), 0600); e != nil {
					t.Fatal(e)
				}
			case "key":
				if e = os.Remove(filepath.Join(root, "sealing.key")); e != nil {
					t.Fatal(e)
				}
			case "binding":
				binding = "another/registration/server"
			case "symlink":
				if e = privateRoot.Rename(name, name+".evidence"); e != nil {
					t.Fatal(e)
				}
				if e = privateRoot.Symlink(localAccountRotationName(b)+".evidence", name); e != nil {
					t.Fatal(e)
				}
			}
			if opened, e := Open(root, binding); e == nil {
				_ = opened.Close()
				t.Fatal("damaged or foreign native fence was discarded")
			}
			if kind == "key" {
				if _, e = os.Stat(filepath.Join(root, "sealing.key")); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("missing key was silently regenerated")
				}
			}
			if kind != "tail" {
				raw, e := privateRoot.ReadFile(name)
				if e != nil || !bytes.Equal(raw, original) {
					t.Fatal("rejected native fence was rewritten", e)
				}
			}
		})
	}
}
func TestLocalAccountRotationAbruptExitKeepsStartFenceA268(t *testing.T) {
	const childEnv = "TRSTCTL_A268_ACCOUNT_JOURNAL_CHILD"
	if root := os.Getenv(childEnv); root != "" {
		s, e := Open(root, "tenant/agent/server")
		if e != nil {
			t.Fatal(e)
		}
		_, _ = s.ExecuteLocalAccountRotationOnce(t.Context(), 111, journalAccountBinding(), accountGeneration, "", nil, nil, &localAccountFixture{exitAfterFence: true})
		t.Fatal("child did not stop after durable fence")
	}
	root := t.TempDir()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(t.Context(), binary, "-test.run=^TestLocalAccountRotationAbruptExitKeepsStartFenceA268$") // #nosec G204 -- current Go test executable with one fixed test selector and an owned public temp root; no shell or credentials (CWE-78)
	child.Env = append(os.Environ(), childEnv+"="+root)
	if out, e := child.CombinedOutput(); e != nil {
		t.Fatalf("owned abrupt-exit helper failed: %v %s", e, out)
	}
	s := openAccountStore(t, root)
	f := &localAccountFixture{}
	if _, e := s.ExecuteLocalAccountRotationOnce(t.Context(), 111, journalAccountBinding(), accountGeneration, "", nil, nil, f); !errors.Is(e, winaccounts.ErrRotationUncertain) || f.calls != 0 {
		t.Fatal("abrupt process exit lost durable reset fence", e)
	}
}

func TestLocalAccountRotationPersistenceFailureKeepsUncertainFenceA268(t *testing.T) {
	root := t.TempDir()
	s := openAccountStore(t, root)
	b := journalAccountBinding()
	staging := filepath.Join(root, localAccountRotationDirectory, strings.TrimSuffix(localAccountRotationName(b), ".state")+".next")
	f := &localAccountFixture{afterFence: func() {
		if e := os.Mkdir(staging, 0700); e != nil {
			t.Fatal(e)
		}
	}}
	if p, e := s.ExecuteLocalAccountRotationOnce(t.Context(), 121, b, accountGeneration, "", nil, nil, f); e == nil || p.NewAuthenticated {
		t.Fatal("failed native proof persistence claimed completion")
	}
	if _, e := s.ExecuteLocalAccountRotationOnce(t.Context(), 121, b, accountGeneration, "", nil, nil, f); e == nil || f.calls != 1 {
		t.Fatal("persistence failure allowed another native reset")
	}
	// Only remove the exact empty directory created by this fault fixture. The
	// retained fenced record remains untouched through close and reopen.
	if e := os.Remove(staging); e != nil {
		t.Fatal(e)
	}
	_ = s.Close()
	s = openAccountStore(t, root)
	if _, e := s.ExecuteLocalAccountRotationOnce(t.Context(), 121, b, accountGeneration, "", nil, nil, f); !errors.Is(e, winaccounts.ErrRotationUncertain) || f.calls != 1 {
		t.Fatal("failed completion lost original durable fence", e)
	}
}
func TestLocalAccountRotationRejectsConcurrentNativeResetA268(t *testing.T) {
	s := openAccountStore(t, t.TempDir())
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan error, 1)
	f := &localAccountFixture{entered: entered, block: release}
	go func() {
		_, e := s.ExecuteLocalAccountRotationOnce(t.Context(), 131, journalAccountBinding(), accountGeneration, "", nil, nil, f)
		finished <- e
	}()
	select {
	case <-entered:
	case e := <-finished:
		t.Fatal("native fixture stopped before its start fence", e)
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("native fixture did not reach its start fence")
	}
	other := &localAccountFixture{}
	if _, e := s.ExecuteLocalAccountRotationOnce(t.Context(), 132, journalAccountBinding(), nextAccountGeneration, accountGeneration, nil, nil, other); e == nil || other.calls != 0 {
		t.Error("concurrent attempt entered native password engine")
	}
	close(release)
	if e := <-finished; e != nil {
		t.Fatal(e)
	}
}

func TestLocalAccountRotationStableAuthoritySurvivesOutboxRecreationA268(t *testing.T) {
	root := t.TempDir()
	s := openAccountStore(t, root)
	b := journalAccountBinding()
	f := &localAccountFixture{}
	p, e := s.ExecuteLocalAccountRotationOnce(t.Context(), 201, b, accountGeneration, "", nil, nil, f)
	if e != nil {
		t.Fatal(e)
	}
	_ = s.Close()
	s = openAccountStore(t, root)
	// Outbox rows use a database-local identity. The immutable generation and
	// native authority survive rebuild even when that delivery receives a new ID.
	replay, e := s.ExecuteLocalAccountRotationOnce(t.Context(), 17, b, accountGeneration, "", nil, nil, f)
	if e != nil || !sameAccountRotationProof(p, replay) || f.calls != 1 {
		t.Fatal("outbox recreation lost exact generation proof or repeated native work", e)
	}
	report := accountObservation(17, p)
	if e = s.Put(report); e != nil {
		t.Fatal(e)
	}
	if e = s.Acknowledge(report); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ExecuteLocalAccountRotationOnce(t.Context(), 2, b, nextAccountGeneration, accountGeneration, nil, nil, f); e != nil || f.calls != 2 {
		t.Fatal("database-local identity incorrectly ordered native generations", e)
	}
}

func TestLocalAccountRotationRequiresExactGenerationAncestryA268(t *testing.T) {
	s := openAccountStore(t, t.TempDir())
	b := journalAccountBinding()
	f := &localAccountFixture{}
	if _, e := s.ExecuteLocalAccountRotationOnce(t.Context(), 1, b, nextAccountGeneration, accountGeneration, nil, nil, f); !errors.Is(e, winaccounts.ErrRotationUncertain) || f.calls != 0 {
		t.Fatal("missing host predecessor was treated as a fresh account", e)
	}
	p, e := s.ExecuteLocalAccountRotationOnce(t.Context(), 2, b, accountGeneration, "", nil, nil, f)
	if e != nil {
		t.Fatal(e)
	}
	report := accountObservation(2, p)
	if e = s.Put(report); e != nil {
		t.Fatal(e)
	}
	if e = s.Acknowledge(report); e != nil {
		t.Fatal(e)
	}
	for _, parent := range []string{"", nextAccountGeneration} {
		if _, e = s.ExecuteLocalAccountRotationOnce(t.Context(), 3, b, nextAccountGeneration, parent, nil, nil, f); e == nil || f.calls != 1 {
			t.Fatal("wrong ancestry reached native reset", e)
		}
	}
	if _, _, e = s.ReplayLocalAccountRotation(t.Context(), 2, b, accountGeneration, nextAccountGeneration); e == nil {
		t.Fatal("changed predecessor reused original proof")
	}
	if _, e = s.ExecuteLocalAccountRotationOnce(t.Context(), 1, b, nextAccountGeneration, accountGeneration, nil, nil, f); e != nil || f.calls != 2 {
		t.Fatal("stable predecessor did not authorize distinct successor", e)
	}
}
