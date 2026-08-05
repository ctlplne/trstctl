// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
)

// Is the restore drill REACHABLE from the running binary? (epic J2)
//
// The first cut of J2 built the drill, the attestation, the ephemeral database
// and the DR posture endpoint, tested all of them, wrote the docs row — and
// wired none of it. RunRestoreDrill had no production caller. Every test passed
// and the drill could not run.
//
// That is the fourth instance of the same defect in this backlog: D2 shipped
// VerifyAddress with no producer, B2 shipped an endpoint.renew job kind with no
// enqueue, B5 shipped a custody projection that was never written, and this.
// The pattern is always the same — the capability is complete, the tests drive
// it directly, and nothing in the composition root calls it — and unit tests
// cannot see it by construction, because they are the thing standing in for the
// caller that does not exist.
//
// So these tests assert the WIRING, not the behaviour. They are deliberately
// cheap and deliberately about plumbing.

func TestTheRestoreDrillSchedulerIsRegisteredAsARuntimeWorker(t *testing.T) {
	t.Parallel()
	// The composition root's worker list is the only thing that makes any
	// scheduler run. Reading it as source is crude and it is what a unit test
	// on the scheduler cannot do: the scheduler works perfectly whether or not
	// anybody starts it.
	src, err := os.ReadFile("run.go")
	if err != nil {
		t.Fatalf("read the composition root: %v", err)
	}
	if !strings.Contains(string(src), "startRuntimeWorker(workCtx, srv.RunRestoreDrillScheduler)") {
		t.Fatal("RunRestoreDrillScheduler is not registered as a runtime worker in run.go, so no " +
			"deployment ever runs a restore drill and the DR surface reports 'never drilled' " +
			"forever — which reads as a configuration oversight rather than as a missing feature")
	}
}

func TestTheDRSurfaceReadsTheDrillTheSchedulerWrites(t *testing.T) {
	t.Parallel()
	// A scheduler that runs and an endpoint that reads a different place would
	// each pass their own tests. This asserts they are joined.
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read the API assembly: %v", err)
	}
	if !strings.Contains(string(src), "api.WithRestoreDrill(s.LastRestoreDrill)") {
		t.Fatal("the DR posture API is not wired to the Server's last drill attestation, so a " +
			"drill can run nightly and succeed while the served surface still reports that " +
			"none has ever run")
	}
}

// The scheduler must record what it ran, and the API must be able to see it.
func TestARunDrillBecomesTheServedAttestation(t *testing.T) {
	t.Parallel()
	want := backup.DrillAttestation{Outcome: backup.DrillRestored, EventsRestored: 41}
	s := &Server{restoreDrill: func(context.Context) (backup.DrillAttestation, error) {
		return want, nil
	}}

	if got := s.LastRestoreDrill(); got != nil {
		t.Fatalf("a server that has never drilled reports an attestation: %+v", got)
	}
	if _, err := s.RunRestoreDrillOnce(context.Background()); err != nil {
		t.Fatalf("run one drill: %v", err)
	}
	got := s.LastRestoreDrill()
	if got == nil {
		t.Fatal("the drill ran and the served surface still reports that none has")
	}
	if got.EventsRestored != want.EventsRestored || got.Outcome != want.Outcome {
		t.Fatalf("served attestation = %+v, want %+v", got, want)
	}
}

// A failed drill must be RECORDED, not dropped.
//
// This is the case worth protecting. A drill that fails means the backup exists
// and cannot be restored — the one state where every other signal in the system
// reports healthy, and the only one where this surface earns its place. Code
// that kept the last SUCCESSFUL attestation would report a green drill from
// three weeks ago while last night's failed.
func TestAFailedDrillReplacesASucceededOne(t *testing.T) {
	t.Parallel()
	outcome := backup.DrillRestored
	s := &Server{restoreDrill: func(context.Context) (backup.DrillAttestation, error) {
		return backup.DrillAttestation{Outcome: outcome, EventsRestored: 41}, nil
	}}
	if _, err := s.RunRestoreDrillOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	outcome = backup.DrillFailed
	if _, err := s.RunRestoreDrillOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := s.LastRestoreDrill(); got == nil || got.Outcome != backup.DrillFailed {
		t.Fatalf("after a failed drill the surface reports %+v; a stale success is the one "+
			"answer this endpoint must never give", got)
	}
}

// A drill that errors outright must not overwrite the last real attestation
// with an empty one. "The drill could not start" is not "the drill found
// nothing".
func TestADrillThatCouldNotRunLeavesTheLastAttestationAlone(t *testing.T) {
	t.Parallel()
	fail := false
	s := &Server{restoreDrill: func(context.Context) (backup.DrillAttestation, error) {
		if fail {
			return backup.DrillAttestation{}, errors.New("no ephemeral database")
		}
		return backup.DrillAttestation{Outcome: backup.DrillRestored, EventsRestored: 41}, nil
	}}
	if _, err := s.RunRestoreDrillOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	fail = true
	if _, err := s.RunRestoreDrillOnce(context.Background()); err == nil {
		t.Fatal("a drill that could not run reported success")
	}
	got := s.LastRestoreDrill()
	if got == nil || got.EventsRestored != 41 {
		t.Fatalf("an errored drill overwrote the last real attestation: %+v", got)
	}
}

// A deployment that configured no backup directory gets no drill runner, so it
// reports "not configured" rather than failing a drill nightly against a path
// nobody chose.
func TestNoBackupDirectoryMeansNoDrillRunner(t *testing.T) {
	t.Parallel()
	if runner := restoreDrillRunner(&config.Config{}); runner != nil {
		t.Error("a deployment with no backup directory was given a drill runner; it would fail " +
			"every night and the failure would mean nothing")
	}
	if runner := restoreDrillRunner(nil); runner != nil {
		t.Error("a nil config was given a drill runner")
	}
	cfg := &config.Config{}
	cfg.Backup.Directory = t.TempDir()
	if runner := restoreDrillRunner(cfg); runner == nil {
		t.Error("a configured backup directory produced no drill runner, so the drill never runs")
	}
}

// The runner must not be able to follow a later change to the caller's config.
func TestTheDrillRunnerCannotBeRedirectedAfterAssembly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Backup.Directory = dir
	runner := restoreDrillRunner(cfg)
	if runner == nil {
		t.Fatal("no runner built")
	}
	// Point the caller's struct at somewhere else entirely. The runner already
	// holds its own copy; a drill that could be redirected after assembly would
	// be a restore aimed wherever the last mutation pointed.
	other := filepath.Join(dir, "elsewhere")
	if err := os.MkdirAll(other, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg.Backup.Directory = other
	cfg.Postgres.DSN = "postgres://attacker@example.invalid/x"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// No external Postgres configured in the captured snapshot, so this reports
	// a skipped drill rather than reaching any database. What matters is that it
	// did not pick up the DSN set after assembly.
	att, err := runner(ctx)
	if err != nil && !errors.Is(err, backup.ErrNoEphemeralTarget) {
		t.Fatalf("run the drill: %v", err)
	}
	if att.Outcome == backup.DrillRestored {
		t.Fatal("a drill with no configured database reported a restore")
	}
	if att.Outcome != backup.DrillSkipped {
		t.Fatalf("outcome = %q, want a recorded skip: a deployment that CANNOT drill must not "+
			"be reported the same way as one that simply has not yet", att.Outcome)
	}
}

// A deployment that cannot drill must report that it cannot, not that it never
// has.
//
// RunDrill returns a populated "skipped" attestation ALONGSIDE a sentinel error.
// The first cut of this wiring treated any error as a failure and threw the
// attestation away, which collapsed "this deployment has no ephemeral target"
// into "no drill has ever run" — the two states J2 exists to separate.
func TestADeploymentThatCannotDrillSaysSoRatherThanStayingSilent(t *testing.T) {
	t.Parallel()
	s := &Server{restoreDrill: func(context.Context) (backup.DrillAttestation, error) {
		return backup.DrillAttestation{
			Outcome: backup.DrillSkipped,
			Detail:  "No ephemeral restore target is configured, so no drill ran.",
		}, backup.ErrNoEphemeralTarget
	}}
	if _, err := s.RunRestoreDrillOnce(context.Background()); !errors.Is(err, backup.ErrNoEphemeralTarget) {
		t.Fatalf("error = %v, want the sentinel passed through so a caller can tell why", err)
	}
	got := s.LastRestoreDrill()
	if got == nil {
		t.Fatal("a deployment that cannot drill reports no attestation at all, so the DR " +
			"surface says 'never drilled' — indistinguishable from an oversight")
	}
	if got.Outcome != backup.DrillSkipped {
		t.Fatalf("recorded outcome = %q, want skipped", got.Outcome)
	}
}

// An unparseable interval must fail startup rather than silently defaulting.
func TestABadDrillIntervalIsAConfigurationError(t *testing.T) {
	t.Parallel()
	var b config.Backup
	b.DrillInterval = "24hours"
	if _, err := b.DrillIntervalDuration(); err == nil {
		t.Error("\"24hours\" parsed as a duration; an operator who typed it would get the " +
			"default and never learn the setting was ignored")
	}
	b.DrillInterval = ""
	if d, err := b.DrillIntervalDuration(); err != nil || d != 24*time.Hour {
		t.Errorf("unset drill interval = %v, %v; want a daily default", d, err)
	}
	b.DrillInterval = "0"
	if d, err := b.DrillIntervalDuration(); err != nil || d != 0 {
		t.Errorf("explicit \"0\" = %v, %v; want zero", d, err)
	}
}
