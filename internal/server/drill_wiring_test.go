// SPDX-License-Identifier: BUSL-1.1

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
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
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
// So these tests assert the WIRING, not the behavior. They are deliberately
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

func TestRestoreDrillPartialDurableAssemblyFailsClosed(t *testing.T) {
	t.Parallel()
	s := &Server{
		store: new(store.Store),
		restoreDrill: func(context.Context) (backup.DrillAttestation, error) {
			return backup.DrillAttestation{Outcome: backup.DrillRestored}, nil
		},
	}
	if _, err := s.RunRestoreDrillOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "dependencies are incomplete") {
		t.Fatalf("partial durable restore-drill assembly error = %v, want fail-closed dependency error", err)
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

func TestRestoreDrillAlertReasonCoversEveryClosedOutcomeAndObjective(t *testing.T) {
	t.Parallel()
	const (
		rpo = 24 * time.Hour
		rto = time.Hour
	)
	tests := []struct {
		name string
		att  backup.DrillAttestation
		want projections.RestoreDrillAlertReason
	}{
		{name: "restored within objectives", att: backup.DrillAttestation{Outcome: backup.DrillRestored, RPOSeconds: 1, RTOSeconds: 1}},
		{name: "failed", att: backup.DrillAttestation{Outcome: backup.DrillFailed}, want: projections.RestoreDrillAlertFailed},
		{name: "skipped", att: backup.DrillAttestation{Outcome: backup.DrillSkipped}, want: projections.RestoreDrillAlertSkipped},
		{name: "over RPO", att: backup.DrillAttestation{Outcome: backup.DrillRestored, RPOSeconds: int64((rpo + time.Second) / time.Second), RTOSeconds: 1}, want: projections.RestoreDrillAlertOverRPO},
		{name: "over RTO", att: backup.DrillAttestation{Outcome: backup.DrillRestored, RPOSeconds: 1, RTOSeconds: int64((rto + time.Second) / time.Second)}, want: projections.RestoreDrillAlertOverRTO},
		{name: "over both", att: backup.DrillAttestation{Outcome: backup.DrillRestored, RPOSeconds: int64((rpo + time.Second) / time.Second), RTOSeconds: int64((rto + time.Second) / time.Second)}, want: projections.RestoreDrillAlertOverBoth},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := restoreDrillAlertReason(tt.att, rpo, rto); got != tt.want {
				t.Fatalf("restoreDrillAlertReason(%+v) = %q, want %q", tt.att, got, tt.want)
			}
		})
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

// "0" must actually DISABLE the drill, not merely parse to zero.
//
// Two layers were wrong and one test was worse than useless. config's "0"
// parsed to a zero Duration — asserted, and true. The scheduler treated only a
// NEGATIVE interval as disabled, so zero fell through to a daily default, and
// every deployment that asked for no drill got one. The claim lived one layer
// below the test that was supposed to cover it.
//
// The replacement I wrote first was no better: it ran the scheduler and
// asserted no drill fired within 150ms. Against the bug, zero became a 24-hour
// ticker — which also fires nothing in 150ms. It passed against the defect it
// existed to catch. Timing cannot see this difference for any window shorter
// than a day, so the decision is a pure function and the assertion is on the
// decision.
func TestAZeroDrillIntervalDisablesRatherThanDefaulting(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		haveRunner  bool
		configured  time.Duration
		wantEnabled bool
		wantEvery   time.Duration
	}{
		{"explicit \"0\" disables", true, 0, false, 0},
		{"negative disables", true, -time.Second, false, 0},
		{"no runner disables", false, time.Hour, false, 0},
		{"a positive interval is honored exactly", true, 6 * time.Hour, true, 6 * time.Hour},
		{"the resolved default is honored", true, config.DefaultBackupDrillInterval, true, config.DefaultBackupDrillInterval},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			every, enabled := restoreDrillSchedule(tc.haveRunner, tc.configured)
			if enabled != tc.wantEnabled {
				t.Fatalf("enabled = %v, want %v. A zero reaching this layer can only mean the "+
					"operator wrote \"0\", which is documented as switching the drill off; "+
					"applying a default here is exactly how \"0\" came to mean \"daily\".",
					enabled, tc.wantEnabled)
			}
			if every != tc.wantEvery {
				t.Fatalf("interval = %v, want %v", every, tc.wantEvery)
			}
		})
	}
}

// An unset interval still gets the daily default — disabling must be explicit,
// not something an operator falls into by leaving a field out.
func TestAnUnsetDrillIntervalStillGetsTheDailyDefault(t *testing.T) {
	t.Parallel()
	var b config.Backup
	got, err := b.DrillIntervalDuration()
	if err != nil {
		t.Fatal(err)
	}
	if got != config.DefaultBackupDrillInterval {
		t.Fatalf("unset drill interval = %v, want the daily default", got)
	}
	if got <= 0 {
		t.Fatal("the default resolved to a non-positive value, which the scheduler now reads as " +
			"disabled — leaving a field out would silently turn the drill off")
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
	// Parsing to zero is only half the promise; that zero DISABLES the drill is
	// asserted by TestAZeroDrillIntervalStopsTheDrillRatherThanDefaultingIt,
	// because this assertion alone passed happily while the drill ran daily.
}

func TestRestoreDrillObjectivesDefaultParseAndRejectNegativeValues(t *testing.T) {
	t.Parallel()
	rpo, rto, err := (config.Backup{}).DrillObjectiveDurations()
	if err != nil || rpo != config.DefaultBackupDrillRPO || rto != config.DefaultBackupDrillRTO {
		t.Fatalf("default objectives = %v/%v err=%v", rpo, rto, err)
	}
	configured := config.Backup{DrillRPO: "8h", DrillRTO: "20m"}
	if rpo, rto, err = configured.DrillObjectiveDurations(); err != nil || rpo != 8*time.Hour || rto != 20*time.Minute {
		t.Fatalf("configured objectives = %v/%v err=%v", rpo, rto, err)
	}
	if _, _, err := (config.Backup{DrillRPO: "-1s"}).DrillObjectiveDurations(); err == nil {
		t.Fatal("negative RPO objective was accepted and would disable threshold alerting")
	}
}
