// SPDX-License-Identifier: MPL-2.0

//go:build !trstctl_core

package main

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// AUD-1: the XREC rounds worker registered, hit a len(Schedules)==0 guard on its
// first tick, and blocked for the life of the process. Zero rounds ever ran, no
// witness was ever raised, and the served agreement report answered "0 open
// witnesses" forever — while a licensed operator watched a healthy worker sit in
// the runtime roster. There was no config key to populate schedules at all.

func TestReconcileSchedulesComeFromOperatorConfig(t *testing.T) {
	t.Parallel()
	got := reconcileSchedulesFromConfig(config.Reconcile{Schedules: []config.ReconcileSchedule{{
		TenantID: "t1", Cadence: "30m", Jitter: "2m", Liveness: "12h",
		Authorities: []config.ReconcileAuthority{{AuthorityID: "adcs"}, {AuthorityID: "vault"}},
	}}})
	if len(got) != 1 {
		t.Fatalf("schedules = %d, want 1.\n\n"+
			"Without this the rounds worker hits its empty-schedules guard on the first tick and "+
			"blocks forever: a registered, healthy-looking worker that compares nothing.", len(got))
	}
	if got[0].Cadence != 30*time.Minute || got[0].Jitter != 2*time.Minute {
		t.Fatalf("cadence/jitter = %v/%v, want the operator's values", got[0].Cadence, got[0].Jitter)
	}
	if len(got[0].Planes) != 2 {
		t.Fatalf("planes = %d, want both authorities", len(got[0].Planes))
	}
}

// A round with fewer than two authorities compares an authority to nothing. It
// must be DROPPED, not scheduled: it produces no witness and would make the
// served report claim collecting=true on a deployment that still compares
// nothing — which is the exact illusion AUD-1 is about.
func TestARoundWithNothingToCompareIsNotScheduled(t *testing.T) {
	t.Parallel()
	for _, s := range []config.ReconcileSchedule{
		{TenantID: "t1", Authorities: []config.ReconcileAuthority{{AuthorityID: "adcs"}}},
		{TenantID: "t1"},
		{Authorities: []config.ReconcileAuthority{{AuthorityID: "a"}, {AuthorityID: "b"}}},
		{TenantID: "t1", Authorities: []config.ReconcileAuthority{{AuthorityID: "adcs"}, {AuthorityID: "  "}}},
	} {
		if got := reconcileSchedulesFromConfig(config.Reconcile{Schedules: []config.ReconcileSchedule{s}}); len(got) != 0 {
			t.Fatalf("%+v was scheduled. Comparing an authority to itself is not reconciliation, "+
				"and scheduling it would make the agreement report say it is collecting while "+
				"nothing is compared", s)
		}
	}
}

// A zero cadence would busy-loop the scheduler and a zero liveness would make
// every authority instantly stale. Unparseable values take a sane default
// rather than zero.
func TestAnUnparseableCadenceDoesNotBusyLoopTheScheduler(t *testing.T) {
	t.Parallel()
	got := reconcileSchedulesFromConfig(config.Reconcile{Schedules: []config.ReconcileSchedule{{
		TenantID: "t1", Cadence: "not-a-duration", Liveness: "0s",
		Authorities: []config.ReconcileAuthority{{AuthorityID: "a"}, {AuthorityID: "b"}},
	}}})
	if len(got) != 1 {
		t.Fatal("the schedule was dropped for a bad duration; the authorities are still valid")
	}
	if got[0].Cadence <= 0 {
		t.Fatalf("cadence = %v; a zero cadence busy-loops the scheduler against a customer's "+
			"authorities", got[0].Cadence)
	}
	if got[0].Liveness <= 0 {
		t.Fatalf("liveness = %v; a zero liveness marks every authority instantly stale, so every "+
			"round would raise staleness witnesses that mean nothing", got[0].Liveness)
	}
}

// An absent config schedules nothing rather than panicking.
func TestNoReconcileConfigSchedulesNothing(t *testing.T) {
	t.Parallel()
	if got := reconcileSchedulesFromConfig(reconcileConfigOf(nil)); len(got) != 0 {
		t.Fatalf("a nil config produced %d schedules", len(got))
	}
}
