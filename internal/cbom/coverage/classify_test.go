// SPDX-License-Identifier: MPL-2.0

package coverage

import (
	"testing"
	"time"
)

func at(t time.Time) *time.Time { return &t }

// TestClassifyKnownEstate is the golden fixture: a known estate with one
// source in every interesting state, and the exact bucket asserted per class.
// A source whose envelope drifts from its behaviour changes a bucket here and
// breaks the build.
func TestClassifyKnownEstate(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	estate := []SourceState{
		{SourceID: "s1", Kind: "network", Name: "dc-ranges",
			LastRunStatus: RunSucceeded, LastCompletedAt: at(now.Add(-2 * time.Hour))},
		{SourceID: "s2", Kind: "ssh", Name: "prod-hosts",
			LastRunStatus: RunSucceeded, LastCompletedAt: at(now.Add(-48 * time.Hour))}, // stale
		{SourceID: "s3", Kind: "cloud_certificate", Name: "aws-acm",
			LastRunStatus: "failed", LastCompletedAt: at(now.Add(-1 * time.Hour))},
		{SourceID: "s4", Kind: "api_key", Name: "gh-tokens"}, // never ran
		{SourceID: "s5", Kind: "widget", Name: "hand-audit", // unknown kind -> manual
			LastRunStatus: RunSucceeded, LastCompletedAt: at(now.Add(-1 * time.Hour))},
	}

	rep := Classify(now, estate)

	got := map[AssetClass]ClassCoverage{}
	for _, c := range rep.Classes {
		got[c.Class] = c
	}

	// Every declared class and every structural class appears exactly once.
	if want := len(got); want != len(rep.Classes) {
		t.Fatalf("duplicate classes in report: %d rows, %d distinct", len(rep.Classes), want)
	}

	assertStatus := func(class AssetClass, want Status) ClassCoverage {
		t.Helper()
		c, ok := got[class]
		if !ok {
			t.Fatalf("class %q missing from report", class)
		}
		if c.Status != want {
			t.Fatalf("class %q status = %q, want %q (reason %q)", class, c.Status, want, c.Reason)
		}
		return c
	}

	// Fresh network run: both its classes observed, attributed, timestamped.
	tls := assertStatus(AssetTLSEndpoint, StatusObserved)
	if len(tls.ObservedBy) != 1 || tls.ObservedBy[0] != "dc-ranges" {
		t.Errorf("tls-endpoint observed by %v, want [dc-ranges]", tls.ObservedBy)
	}
	if tls.LastObservedAt == nil || !tls.LastObservedAt.Equal(now.Add(-2*time.Hour)) {
		t.Errorf("tls-endpoint last observed %v, want 2h ago", tls.LastObservedAt)
	}
	assertStatus(AssetCertificateKey, StatusObserved)

	// Stale success: unobserved, and the reason names the source, its
	// completion time, and the freshness window; the action re-runs it.
	ssh := assertStatus(AssetSSHHostKey, StatusUnobserved)
	if ssh.Reason == "" || ssh.Action != `re-run discovery source "prod-hosts"` {
		t.Errorf("stale ssh reason/action = %q / %q", ssh.Reason, ssh.Action)
	}

	// Failed run: unobserved with the failing status named.
	acm := assertStatus(AssetCloudCertificate, StatusUnobserved)
	if acm.Reason != `last run of "aws-acm" finished "failed", not "succeeded"` {
		t.Errorf("failed reason = %q", acm.Reason)
	}

	// Configured but never run.
	tok := assertStatus(AssetAPIKeyToken, StatusUnobserved)
	if tok.Action != `run discovery source "gh-tokens"` {
		t.Errorf("never-ran action = %q", tok.Action)
	}

	// No source at all: the action names the kind and its preconditions.
	ct := assertStatus(AssetCTExposedCertificate, StatusUnobserved)
	if ct.Reason != "no configured source observes this class" {
		t.Errorf("no-source reason = %q", ct.Reason)
	}
	if want := "configure a discovery source of kind ct_log (needs: monitored-domains-configured)"; ct.Action != want {
		t.Errorf("no-source action = %q, want %q", ct.Action, want)
	}

	// Unknown kind resolved to the manual envelope and observed its class.
	man := assertStatus(AssetOperatorDeclared, StatusObserved)
	if len(man.ObservedBy) != 1 || man.ObservedBy[0] != "hand-audit" {
		t.Errorf("manual observed by %v", man.ObservedBy)
	}

	// Every structurally-unobservable class is present, stated, and reasoned.
	structural := 0
	for _, u := range StructurallyUnobservable() {
		c := assertStatus(u.Class, StatusStructural)
		if c.Reason == "" {
			t.Errorf("structural class %q has no stated reason", u.Class)
		}
		structural++
	}
	if rep.Structural != structural {
		t.Errorf("structural count = %d, want %d", rep.Structural, structural)
	}
	if rep.Observed+rep.Unobserved+rep.Structural != len(rep.Classes) {
		t.Errorf("summary %d+%d+%d does not cover %d classes",
			rep.Observed, rep.Unobserved, rep.Structural, len(rep.Classes))
	}
}

// TestEnvelopeRegistryShape pins structural properties of the registry: every
// envelope observes at least one class, declares at least one precondition,
// and carries a positive freshness window; every declared class is reachable
// from some envelope; and no structural class collides with a declared one —
// a class cannot be both observable and structurally unobservable.
func TestEnvelopeRegistryShape(t *testing.T) {
	envs := Envelopes()
	if len(envs) == 0 {
		t.Fatal("empty envelope registry")
	}
	declared := map[AssetClass]bool{}
	for kind, e := range envs {
		if e.Kind != kind {
			t.Errorf("envelope %q carries kind %q", kind, e.Kind)
		}
		if len(e.Observes) == 0 {
			t.Errorf("envelope %q observes nothing", kind)
		}
		if len(e.Preconditions) == 0 {
			t.Errorf("envelope %q declares no preconditions", kind)
		}
		if e.Freshness <= 0 {
			t.Errorf("envelope %q has no freshness window", kind)
		}
		for _, c := range e.Observes {
			declared[c] = true
		}
	}
	for _, u := range StructurallyUnobservable() {
		if u.Reason == "" {
			t.Errorf("unobservable class %q has no reason", u.Class)
		}
		if declared[u.Class] {
			t.Errorf("class %q is declared observable by an envelope AND structurally unobservable", u.Class)
		}
	}
	if _, ok := envs[ManualKind]; !ok {
		t.Error("no manual fallback envelope")
	}
}
