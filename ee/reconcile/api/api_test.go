// SPDX-License-Identifier: LicenseRef-trstctl-EE

package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	reconcileapi "trstctl.com/trstctl/ee/reconcile/api"
	"trstctl.com/trstctl/ee/reconcile/rounds"
)

// The agreement surface's job is to never let silence read as agreement (C4).
//
// XREC can detect that two authorities disagree about the same certificate. Up
// to this epic it had nowhere to say so: the drift projection accumulated every
// witness and no served route read it. The danger in fixing that is a page
// showing "0 open witnesses" over a deployment where reconciliation is not
// running, has not consumed any events, or has never been configured — three
// states that render identically to perfect agreement unless the surface is
// built to keep them apart.

type fakeDrift struct{ snap rounds.DriftSnapshot }

func (f fakeDrift) Snapshot() rounds.DriftSnapshot { return f.snap }

func TestAnUnconfiguredDeploymentIsNotReportedAsAgreeing(t *testing.T) {
	t.Parallel()
	// No drift projection: XREC is unlicensed or unattached.
	report := reconcileapi.NewService(nil, 0).Report()
	if report.Configured {
		t.Fatal("a deployment with no reconciliation runtime reported itself configured")
	}
	if report.OpenWitnesses != 0 || len(report.Authorities) != 0 {
		t.Fatal("an unconfigured deployment invented reconciliation state")
	}
	if !strings.Contains(report.Detail, "not a report that your authorities agree") {
		t.Fatalf("detail must refuse the agreement reading; got %q", report.Detail)
	}
}

// Configured but cold. The projection has consumed nothing, so its zeros
// establish nothing — and saying so is the difference between "we looked and
// found nothing" and "we have not looked".
func TestAColdProjectionSaysItsZerosAreNotYetEvidence(t *testing.T) {
	t.Parallel()
	report := reconcileapi.NewService(fakeDrift{}, 1).Report()
	if !report.Configured {
		t.Fatal("an attached runtime reported itself unconfigured")
	}
	if report.ReplayWatermark != 0 {
		t.Fatalf("watermark = %d, want 0", report.ReplayWatermark)
	}
	if !strings.Contains(report.Detail, "not yet evidence") {
		t.Fatalf("a cold projection must say its counts prove nothing; got %q", report.Detail)
	}
}

func TestDivergenceIsReportedWorstAuthorityFirst(t *testing.T) {
	t.Parallel()
	window := time.Date(2026, 8, 5, 9, 0, 0, 0, time.UTC)
	svc := reconcileapi.NewService(fakeDrift{snap: rounds.DriftSnapshot{
		ReplayWatermark: 4211,
		OpenWitnesses:   3,
		WitnessClassCounts: []rounds.WitnessClassCount{
			{AuthorityID: "adcs-eu", Class: "presence", Count: 2, WindowStart: window},
			{AuthorityID: "vault-prod", Class: "attribute_conflict", Count: 9, WindowStart: window},
			{AuthorityID: "vault-prod", Class: "policy_violation", Count: 4, WindowStart: window},
		},
		CompletionDurations: []rounds.CompletionDuration{
			{WitnessID: "w1", Seconds: 30}, {WitnessID: "w2", Seconds: 90}, {WitnessID: "w3", Seconds: 600},
		},
	}}, 1)
	report := svc.Report()

	if len(report.Authorities) != 2 {
		t.Fatalf("authorities = %d, want 2", len(report.Authorities))
	}
	// vault-prod has 13 witnesses to adcs-eu's 2 and must lead: an operator
	// opening this page is looking for the worst disagreement, and a real
	// divergence sorted onto page two is one nobody reads.
	if report.Authorities[0].AuthorityID != "vault-prod" || report.Authorities[0].Total != 13 {
		t.Fatalf("worst authority = %+v, want vault-prod with 13", report.Authorities[0])
	}
	// Within an authority, the largest class first, for the same reason.
	if report.Authorities[0].Witnesses[0].Class != "attribute_conflict" {
		t.Fatalf("classes not ordered by count: %+v", report.Authorities[0].Witnesses)
	}
	if report.OpenWitnesses != 3 {
		t.Fatalf("open witnesses = %d, want 3", report.OpenWitnesses)
	}
	// Median, not mean: 30/90/600 has a median of 90 and a mean of 240, and the
	// mean is the number one abandoned witness turns into a fiction.
	if report.MedianResolutionSeconds != 90 {
		t.Fatalf("median resolution = %d, want 90 (mean would be 240)", report.MedianResolutionSeconds)
	}
	if report.ResolvedInWindow != 3 {
		t.Fatalf("resolved sample size = %d, want 3", report.ResolvedInWindow)
	}
	if !strings.Contains(report.Detail, "Authorities disagree") {
		t.Fatalf("open witnesses must be stated plainly; got %q", report.Detail)
	}
}

// Resolved history must not read as an open problem, and an empty window must
// not read as one either.
func TestResolvedAndCleanWindowsAreDistinguished(t *testing.T) {
	t.Parallel()
	resolved := reconcileapi.NewService(fakeDrift{snap: rounds.DriftSnapshot{
		ReplayWatermark: 10, OpenWitnesses: 0,
		WitnessClassCounts: []rounds.WitnessClassCount{
			{AuthorityID: "adcs-eu", Class: "presence", Count: 1, WindowStart: time.Now().UTC()},
		},
	}}, 1).Report()
	if !strings.Contains(resolved.Detail, "did disagree and no longer do") {
		t.Fatalf("a window whose witnesses all closed must say so; got %q", resolved.Detail)
	}

	clean := reconcileapi.NewService(fakeDrift{snap: rounds.DriftSnapshot{ReplayWatermark: 10}}, 1).Report()
	if !strings.Contains(clean.Detail, "raised no divergence") {
		t.Fatalf("a genuinely clean window reads differently from a resolved one; got %q", clean.Detail)
	}
}

// The route is served, and it serves the report rather than something adjacent.
func TestTheAgreementRouteIsServedAndReadsTheProjection(t *testing.T) {
	t.Parallel()
	svc := reconcileapi.NewService(fakeDrift{snap: rounds.DriftSnapshot{
		ReplayWatermark: 7, OpenWitnesses: 1,
		WitnessClassCounts: []rounds.WitnessClassCount{
			{AuthorityID: "gcp-cas", Class: "staleness", Count: 5, WindowStart: time.Now().UTC()},
		},
	}}, 1)
	routes := reconcileapi.Routes(svc)
	if len(routes) != 1 {
		t.Fatalf("routes = %d, want exactly one read-only surface", len(routes))
	}
	route := routes[0]
	if route.Method != http.MethodGet || route.Path != "/api/v1/reconcile/agreement" {
		t.Fatalf("route = %s %s, unexpected", route.Method, route.Path)
	}
	// Remediation must NOT be reachable here. A corrective operation runs only
	// through a plan verified inside the signer, and a REST route that could
	// start one would be a way around that verification wearing the same URL
	// prefix as a status page.
	if route.Mutation {
		t.Fatal("the agreement surface declares a mutation; remediation must not be reachable here")
	}

	rec := httptest.NewRecorder()
	route.Handler(nil)(rec, httptest.NewRequest(http.MethodGet, "/api/v1/reconcile/agreement", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var got reconcileapi.AgreementReport
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Configured || got.OpenWitnesses != 1 || got.ReplayWatermark != 7 {
		t.Fatalf("served body did not come from the projection: %+v", got)
	}
	if len(got.Authorities) != 1 || got.Authorities[0].AuthorityID != "gcp-cas" {
		t.Fatalf("served authorities = %+v", got.Authorities)
	}
	if got.Guidance == "" {
		t.Fatal("the served body carries no guidance, so a reader has only numbers")
	}
}

// Attached, consuming events, and looking at NOTHING.
//
// This is the state the shipped deployment is actually in, and it is the one
// the surface most nearly got wrong. rounds.Worker returns immediately when it
// has no schedules, and nothing calls witness.Recorder.RecordWitness in
// production — so no round runs and no witness is ever recorded. Meanwhile the
// drift projection's replay watermark advances with the event log like any
// projection.
//
// So every ingredient of "we looked carefully and your authorities agree" is
// present: attached, warm, zero open witnesses, no divergence. The one thing
// missing is anything doing the looking. Without the collecting signal this
// surface would have shipped that sentence, which is exactly the reassurance it
// was written to refuse — defeated one layer below where it was defending.
func TestAnAttachedRuntimeWithNoSchedulesSaysNothingIsLooking(t *testing.T) {
	t.Parallel()
	// Warm projection, no divergence, no schedules.
	report := reconcileapi.NewService(fakeDrift{snap: rounds.DriftSnapshot{
		ReplayWatermark: 9_000,
	}}, 0).Report()

	if !report.Configured {
		t.Fatal("an attached runtime reported itself unattached")
	}
	if report.Collecting {
		t.Fatal("a runtime with zero round schedules reported that it is collecting")
	}
	if strings.Contains(report.Detail, "raised no divergence") {
		t.Fatalf("the surface reported a clean result from a pipeline with no producer: %q\n\n"+
			"No schedule means no round, no round means no witness, and no witness means the "+
			"zero counts say nothing about whether the authorities agree.", report.Detail)
	}
	if !strings.Contains(report.Detail, "NO round schedule is configured") {
		t.Fatalf("detail must name the missing schedules; got %q", report.Detail)
	}
	if !strings.Contains(report.Detail, "absence of collection") {
		t.Fatalf("detail must refuse the agreement reading; got %q", report.Detail)
	}
}

// With schedules configured, a genuinely clean window still reads as clean —
// the collecting signal must not swallow the real answer.
func TestSchedulesConfiguredStillReportsAGenuinelyCleanWindow(t *testing.T) {
	t.Parallel()
	report := reconcileapi.NewService(fakeDrift{snap: rounds.DriftSnapshot{ReplayWatermark: 10}}, 3).Report()
	if !report.Collecting {
		t.Fatal("three schedules reported as not collecting")
	}
	if !strings.Contains(report.Detail, "raised no divergence") {
		t.Fatalf("a collecting deployment with a clean window must say so; got %q", report.Detail)
	}
}
