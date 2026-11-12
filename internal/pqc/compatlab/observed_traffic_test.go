// SPDX-License-Identifier: BUSL-1.1

package compatlab

import (
	"encoding/json"
	"strings"
	"testing"
)

// X3-L5: a cohort that requires observed traffic counts a negotiated client
// only once real clients were observed at its endpoint. The probe is one
// client — trstctl's own — so a pilot that advanced on it alone would certify
// a leaf no real client had used.
func TestAssessRequiresObservedTrafficX3L5(t *testing.T) {
	t.Parallel()
	negotiated := func(id, traffic string) Result {
		return Result{ClientID: id, Outcome: OutcomeNegotiated, HandshakeBytes: 4200, Traffic: traffic}
	}
	gated := func(rs ...Result) Cohort {
		return Cohort{Name: "canary", Targeted: []string{"a", "b"}, Results: rs, RequireObservedTraffic: true}
	}

	waiting := Assess(gated(negotiated("a", TrafficObserved), negotiated("b", "")))
	if waiting.Ready || waiting.Halt || waiting.AwaitingTraffic != 1 || waiting.Unobserved != 0 || waiting.Negotiated != 2 {
		t.Fatalf("a client still awaiting traffic = %+v; want not ready, not halted, one awaiting", waiting)
	}
	if !strings.HasPrefix(waiting.Summary, "AWAITING TRAFFIC") || !strings.Contains(waiting.Summary, "b") {
		t.Fatalf("awaiting summary = %q; want it to name the client still awaiting traffic", waiting.Summary)
	}

	silent := Assess(gated(negotiated("a", TrafficObserved), negotiated("b", TrafficUnobserved)))
	if silent.Ready || silent.Unobserved != 1 || silent.AwaitingTraffic != 0 || !strings.HasPrefix(silent.Summary, "NOT READY") ||
		!strings.Contains(silent.Summary, "observed-traffic window") {
		t.Fatalf("a window that ended with no traffic = %+v; want not ready naming the window", silent)
	}

	ready := Assess(gated(negotiated("a", TrafficObserved), negotiated("b", TrafficObserved)))
	if !ready.Ready || ready.AwaitingTraffic != 0 || ready.Unobserved != 0 || !strings.Contains(ready.Summary, "observed connecting at each") {
		t.Fatalf("every client observed = %+v; want ready", ready)
	}

	// A refusal still halts first: traffic never outranks a rejection.
	refused := Assess(gated(negotiated("a", TrafficObserved), Result{ClientID: "b", Outcome: OutcomeRejected}))
	if !refused.Halt || refused.AwaitingTraffic != 0 {
		t.Fatalf("a rejection under the traffic gate = %+v; want the halt", refused)
	}

	// Without the requirement a traffic mark changes nothing.
	plain := Assess(Cohort{Name: "canary", Targeted: []string{"a"}, Results: []Result{negotiated("a", "")}})
	if !plain.Ready || plain.AwaitingTraffic != 0 {
		t.Fatalf("a cohort without the requirement = %+v; want ready on the probe", plain)
	}
}

// The signed report carries the requirement and the marks so a reader
// re-derives the verdict, and a report from a pilot without the gate keeps
// exactly the bytes it had before X3-L5.
func TestReportCarriesTheObservedTrafficRequirementX3L5(t *testing.T) {
	t.Parallel()
	gated := Cohort{Name: "canary", Targeted: []string{"a"}, RequireObservedTraffic: true,
		Results: []Result{{ClientID: "a", Outcome: OutcomeNegotiated, Traffic: TrafficUnobserved}}}
	report, err := BuildReport("tenant-1", "pq-ca", gated, 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	body, err := report.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"require_observed_traffic":true`) || !strings.Contains(string(body), `"Traffic":"unobserved"`) ||
		!strings.Contains(string(body), `"Unobserved":1`) || report.Verdict.Ready {
		t.Fatalf("gated report body = %s", body)
	}
	var reread Report
	if err := json.Unmarshal(body, &reread); err != nil {
		t.Fatal(err)
	}
	again := Assess(Cohort{Name: reread.Cohort, Targeted: reread.Targeted, Results: reread.Results, RequireObservedTraffic: reread.RequireObservedTraffic})
	if again.Ready != reread.Verdict.Ready || again.Unobserved != reread.Verdict.Unobserved || again.Summary != reread.Verdict.Summary {
		t.Fatalf("re-derived verdict %+v differs from the signed one %+v", again, reread.Verdict)
	}

	plain, err := BuildReport("tenant-1", "pq-ca", Cohort{Name: "canary", Targeted: []string{"a"},
		Results: []Result{{ClientID: "a", Outcome: OutcomeNegotiated, HandshakeBytes: 10, LatencyMS: 2}}}, 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	plainBody, err := plain.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"spec_version":"pqc.compatlab/v1","tenant_id":"tenant-1","authority_id":"pq-ca","cohort":"canary","targeted":["a"],` +
		`"results":[{"ClientID":"a","Outcome":"negotiated","HandshakeBytes":10,"LatencyMS":2,"Detail":""}],` +
		`"verdict":{"Ready":true,"Halt":false,"Summary":"Ready: all 1 targeted clients negotiated the PQ leaf.","Negotiated":1,"Rejected":0,"Unreachable":0,"NotAttempted":0},` +
		`"generated_at":1700000000}`
	if string(plainBody) != want {
		t.Fatalf("a report without the gate changed its bytes:\n got %s\nwant %s", plainBody, want)
	}
}
