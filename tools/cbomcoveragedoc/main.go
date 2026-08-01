// SPDX-License-Identifier: MPL-2.0

// Command cbomcoveragedoc generates docs/design/cbom-coverage.md from the
// coverage model itself (WS-1 card A9).
//
// The page is generated rather than written for the same reason the claim
// traceability table and the CWE register are: a design doc that restates a
// registry by hand drifts from it silently. This program imports
// internal/cbom/coverage and reads the real Envelopes() and
// StructurallyUnobservable() registries, then computes the bucket counts by
// running the real Classify() over a fixed fixture estate. Add a source kind,
// an asset class, or an unobservable class and the page changes; forget to
// regenerate and `-check` fails the build.
//
// The fixture clock is a compile-time constant so the output is byte-stable —
// nothing here reads the wall clock.
//
// Usage:
//
//	go run ./tools/cbomcoveragedoc           # write docs/design/cbom-coverage.md
//	go run ./tools/cbomcoveragedoc -check    # fail if the committed page is stale
//	go run ./tools/cbomcoveragedoc -out PATH # write elsewhere (self-test hook)
//
// Exit codes: 0 ok · 1 stale (-check) or write failure · 2 usage error.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/cbom/coverage"
)

const outPathDefault = "docs/design/cbom-coverage.md"

// fixtureNow is the fixed clock the worked example is computed at. A constant,
// not time.Now(), so regenerating the page twice produces identical bytes.
var fixtureNow = time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

// fixtureEstate is a deliberately small estate exercising all four UNOBSERVED
// reasons plus a fresh OBSERVED run, so the worked example below demonstrates
// every branch of the classifier rather than only the happy one.
func fixtureEstate() []coverage.SourceState {
	fresh := fixtureNow.Add(-2 * time.Hour)
	stale := fixtureNow.Add(-72 * time.Hour)
	return []coverage.SourceState{
		{SourceID: "s1", Kind: "network", Name: "dc-east", LastRunStatus: coverage.RunSucceeded, LastCompletedAt: &fresh},
		{SourceID: "s2", Kind: "ssh", Name: "bastions", LastRunStatus: coverage.RunSucceeded, LastCompletedAt: &stale},
		{SourceID: "s3", Kind: "ct_log", Name: "ct-watch", LastRunStatus: "failed", LastCompletedAt: &fresh},
		{SourceID: "s4", Kind: "cloud_certificate", Name: "acm-prod", LastRunStatus: ""},
	}
}

func main() {
	check := flag.Bool("check", false, "fail if the committed page differs from freshly generated output")
	out := flag.String("out", outPathDefault, "output path")
	flag.Parse()

	rendered := render()

	if *check {
		current, err := os.ReadFile(*out) // #nosec G304 -- operator/CI-supplied path to this repo's own generated page (CWE-22)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cbom coverage doc: %s is missing — run 'go run ./tools/cbomcoveragedoc' and commit the result\n", *out)
			os.Exit(1)
		}
		if string(current) != rendered {
			fmt.Fprintf(os.Stderr, "cbom coverage doc: %s is stale — run 'go run ./tools/cbomcoveragedoc' and commit the result\n", *out)
			os.Exit(1)
		}
		fmt.Printf("cbom coverage doc: %s is current\n", *out)
		return
	}

	if err := os.WriteFile(*out, []byte(rendered), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "cbom coverage doc: write %s: %v\n", *out, err)
		os.Exit(1)
	}
	fmt.Printf("cbom coverage doc: wrote %s\n", *out)
}

func render() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	envs := coverage.Envelopes()
	kinds := make([]string, 0, len(envs))
	for k := range envs {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)

	unobservable := coverage.StructurallyUnobservable()
	report := coverage.Classify(fixtureNow, fixtureEstate())

	declared := map[coverage.AssetClass]bool{}
	for _, e := range envs {
		for _, c := range e.Observes {
			declared[c] = true
		}
	}

	w("<!-- GENERATED FILE — do not edit by hand.")
	w("     Regenerate: go run ./tools/cbomcoveragedoc")
	w("     CI verifies freshness with -check (make cbom-docs-check). -->")
	w("")
	w("# Computed cryptographic discovery coverage")
	w("")
	w("Discovery tools all answer \"what did you find.\" This one also answers")
	w("**\"how would you know what you missed.\"** Every discovery source the server")
	w("can execute declares an *observability envelope* — the asset classes it can")
	w("see, what the deployment must provide before it can run, and how long an")
	w("observation stays current. The estate is then sorted into three buckets, so a")
	w("gap is a row with a reason instead of an absence nobody notices.")
	w("")
	w("This page is generated from the model. The tables below are read out of")
	w("`internal/cbom/coverage` at generation time and the numbers are computed by")
	w("running the real classifier over a fixed fixture estate — so the page cannot")
	w("describe a registry the code does not have.")
	w("")

	w("## The three buckets")
	w("")
	w("| Bucket | Means | What closes it |")
	w("|---|---|---|")
	w("| `%s` | A source whose envelope covers the class completed a run inside its freshness window | nothing — this is the good case |", coverage.StatusObserved)
	w("| `%s` | The class is inside some configured source's envelope, but no run has covered it | the per-row action: configure, fix, or re-run the named source |", coverage.StatusUnobserved)
	w("| `%s` | No configured source can ever observe this class | a new source kind, or an honest statement that trstctl does not cover it |", coverage.StatusStructural)
	w("")
	w("The headline number is coverage, not asset count. An `%s` row always", coverage.StatusUnobserved)
	w("carries both the specific reason and the action that would close it; a")
	w("`%s` row names the class and states plainly that no served", coverage.StatusStructural)
	w("source covers it.")
	w("")

	w("## Observability envelopes — %d served source kinds", len(kinds))
	w("")
	w("The authoritative catalog is the **served executor set**: the source kinds the")
	w("server can actually run when an operator queues a discovery run")
	w("(`discoveryRunExecutors` in `internal/server/discovery.go`). Coverage is a claim")
	w("about what this deployment can do, not about which interfaces exist in the")
	w("library. `TestEveryDiscoverySourceDeclaresEnvelope` welds this registry to that")
	w("catalog in both directions — a served kind with no envelope and an envelope for")
	w("a kind the server cannot execute both fail the build — so the table below is the")
	w("served set by construction.")
	w("")
	w("| Source kind | Observes | Preconditions | Freshness |")
	w("|---|---|---|---|")
	for _, k := range kinds {
		e := envs[k]
		classes := make([]string, 0, len(e.Observes))
		for _, c := range e.Observes {
			classes = append(classes, "`"+string(c)+"`")
		}
		pre := make([]string, 0, len(e.Preconditions))
		for _, p := range e.Preconditions {
			pre = append(pre, "`"+string(p)+"`")
		}
		sort.Strings(classes)
		sort.Strings(pre)
		w("| `%s` | %s | %s | %s |", k, strings.Join(classes, ", "), strings.Join(pre, ", "), e.Freshness)
	}
	w("")
	w("`%s` is the served fallback: a source of any kind with no dedicated", coverage.ManualKind)
	w("connector records operator-supplied findings, and its envelope says exactly")
	w("that — the operator's own declarations, nothing observed by trstctl itself.")
	w("")

	w("## Structurally unobservable classes — %d", len(unobservable))
	w("")
	w("These are the honest edges of the product. They are enumerated **in code**")
	w("(`internal/cbom/coverage/unobservable.go`), not in prose, and a class added")
	w("without a stated reason fails `TestEnvelopeRegistryShape`. A class cannot be")
	w("both observable and structurally unobservable — that contradiction fails the")
	w("same test.")
	w("")
	w("| Class | Why no configured source can observe it |")
	w("|---|---|")
	for _, u := range unobservable {
		w("| `%s` | %s |", u.Class, u.Reason)
	}
	w("")

	w("## Worked example")
	w("")
	w("Computed by running `coverage.Classify` over a four-source fixture estate at a")
	w("fixed clock, exercising every UNOBSERVED branch. This is the generator's own")
	w("output, not an illustration.")
	w("")
	w("Estate: a `network` source that succeeded 2h ago, an `ssh` source whose last")
	w("success was 72h ago (past its %s window), a `ct_log` source whose last run", coverage.DefaultFreshness)
	w("failed, and a `cloud_certificate` source that has never completed a run.")
	w("")
	w("**%d observed · %d observable-unobserved · %d structurally unobservable** across %d classes.",
		report.Observed, report.Unobserved, report.Structural, len(report.Classes))
	w("")
	w("| Class | Bucket | Reason / attribution |")
	w("|---|---|---|")
	for _, c := range report.Classes {
		detail := ""
		switch c.Status {
		case coverage.StatusObserved:
			detail = "observed by " + strings.Join(c.ObservedBy, ", ")
		default:
			detail = strings.TrimSpace(c.Reason)
			if c.Action != "" {
				detail += " — **" + c.Action + "**"
			}
		}
		w("| `%s` | `%s` | %s |", c.Class, c.Status, detail)
	}
	w("")

	w("## What this does not prove")
	w("")
	w("An `%s` class means a source that declares it completed a run inside", coverage.StatusObserved)
	w("its freshness window. It does **not** mean every instance of that class in the")
	w("estate was found — a scan covers the ranges it was given, and coverage cannot")
	w("know about a subnet nobody declared. What the model does guarantee is that a")
	w("class no source can reach is named and reasoned rather than silently absent,")
	w("and that a source cannot claim reach it never declared.")
	w("")
	w("## How this page stays honest")
	w("")
	w("`make cbom-docs-check` regenerates this page and fails when the committed copy")
	w("differs. It runs in CI beside the claim-traceability and CWE-register checks.")
	w("Adding a source kind, an asset class, or an unobservable class without")
	w("regenerating is a red build.")

	return b.String()
}
