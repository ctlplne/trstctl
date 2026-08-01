// SPDX-License-Identifier: MPL-2.0

package coverage

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Status is a coverage bucket. Exactly three exist: the headline metric is
// which bucket each class is in and why, not an asset count.
type Status string

const (
	// StatusObserved: a source whose envelope covers the class completed a
	// successful run inside its freshness window.
	StatusObserved Status = "OBSERVED"
	// StatusUnobserved: some configured (or configurable) source's envelope
	// covers the class, but no fresh successful run has — the reason names
	// the specific gap and the action that closes it.
	StatusUnobserved Status = "OBSERVABLE-UNOBSERVED"
	// StatusStructural: no served source can ever observe the class; the
	// reason states it plainly.
	StatusStructural Status = "STRUCTURALLY-UNOBSERVABLE"
)

// RunSucceeded is the discovery-run status string that counts as a completed
// observation (matching the server's run lifecycle).
const RunSucceeded = "succeeded"

// SourceState is the per-source rollup the store projects from the
// discovery.source.upserted and discovery.run.completed events.
type SourceState struct {
	SourceID        string
	Kind            string
	Name            string
	LastRunStatus   string // "" when the source has never completed a run
	LastCompletedAt *time.Time
}

// ClassCoverage is one asset class's computed bucket.
type ClassCoverage struct {
	Class          AssetClass `json:"class"`
	Status         Status     `json:"status"`
	SourceKinds    []string   `json:"source_kinds,omitempty"`
	ObservedBy     []string   `json:"observed_by,omitempty"`
	LastObservedAt *time.Time `json:"last_observed_at,omitempty"`
	Reason         string     `json:"reason,omitempty"`
	Action         string     `json:"action,omitempty"`
}

// Report is the computed coverage for one tenant's estate.
type Report struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Observed    int             `json:"observed"`
	Unobserved  int             `json:"unobserved"`
	Structural  int             `json:"structurally_unobservable"`
	Classes     []ClassCoverage `json:"classes"`
}

// Classify computes the three-bucket coverage of a tenant's estate at now.
// Pure and deterministic: the clock is explicit, the envelope registry and
// unobservable set are compiled in, and the output ordering is stable.
func Classify(now time.Time, sources []SourceState) Report {
	envs := Envelopes()

	kindsByClass := map[AssetClass][]string{}
	for _, e := range envs {
		for _, c := range e.Observes {
			kindsByClass[c] = append(kindsByClass[c], e.Kind)
		}
	}
	for c := range kindsByClass {
		sort.Strings(kindsByClass[c])
	}

	// Unknown kinds resolve to the manual envelope, mirroring the server's
	// record-manual-findings fallback.
	byKind := map[string][]SourceState{}
	for _, s := range sources {
		kind := s.Kind
		if _, ok := envs[kind]; !ok {
			kind = ManualKind
		}
		byKind[kind] = append(byKind[kind], s)
	}

	classes := make([]AssetClass, 0, len(kindsByClass))
	for c := range kindsByClass {
		classes = append(classes, c)
	}
	sort.Slice(classes, func(i, j int) bool { return classes[i] < classes[j] })

	rep := Report{GeneratedAt: now}
	for _, class := range classes {
		kinds := kindsByClass[class]
		cc := ClassCoverage{Class: class, Status: StatusUnobserved, SourceKinds: kinds}

		var observedBy []string
		var lastObserved time.Time
		var staleSource, failedSource, neverRan *SourceState
		configured := 0
		for _, kind := range kinds {
			env := envs[kind]
			for i := range byKind[kind] {
				s := byKind[kind][i]
				configured++
				switch {
				case s.LastRunStatus == RunSucceeded && s.LastCompletedAt != nil &&
					now.Sub(*s.LastCompletedAt) <= env.Freshness:
					observedBy = append(observedBy, s.Name)
					if s.LastCompletedAt.After(lastObserved) {
						lastObserved = *s.LastCompletedAt
					}
				case s.LastRunStatus == RunSucceeded && s.LastCompletedAt != nil:
					staleSource = &byKind[kind][i]
				case s.LastRunStatus != "" && s.LastRunStatus != RunSucceeded:
					failedSource = &byKind[kind][i]
				default:
					neverRan = &byKind[kind][i]
				}
			}
		}

		switch {
		case len(observedBy) > 0:
			cc.Status = StatusObserved
			sort.Strings(observedBy)
			cc.ObservedBy = observedBy
			t := lastObserved
			cc.LastObservedAt = &t
			rep.Observed++
		case configured == 0:
			cc.Reason = "no configured source observes this class"
			cc.Action = fmt.Sprintf("configure a discovery source of kind %s (needs: %s)",
				strings.Join(kinds, " or "), preconditionsOf(envs, kinds))
			rep.Unobserved++
		case staleSource != nil:
			env := envs[resolveKind(envs, staleSource.Kind)]
			cc.Reason = fmt.Sprintf("last successful run of %q completed %s, older than the %s freshness window",
				staleSource.Name, staleSource.LastCompletedAt.UTC().Format(time.RFC3339), env.Freshness)
			cc.Action = fmt.Sprintf("re-run discovery source %q", staleSource.Name)
			rep.Unobserved++
		case failedSource != nil:
			cc.Reason = fmt.Sprintf("last run of %q finished %q, not %q",
				failedSource.Name, failedSource.LastRunStatus, RunSucceeded)
			cc.Action = fmt.Sprintf("fix and re-run discovery source %q", failedSource.Name)
			rep.Unobserved++
		default:
			cc.Reason = fmt.Sprintf("source %q is configured but has never completed a run", neverRan.Name)
			cc.Action = fmt.Sprintf("run discovery source %q", neverRan.Name)
			rep.Unobserved++
		}
		rep.Classes = append(rep.Classes, cc)
	}

	for _, u := range StructurallyUnobservable() {
		rep.Classes = append(rep.Classes, ClassCoverage{
			Class:  u.Class,
			Status: StatusStructural,
			Reason: u.Reason,
		})
		rep.Structural++
	}
	return rep
}

func resolveKind(envs map[string]Envelope, kind string) string {
	if _, ok := envs[kind]; ok {
		return kind
	}
	return ManualKind
}

func preconditionsOf(envs map[string]Envelope, kinds []string) string {
	seen := map[Precondition]bool{}
	var out []string
	for _, k := range kinds {
		for _, p := range envs[k].Preconditions {
			if !seen[p] {
				seen[p] = true
				out = append(out, string(p))
			}
		}
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}
