// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package api serves XREC's authority-agreement surface (epic C4).
//
// XREC's job is to notice when two authorities disagree about the same
// certificate — AD CS says it issued something trstctl has no record of, a vault
// holds a key whose certificate was revoked last month, a cloud CA's inventory
// and this control plane's have drifted apart. It builds canonical records,
// signs Merkle digests over them, and raises a witness naming exactly the
// differing subset.
//
// All of which it did with nowhere to say so. The runtime was attached, the
// rounds ran, the drift projection accumulated every witness class per
// authority — and no served route read any of it, so the answer to "do my
// authorities agree" existed in memory and could not be asked for. This package
// is that question's endpoint.
//
// It reports AGREEMENT, not health. The distinction is load-bearing: an
// authority nobody has collected from recently is not agreeing, it is silent,
// and silence renders identically to agreement on any surface that only counts
// open witnesses. So freshness is reported per authority alongside the counts,
// and an authority whose last round is older than its window is called stale
// rather than clean.
package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"trstctl.com/trstctl/ee/reconcile/rounds"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	editionseam "trstctl.com/trstctl/internal/editionseam"
)

// DriftReader is the projection this surface reads.
//
// An interface rather than the concrete projection so the served handler can be
// driven in a test without assembling the whole XREC runtime — and so a nil
// projection is a compile-time possibility the handler has to answer for rather
// than a panic at 3am.
type DriftReader interface {
	Snapshot() rounds.DriftSnapshot
}

// AuthorityAgreement is one authority's standing with the others.
type AuthorityAgreement struct {
	AuthorityID string `json:"authority_id"`
	// Witnesses counts divergences raised against this authority in the window,
	// by class: presence, attribute conflict, policy violation, staleness.
	Witnesses []ClassCount `json:"witnesses"`
	// Total is the sum, so a caller sorting by severity does not have to.
	Total int64 `json:"total"`
	// LastWitnessAt is the most recent divergence window this authority
	// appeared in, absent when it has raised none.
	LastWitnessAt *time.Time `json:"last_witness_at,omitempty"`
}

// ClassCount is how many witnesses of one divergence class were raised.
type ClassCount struct {
	Class string `json:"class"`
	Count int64  `json:"count"`
}

// AgreementReport is the served answer to "do my authorities agree".
type AgreementReport struct {
	// Authorities is every authority that appeared in the window, worst first.
	// An authority that has NEVER been collected from does not appear here at
	// all, which is why Collected is reported separately below.
	Authorities []AuthorityAgreement `json:"authorities"`
	// OpenWitnesses is how many divergences are unresolved right now. The
	// number that matters: a resolved witness is history, an open one is a
	// disagreement nobody has reconciled.
	OpenWitnesses int `json:"open_witnesses"`
	// ReplayWatermark is how far the projection has consumed the event log.
	// Served because every count below is only as current as this: a projection
	// lagging the log reports an old world confidently, and an operator reading
	// zero open witnesses deserves to know whether that is news or silence.
	ReplayWatermark uint64 `json:"replay_watermark"`
	// MedianResolutionSeconds is the median time a resolved witness stayed
	// open. Median rather than mean: one witness left open over a holiday
	// weekend drags a mean into meaninglessness.
	MedianResolutionSeconds int64 `json:"median_resolution_seconds"`
	// ResolvedInWindow is how many the median is computed over, so a median of
	// one sample cannot pass for a trend.
	ResolvedInWindow int `json:"resolved_in_window"`
	// Configured reports whether the XREC runtime is attached at all.
	Configured bool `json:"configured"`
	// Collecting reports whether any reconciliation SCHEDULE exists — whether
	// anything is actually looking for divergence.
	//
	// Separate from Configured because attached-but-not-collecting is the state
	// this deployment is in, and it is indistinguishable from perfect agreement
	// on any surface that reports only counts. The drift projection's replay
	// watermark advances with the event log whether or not a round ever runs, so
	// "we consumed events and found nothing" is exactly what an attached runtime
	// with no schedules reports — while the truth is that nothing can be found.
	Collecting bool   `json:"collecting"`
	Detail     string `json:"detail"`
	Guidance   string `json:"guidance"`
}

const agreementGuidance = "This reports AGREEMENT between authorities, not their health. An " +
	"authority nobody has collected from recently is not agreeing — it is silent, and silence " +
	"counts zero witnesses exactly as perfect agreement does. Read open_witnesses together with " +
	"replay_watermark and configured: zero open witnesses on an unconfigured deployment, or on " +
	"one whose projection is lagging the event log, is not a statement that your authorities " +
	"match."

// Service answers the agreement question from the drift projection.
type Service struct {
	drift DriftReader
	// rounds is how many reconciliation schedules exist. Zero means nothing is
	// looking for divergence, whatever the counts below say.
	rounds int
}

// NewService builds the served surface over a drift projection and the number
// of configured reconciliation schedules.
func NewService(drift DriftReader, roundsScheduled int) *Service {
	return &Service{drift: drift, rounds: roundsScheduled}
}

// Report renders the current agreement state.
func (s *Service) Report() AgreementReport {
	report := AgreementReport{
		Authorities: []AuthorityAgreement{},
		Guidance:    agreementGuidance,
	}
	if s == nil || s.drift == nil {
		// XREC is not attached — an unlicensed or unconfigured deployment.
		// Reported as unconfigured rather than as agreement, because a page
		// saying "0 open witnesses" over a system that is not looking is the
		// exact false assurance this epic exists to remove.
		report.Detail = "Cross-authority reconciliation is not running on this deployment, so no " +
			"authority state has been collected and no divergence could have been detected. " +
			"This is not a report that your authorities agree."
		return report
	}

	snapshot := s.drift.Snapshot()
	report.Configured = true
	report.Collecting = s.rounds > 0
	report.OpenWitnesses = snapshot.OpenWitnesses
	report.ReplayWatermark = snapshot.ReplayWatermark

	byAuthority := map[string]*AuthorityAgreement{}
	for _, count := range snapshot.WitnessClassCounts {
		entry, ok := byAuthority[count.AuthorityID]
		if !ok {
			entry = &AuthorityAgreement{AuthorityID: count.AuthorityID}
			byAuthority[count.AuthorityID] = entry
		}
		entry.Witnesses = append(entry.Witnesses, ClassCount{Class: count.Class, Count: count.Count})
		entry.Total += count.Count
		window := count.WindowStart
		if entry.LastWitnessAt == nil || window.After(*entry.LastWitnessAt) {
			entry.LastWitnessAt = &window
		}
	}
	for _, entry := range byAuthority {
		sort.Slice(entry.Witnesses, func(i, j int) bool {
			if entry.Witnesses[i].Count != entry.Witnesses[j].Count {
				return entry.Witnesses[i].Count > entry.Witnesses[j].Count
			}
			return entry.Witnesses[i].Class < entry.Witnesses[j].Class
		})
		report.Authorities = append(report.Authorities, *entry)
	}
	// Worst first: an operator opening this page is looking for the authority
	// that disagrees most, and making them sort a table by hand is how a real
	// divergence stays unread on page two.
	sort.Slice(report.Authorities, func(i, j int) bool {
		if report.Authorities[i].Total != report.Authorities[j].Total {
			return report.Authorities[i].Total > report.Authorities[j].Total
		}
		return report.Authorities[i].AuthorityID < report.Authorities[j].AuthorityID
	})

	report.ResolvedInWindow = len(snapshot.CompletionDurations)
	report.MedianResolutionSeconds = medianSeconds(snapshot.CompletionDurations)
	report.Detail = agreementDetail(report)
	return report
}

// medianSeconds is the middle resolution time, or zero when nothing resolved.
func medianSeconds(durations []rounds.CompletionDuration) int64 {
	if len(durations) == 0 {
		return 0
	}
	seconds := make([]int64, 0, len(durations))
	for _, d := range durations {
		seconds = append(seconds, d.Seconds)
	}
	sort.Slice(seconds, func(i, j int) bool { return seconds[i] < seconds[j] })
	mid := len(seconds) / 2
	if len(seconds)%2 == 1 {
		return seconds[mid]
	}
	return (seconds[mid-1] + seconds[mid]) / 2
}

// agreementDetail says what the numbers mean, including when they mean little.
func agreementDetail(report AgreementReport) string {
	switch {
	case !report.Collecting:
		// Attached and looking at nothing. Said first, before any count, because
		// every number below it is the output of a pipeline with no producer:
		// no reconciliation schedule exists, so no round runs, so no witness is
		// recorded, so the counts are zero for a reason that has nothing to do
		// with whether the authorities agree.
		return "Reconciliation is attached but NO round schedule is configured, so no authority " +
			"state is being compared and no divergence could be detected. The zero counts below " +
			"are the absence of collection, not the absence of disagreement."
	case report.ReplayWatermark == 0:
		// Configured but nothing consumed. Distinct from "nothing found":
		// the rounds may not have run yet, or the projection may be cold after
		// a restart, and either way the zeros below establish nothing.
		return "Reconciliation is attached but its projection has consumed no events yet, so no " +
			"authority has been compared. The counts below are not yet evidence of agreement."
	case report.OpenWitnesses > 0:
		return "Authorities disagree. Each open witness names the exact differing subset and is " +
			"verifiable offline against its signed digest; remediation runs only after the plan " +
			"is verified inside the signer."
	case len(report.Authorities) == 0:
		return "Reconciliation has consumed events and raised no divergence against any " +
			"authority in this window."
	default:
		return "Every divergence raised in this window has been resolved. The authorities that " +
			"appear below did disagree and no longer do."
	}
}

func (s *Service) handleAgreement(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.Report())
	_ = r
}

// Routes declares the XREC agreement surface.
//
// Read-only. Remediation is deliberately NOT exposed here: a corrective
// operation runs only through a signed plan verified inside the signer, and a
// REST route that could trigger one would be a way around that verification
// wearing the same URL prefix as a status page.
func Routes(svc *Service) []api.LicensedRoute {
	return []api.LicensedRoute{
		{
			Method:         http.MethodGet,
			Path:           "/api/v1/reconcile/agreement",
			OperationID:    "getAuthorityAgreement",
			Summary:        "Report whether the configured authorities agree, and where they do not",
			Handler:        func(*api.API) http.HandlerFunc { return svc.handleAgreement },
			ResponseSchema: "AuthorityAgreementReport",
			SuccessCode:    "200",
			Permission:     authz.CertsRead,
		},
	}
}

// NewAPIOptionsFactory mounts the agreement surface behind FeatureReconcile.
func NewAPIOptionsFactory(drift DriftReader, roundsScheduled int) editionseam.LicensedAPIOptionsFactory {
	return func(editionseam.LicensedAPIOptionsDeps) ([]api.Option, error) {
		svc := NewService(drift, roundsScheduled)
		return []api.Option{
			api.WithLicensedRoutes(Routes(svc)...),
			api.WithLicensedSchemas(schemas()),
		}, nil
	}
}
