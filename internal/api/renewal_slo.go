// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"
	"strconv"
)

// Renewal success SLO and error budget (epic D6).
//
// Renewal is the one thing this product must not get wrong quietly. Every other
// surface reports posture — what is configured, what was deployed, what is
// being served — and none of them answers "is the automation actually keeping
// up". An SLO does, and it is the number that tells an operator whether to
// trust the rest.
//
// Both the window and the target are inputs rather than constants. A 99.9%
// target over 30 days and a 99% target over 7 days are different promises, and
// serving compliance against a standard nobody agreed to would be a claim about
// someone else's commitments.

// RenewalSLO is the served response.
type RenewalSLO struct {
	WindowDays    int     `json:"window_days"`
	TargetPercent float64 `json:"target_percent"`
	// Total counts only renewals that reached a terminal state in the window.
	// An in-flight renewal is neither a success nor a failure, and forcing it
	// into either would move the number for reasons unrelated to reliability.
	Total     int `json:"total"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	// ObservedPercent is the achieved rate. An idle window reports 100 rather
	// than 0: nothing was due, which is not a breach.
	ObservedPercent float64 `json:"observed_percent"`
	// BudgetRemainingPercent is how much of the allowed failure budget is left,
	// clamped to 0-100. A figure like -340% is not more actionable than none
	// left, and the raw counts sit beside it.
	BudgetRemainingPercent float64 `json:"budget_remaining_percent"`
	Breached               bool    `json:"breached"`
	Guidance               string  `json:"guidance"`
}

const renewalSLOGuidance = "Only renewals that reached a terminal state inside the window are counted; " +
	"one still executing is neither a success nor a failure. A window in which nothing was due reports 100% " +
	"rather than 0% — an estate with no renewals pending is not in breach, and paging on the absence of work " +
	"is how a team learns to ignore an SLO. Error-budget burn is clamped at zero because a large negative " +
	"number is not more actionable than none-remaining."

func (a *API) getRenewalSLO(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "renewal SLO is not configured"))
		return
	}
	// Defaults are conservative rather than flattering: 30 days is long enough
	// that a single bad night does not dominate, and 99% is a target most
	// estates can actually hold, so a breach means something.
	windowDays := 30
	if v := r.URL.Query().Get("window_days"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 365 {
			windowDays = parsed
		}
	}
	target := 99.0
	if v := r.URL.Query().Get("target_percent"); v != "" {
		if parsed, err := strconv.ParseFloat(v, 64); err == nil && parsed > 0 && parsed <= 100 {
			target = parsed
		}
	}

	slo, err := a.store.SummarizeRenewalSLO(r.Context(), tenantID, windowDays, target)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, RenewalSLO{
		WindowDays: slo.WindowDays, TargetPercent: slo.TargetPercent,
		Total: slo.Total, Succeeded: slo.Succeeded, Failed: slo.Failed,
		ObservedPercent:        slo.ObservedPercent,
		BudgetRemainingPercent: slo.BudgetRemainingPercent,
		Breached:               slo.Breached(),
		Guidance:               renewalSLOGuidance,
	})
}
