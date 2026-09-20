// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"
	"strconv"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// The unowned queue (epic I1).
//
// A high-priority queue rather than a report, and the difference is in what it
// refuses to average. Four reasons travel separately because they need four
// different actions: an identity with no owner is a data-entry gap, one whose
// owner carries no application or environment is a classification gap — it names
// a person and not a system, which is the wrong half for deciding blast radius —
// one whose ownership nobody has ever attested is a trust gap, and an expired
// attestation is a cadence gap. A single
// "unowned: 47" would be a number nobody can act on.

// UnownedIdentity is one row of the queue.
type UnownedIdentity struct {
	IdentityID string `json:"identity_id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	// Reason is from a closed set so a console can group and count without
	// parsing prose.
	Reason string `json:"reason"`
	// Detail says what would clear this row.
	Detail string `json:"detail"`
}

// UnownedQueue is the served queue.
type UnownedQueue struct {
	Items []UnownedIdentity `json:"items"`
	// Counts are per reason, not a total. A total would let a console render
	// one number and lose the only information that makes the queue actionable.
	Counts   map[string]int `json:"counts"`
	Total    int            `json:"total"`
	Guidance string         `json:"guidance"`
}

const unownedGuidance = "Every row is a managed identity whose ownership cannot answer an incident " +
	"question. The three reasons need different work and are kept apart deliberately: no_owner is a " +
	"missing record, owner_missing_application_model means somebody is named but no system is, and " +
	"ownership_never_attested means nobody has confirmed the named owner is still right. An empty " +
	"queue means every managed identity has an attested owner carrying an application and an " +
	"environment — it does not mean unmanaged credentials elsewhere in the estate have owners."

// unownedLimit reads the page size, bounded.
//
// Bounded here as well as in the store because an unbounded queue during an
// incident is a browser tab that stops responding at the moment it is needed.
func unownedLimit(r *http.Request) int {
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return 200
}

// unownedReasonDetail turns a closed-set reason into the action that clears it.
func unownedReasonDetail(reason string) string {
	switch reason {
	case store.UnownedNoOwner:
		return "no owner record is attached; assign one, or log an exception if this identity is " +
			"deliberately unowned"
	case store.UnownedIncompleteOwner:
		return "the owner names a person but no application or environment, so this identity " +
			"cannot be placed in a blast radius during an incident"
	case store.UnownedUnattested:
		return "nobody has confirmed this ownership is still correct; an owner recorded once and " +
			"never re-checked is the one most likely to have moved on"
	case store.UnownedStale:
		return "the last ownership confirmation is older than the configured cadence; re-attest " +
			"the application and environment before another steady-state deployment"
	default:
		return ""
	}
}

// listUnownedIdentities serves the queue.
func (a *API) listUnownedIdentities(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "ownership data is not configured"))
		return
	}
	rows, err := a.store.ListUnownedIdentitiesAt(
		r.Context(), tenantID, time.Now().UTC(), a.ownerAttestationCadence(), unownedLimit(r),
	)
	if err != nil {
		a.writeError(w, err)
		return
	}
	out := UnownedQueue{
		Items: make([]UnownedIdentity, 0, len(rows)),
		// Pre-seeded with every reason at zero, so a console renders three rows
		// rather than hiding a category that happens to be empty today. A
		// missing key and a zero read very differently at a glance.
		Counts: map[string]int{
			store.UnownedNoOwner:         0,
			store.UnownedIncompleteOwner: 0,
			store.UnownedUnattested:      0,
			store.UnownedStale:           0,
		},
		Guidance: unownedGuidance,
	}
	for _, row := range rows {
		out.Items = append(out.Items, UnownedIdentity{
			IdentityID: row.IdentityID, Name: row.Name, Status: row.Status,
			Reason: row.Reason, Detail: unownedReasonDetail(row.Reason),
		})
		out.Counts[row.Reason]++
	}
	out.Total = len(out.Items)
	a.writeJSON(w, http.StatusOK, out)
}
