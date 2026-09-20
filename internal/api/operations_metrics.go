// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"

	"trstctl.com/trstctl/internal/bulkhead"
)

// B-1: AN-7 gives every subsystem its own bounded pool, and AN-6 puts every
// external effect through the outbox — but neither was readable from the
// served API, so an operator could not answer "is a queue backing up, and
// which one" without shell access to the metrics endpoint. This exposes the
// same in-process snapshots the pools and the outbox already keep.
//
// The pool stats are process-wide operational telemetry, not tenant rows:
// they carry subsystem names and counters, never credential or tenant data.
// The outbox view IS tenant-scoped, and stays so.

type bulkheadPoolStats struct {
	Name      string `json:"name"`
	Workers   int    `json:"workers"`
	Capacity  int    `json:"capacity"`
	Queued    int    `json:"queued"`
	Submitted int64  `json:"submitted"`
	Completed int64  `json:"completed"`
	Rejected  int64  `json:"rejected"`
	Panicked  int64  `json:"panicked"`
	// Saturation is queued/capacity as a percentage, so a caller can sort by
	// pressure without recomputing it. 0 when the pool is unbounded.
	Saturation int `json:"saturation_percent"`
}

type bulkheadStatsResponse struct {
	Served bool                `json:"served"`
	Pools  []bulkheadPoolStats `json:"pools"`
}

func toBulkheadPoolStats(stats bulkhead.Stats) bulkheadPoolStats {
	saturation := 0
	if stats.Capacity > 0 {
		saturation = stats.Queued * 100 / stats.Capacity
	}
	return bulkheadPoolStats{
		Name: stats.Name, Workers: stats.Workers, Capacity: stats.Capacity, Queued: stats.Queued,
		Submitted: stats.Submitted, Completed: stats.Completed, Rejected: stats.Rejected,
		Panicked: stats.Panicked, Saturation: saturation,
	}
}

// listBulkheadStats reports every bounded worker pool's live pressure. When no
// pool set is wired (a server assembled without the bulkheaded surfaces) it
// answers served=false with an empty list rather than 404 — the question "is
// anything saturated" has a truthful answer either way.
func (a *API) listBulkheadStats(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.tenant(r); !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.bulkheadStats == nil {
		a.writeJSON(w, http.StatusOK, bulkheadStatsResponse{Served: false, Pools: []bulkheadPoolStats{}})
		return
	}
	pools := []bulkheadPoolStats{}
	for _, stats := range a.bulkheadStats() {
		pools = append(pools, toBulkheadPoolStats(stats))
	}
	a.writeJSON(w, http.StatusOK, bulkheadStatsResponse{Served: true, Pools: pools})
}
