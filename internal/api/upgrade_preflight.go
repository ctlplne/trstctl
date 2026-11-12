// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"

	"trstctl.com/trstctl/internal/api/problem"
)

// WithUpgradePreflight serves the upgrade preflight (A246-L1): the verdict
// `trstctl --upgrade-preflight` prints, read against this deployment's own
// database with the running binary's migrations and its configured backup.
// It changes nothing and carries names, versions, flags and times only.
func WithUpgradePreflight(fn func(context.Context) (any, error)) Option {
	return func(c *config) { c.upgradePreflight = fn }
}

// getUpgradePreflight serves GET /api/v1/platform/upgrade-preflight, the same
// JSON form a pipeline reads from `trstctl --upgrade-preflight
// --upgrade-preflight-format json` (format trstctl.upgrade-preflight.v1).
func (a *API) getUpgradePreflight(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.tenant(r); !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.upgradePreflight == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "the upgrade preflight is not served by this process"))
		return
	}
	verdict, err := a.upgradePreflight(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, verdict)
}
