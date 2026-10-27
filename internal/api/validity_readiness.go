// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/tlsvalidity"
)

// ValidityReadinessProvider owns the dated lifetime-reduction readiness report
// (A178). The server builds it from the scheduler's own configuration and
// renewable-identity inventory; the API only serves and exports it.
type ValidityReadinessProvider interface {
	ValidityReadiness(context.Context, string, time.Time) (tlsvalidity.Report, error)
}

// WithValidityReadiness wires the validity-readiness report.
func WithValidityReadiness(provider ValidityReadinessProvider) Option {
	return func(c *config) { c.validityReadiness = provider }
}

// ValidityReadinessExport is the report as a CSV file. Every row, and the file
// name, names the Baseline Requirements version it was evaluated against.
type ValidityReadinessExport struct {
	Filename     string             `json:"filename"`
	ContentType  string             `json:"content_type"`
	Requirements tlsvalidity.Source `json:"requirements"`
	GeneratedAt  time.Time          `json:"generated_at"`
	Truncated    bool               `json:"truncated"`
	CSV          string             `json:"csv"`
}

func (a *API) validityReadinessReport(w http.ResponseWriter, r *http.Request) (tlsvalidity.Report, bool) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return tlsvalidity.Report{}, false
	}
	if a.validityReadiness == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "validity readiness report is not assembled"))
		return tlsvalidity.Report{}, false
	}
	report, err := a.validityReadiness.ValidityReadiness(r.Context(), tenantID, time.Now().UTC())
	if err != nil {
		a.writeError(w, err)
		return tlsvalidity.Report{}, false
	}
	return report, true
}

func (a *API) getValidityReadiness(w http.ResponseWriter, r *http.Request) {
	report, ok := a.validityReadinessReport(w, r)
	if !ok {
		return
	}
	a.writeJSON(w, http.StatusOK, report)
}

func (a *API) exportValidityReadiness(w http.ResponseWriter, r *http.Request) {
	report, ok := a.validityReadinessReport(w, r)
	if !ok {
		return
	}
	body, err := tlsvalidity.CSV(report)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, ValidityReadinessExport{
		Filename: tlsvalidity.Filename(report), ContentType: "text/csv",
		Requirements: report.Requirements, GeneratedAt: report.GeneratedAt,
		Truncated: report.Truncated, CSV: string(body),
	})
}
