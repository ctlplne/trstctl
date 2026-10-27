// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/api"
)

// Customer assurance reports (A187). A Provider schedules a customer's report
// through a tenant template's report_schedules; core signs every run with the
// rendering in the customer's white-label brand inside. These reads hand the
// Provider the exact signed runs to share with that customer, and the key that
// verifies them offline.

// AssuranceReports is one customer's signed assurance report runs, newest
// first, and the key that signs them.
type AssuranceReports struct {
	TenantID   string                 `json:"tenant_id"`
	SigningKey api.ReportSigningKey   `json:"signing_key"`
	Runs       []api.ReportRunSummary `json:"runs"`
}

var errReportsNotAttached = fmt.Errorf("%w: customer report reads need core's signed report archive, which this deployment has not attached", ErrForbidden)

func (s *Service) reportsReady(ctx context.Context, actor Operator, customerID string) error {
	if err := s.requireOperator(actor); err != nil {
		return err
	}
	if err := s.authorize(ctx, actor, customerID, OpRead); err != nil {
		return err
	}
	if s.reports == nil {
		return errReportsNotAttached
	}
	return nil
}

// ListAssuranceReports lists a delegated customer's completed assurance report
// runs with the key that signs them.
func (s *Service) ListAssuranceReports(ctx context.Context, actor Operator, customerID string) (AssuranceReports, error) {
	if err := s.reportsReady(ctx, actor, customerID); err != nil {
		return AssuranceReports{}, err
	}
	key, err := s.reports.ReportSigningKey()
	if err != nil {
		return AssuranceReports{}, err
	}
	runs, err := s.reports.CustomerAssuranceRuns(ctx, customerID)
	if err != nil {
		return AssuranceReports{}, err
	}
	return AssuranceReports{TenantID: customerID, SigningKey: key, Runs: runs}, nil
}

// AssuranceReport is one run's exact signed bytes, read back from the archive
// and verified before they are handed out.
func (s *Service) AssuranceReport(ctx context.Context, actor Operator, customerID, runID string) ([]byte, error) {
	if err := s.reportsReady(ctx, actor, customerID); err != nil {
		return nil, err
	}
	artifact, err := s.reports.CustomerAssuranceArtifact(ctx, customerID, runID)
	if errors.Is(err, api.ErrReportRunNotFound) {
		return nil, fmt.Errorf("%w: %v", ErrNotFound, err)
	}
	return artifact, err
}

func (h *handler) listAssuranceReports(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	customerID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/provider/v1/tenants/"), "/assurance-reports")
	reports, err := h.svc.ListAssuranceReports(r.Context(), op, customerID)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, reports)
}

func (h *handler) getAssuranceReport(w http.ResponseWriter, r *http.Request) {
	op, ok := h.operatorFromRequest(r)
	if !ok {
		writeProviderError(w, ErrProviderUnauthenticated)
		return
	}
	customerID, runID, found := strings.Cut(strings.TrimPrefix(r.URL.Path, "/provider/v1/tenants/"), "/assurance-reports/")
	if !found || customerID == "" || runID == "" || strings.Contains(runID, "/") {
		writeProviderError(w, ErrNotFound)
		return
	}
	artifact, err := h.svc.AssuranceReport(r.Context(), op, customerID, runID)
	if err != nil {
		writeProviderError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=assurance-report-"+runID+".json")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(artifact)))
	w.WriteHeader(http.StatusOK)
	// The run ID was parsed as a UUID before core returned any bytes.
	_, _ = w.Write(artifact) // #nosec G705 -- the exact signed JSON report, sent as an application/json attachment that is never rendered as HTML (CWE-79)
}
