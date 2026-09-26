// SPDX-License-Identifier: BUSL-1.1

package acme

import (
	"context"
	"time"

	"trstctl.com/trstctl/internal/protocols/ari"
)

// DomainValidationActivitiesContext refreshes the registration-bound serving
// view before an operator reads it, even if no ACME client has returned yet.
func (s *Server) DomainValidationActivitiesContext(ctx context.Context, limit int) ([]DomainValidationActivity, error) {
	_, release, err := s.beginStateScope(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return s.DomainValidationActivities(limit), nil
}

// LookupRenewalInfoContext is the operator-facing lookup with the same tenant
// registration boundary as the HTTP renewal-info handler.
func (s *Server) LookupRenewalInfoContext(ctx context.Context, certID string, at time.Time) (ari.RenewalInfo, bool, error) {
	_, release, err := s.beginStateScope(ctx)
	if err != nil {
		return ari.RenewalInfo{}, false, err
	}
	defer release()
	info, found := s.LookupRenewalInfo(certID, at)
	return info, found, nil
}
