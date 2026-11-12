// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/store"
)

var _ api.ADCSPendingRequestService = (*Server)(nil)

// ListADCSPendingRequests lists the requests an AD CS issuer's CA holds for a
// manager's approval, from the relay's latest read of its database (N1-L2),
// marking each one a trstctl issuance is held on (N1-L1).
func (s *Server) ListADCSPendingRequests(ctx context.Context, tenantID, issuerID string) (api.ADCSPendingRequests, error) {
	route, err := s.adcsDecisionRoute(tenantID, issuerID)
	if err != nil {
		return api.ADCSPendingRequests{}, err
	}
	out := api.ADCSPendingRequests{IssuerID: issuerID, CAConfig: route.CAConfig, Items: []api.ADCSPendingRequest{}}
	listed, err := s.store.GetADCSPendingRequests(ctx, tenantID, route.CAConfig)
	if errors.Is(err, store.ErrADCSPendingRequestsNotRead) {
		return out, nil
	}
	if err != nil {
		return api.ADCSPendingRequests{}, err
	}
	held := map[int]bool{}
	issues, err := s.store.ListExternalCAHeldIssues(ctx, tenantID, issuerID, store.ExternalCAHeldIssueListMax)
	if err != nil {
		return api.ADCSPendingRequests{}, err
	}
	for _, issue := range issues {
		if issue.Status == store.ExternalCAHeldIssueHeld {
			held[issue.CARequestID] = true
		}
	}
	readAt := listed.ObservedAt.UTC()
	out.ReadAt, out.Truncated = &readAt, listed.Truncated
	for _, r := range listed.Requests {
		out.Items = append(out.Items, api.ADCSPendingRequest{RequestID: r.RequestID, Template: r.Template, CommonName: r.CommonName,
			Requester: r.Requester, HeldIssuance: held[r.RequestID]})
	}
	return out, nil
}
