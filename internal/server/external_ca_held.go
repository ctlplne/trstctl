// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// N1-L1: issuances an external CA holds for a manager's approval, listed and
// resumed by the CA's request id.

var _ api.ExternalCAHeldIssueService = (*externalCARegistry)(nil)

const externalCAHeldIssueListLimit = 200

// entryFor resolves an authority the tenant may use.
func (r *externalCARegistry) entryFor(tenantID, id string) (externalCAEntry, error) {
	id = strings.TrimSpace(id)
	entry, ok := r.byID[id]
	if !ok || (entry.tenantID != "" && entry.tenantID != tenantID) {
		return externalCAEntry{}, fmt.Errorf("%w: %s", api.ErrExternalCANotFound, id)
	}
	if tenantID == "" {
		return externalCAEntry{}, fmt.Errorf("%w: missing tenant", api.ErrExternalCAInvalid)
	}
	return entry, nil
}

func heldIssueView(h store.ExternalCAHeldIssue) api.ExternalCAHeldIssue {
	names := append([]string{}, h.DNSNames...)
	return api.ExternalCAHeldIssue{CARequestID: h.CARequestID, DNSNames: names, Status: h.Status, Serial: h.Serial,
		HeldAt: h.HeldAt.UTC(), ResolvedAt: h.ResolvedAt}
}

// ListExternalCAHeldIssues lists the issuances an authority holds, or held, for
// approval, newest first.
func (r *externalCARegistry) ListExternalCAHeldIssues(ctx context.Context, tenantID, id string) ([]api.ExternalCAHeldIssue, error) {
	entry, err := r.entryFor(tenantID, id)
	if err != nil {
		return nil, err
	}
	rows, err := entry.svc.HeldIssues(ctx, tenantID, externalCAHeldIssueListLimit)
	if err != nil {
		return nil, err
	}
	out := make([]api.ExternalCAHeldIssue, 0, len(rows))
	for _, row := range rows {
		out = append(out, heldIssueView(row))
	}
	return out, nil
}

// ResumeExternalCAHeldIssue reads a held request back from the authority and
// finishes its issuance once the CA issued it.
func (r *externalCARegistry) ResumeExternalCAHeldIssue(ctx context.Context, tenantID, id string, requestID int) (api.ExternalCAHeldIssueResume, error) {
	entry, err := r.entryFor(tenantID, id)
	if err != nil {
		return api.ExternalCAHeldIssueResume{}, err
	}
	resumed, err := entry.svc.ResumeHeld(ctx, tenantID, requestID)
	switch {
	case errors.Is(err, store.ErrExternalCAHeldIssueNotFound):
		return api.ExternalCAHeldIssueResume{}, api.ErrExternalCAHeldIssueNotFound
	case errors.Is(err, ca.ErrIssuanceHeld):
		return api.ExternalCAHeldIssueResume{}, api.ErrExternalCAStillHeld
	case errors.Is(err, ca.ErrHeldRetrievalUnsupported):
		return api.ExternalCAHeldIssueResume{}, api.ErrExternalCAHeldUnsupported
	case err != nil:
		return api.ExternalCAHeldIssueResume{}, fmt.Errorf("%w: %s", api.ErrExternalCAUpstream, externalCAUpstreamDetail(err))
	}
	out := api.ExternalCAHeldIssueResume{ExternalCAHeldIssue: heldIssueView(resumed.Held)}
	if resumed.Status == store.ExternalCAHeldIssueIssued && len(resumed.Certificate.CertificatePEM) > 0 {
		out.CertificatePEM = string(resumed.Certificate.CertificatePEM)
		if !resumed.Certificate.NotAfter.IsZero() {
			notAfter := resumed.Certificate.NotAfter.UTC()
			out.NotAfter = &notAfter
		}
	}
	return out, nil
}

// RetrieveHeld uses the same short-lived factory as issuance (N1-L1): no
// standing upstream credential is kept between reads.
func (c factoryExternalCA) RetrieveHeld(ctx context.Context, requestID int) (ca.Certificate, error) {
	implementation, cleanup, err := c.factory(ctx)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return ca.Certificate{}, err
	}
	if implementation == nil {
		return ca.Certificate{}, errors.New("external CA factory returned no implementation")
	}
	return ca.RetrieveHeldThrough(ctx, implementation, requestID)
}

// RetrieveHeld forwards to the wrapped authority (N1-L1).
func (c diagnosticExternalCA) RetrieveHeld(ctx context.Context, requestID int) (ca.Certificate, error) {
	return ca.RetrieveHeldThrough(ctx, c.inner, requestID)
}

// DeliverExternalCAResumeHeld resumes a held issuance once the issuer's relay
// approved its request (N1-L1). The CA's answer can lag the relay's readback,
// so a request still held is retried; an issuance resolved meanwhile answers
// as resolved, and one that no longer exists, or an authority that cannot read
// a request back, ends the job without an effect.
func (r *externalCARegistry) DeliverExternalCAResumeHeld(ctx context.Context, m orchestrator.Message) error {
	var payload orchestrator.ExternalCAResumeHeld
	if err := json.Unmarshal(m.Payload, &payload); err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: decode held issuance resume: %w", err))
	}
	entry, err := r.entryFor(m.TenantID, payload.AuthorityID)
	if err != nil {
		return orchestrator.DefiniteNoEffect(err)
	}
	_, err = entry.svc.ResumeHeld(ctx, m.TenantID, payload.CARequestID)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrExternalCAHeldIssueNotFound), errors.Is(err, ca.ErrHeldRetrievalUnsupported):
		return orchestrator.DefiniteNoEffect(err)
	default:
		return err
	}
}
