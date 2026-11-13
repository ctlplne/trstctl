// SPDX-License-Identifier: BUSL-1.1

package ca

import (
	"context"
	"errors"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// HeldResume is a held issuance after its request was read back from the CA
// (N1-L1): still held, issued (with the certificate) or denied.
type HeldResume struct {
	Status      string
	Certificate Certificate
	Held        store.ExternalCAHeldIssue
}

// recordHeld records that the CA holds an issuance's request for approval.
func (s *IssuanceService) recordHeld(ctx context.Context, tenantID, key string, req IssueRequest, requestID int) error {
	if s.log == nil || s.outboxAuthorityID == "" {
		return errors.New("ca: a held issuance needs the event log and its authority")
	}
	return orchestrator.NewOrchestrator(s.log, s.store, s.outbox).RecordExternalCAIssueHeld(ctx, tenantID, projections.ExternalCAIssueHeld{
		AuthorityID: s.outboxAuthorityID, CARequestID: requestID, IssueKey: key, RequestBinding: req.RequestBinding,
		KeyOrigin: req.KeyOrigin, DNSNames: append([]string(nil), req.DNSNames...),
	})
}

// HeldIssues lists the issuances this authority holds, or held, for approval,
// newest first.
func (s *IssuanceService) HeldIssues(ctx context.Context, tenantID string, limit int) ([]store.ExternalCAHeldIssue, error) {
	if s.outboxAuthorityID == "" {
		return []store.ExternalCAHeldIssue{}, nil
	}
	return s.store.ListExternalCAHeldIssues(ctx, tenantID, s.outboxAuthorityID, limit)
}

// ResumeHeld reads the request the CA held for an issuance back by the CA's
// request id (N1-L1). Once the CA issued it, the certificate is recorded under
// the held issuance's own idempotency key, so the issuance's caller recovers
// it on replay and its delivery finishes; once the CA refused it, the refusal
// is recorded. While the CA still holds it, nothing is recorded and the error
// matches ErrIssuanceHeld. Reading a request back cannot issue a second
// certificate, so resuming again is safe and answers the same.
func (s *IssuanceService) ResumeHeld(ctx context.Context, tenantID string, requestID int) (HeldResume, error) {
	if s.outboxAuthorityID == "" || s.log == nil {
		return HeldResume{}, ErrHeldRetrievalUnsupported
	}
	held, err := s.store.GetExternalCAHeldIssue(ctx, tenantID, s.outboxAuthorityID, requestID)
	if err != nil {
		return HeldResume{}, err
	}
	if held.Status == store.ExternalCAHeldIssueDenied {
		return HeldResume{Status: held.Status, Held: held}, nil
	}
	// Recorded already: resolved before, or a crash between recording the
	// certificate and resolving the held issuance.
	if cert, found, err := s.recoverExternalIssue(ctx, tenantID, held.IssueKey, held.RequestBinding); err != nil {
		return HeldResume{}, err
	} else if found {
		return s.resolveHeld(ctx, tenantID, held, store.ExternalCAHeldIssueIssued, cert)
	}
	cert, err := RetrieveHeldThrough(ctx, s.ca, requestID)
	switch {
	case err == nil:
		s.observeLifetime(tenantID, cert)
		// A held issuance keeps no enrollment path, so the certificate it
		// delivers records none (A244-L4).
		if err := s.record(ctx, tenantID, held.IssueKey, held.RequestBinding, held.KeyOrigin, "", cert); err != nil {
			return HeldResume{}, safeExternalIssueError("external_ca_record_failed", "external CA certificate recording failed", err)
		}
		if err := s.recordDependentOnce(ctx, IssueRequest{TenantID: tenantID}, held.IssueKey, cert); err != nil {
			return HeldResume{}, safeExternalIssueError("external_ca_observation_failed", "external CA issuance observation failed", err)
		}
		return s.resolveHeld(ctx, tenantID, held, store.ExternalCAHeldIssueIssued, cert)
	case errors.Is(err, ErrIssuanceHeld):
		return HeldResume{Status: store.ExternalCAHeldIssueHeld, Held: held}, ErrIssuanceHeld
	case errors.Is(err, ErrRequestRefused):
		return s.resolveHeld(ctx, tenantID, held, store.ExternalCAHeldIssueDenied, Certificate{})
	case errors.Is(err, ErrHeldRetrievalUnsupported):
		return HeldResume{}, err
	default:
		return HeldResume{}, safeExternalIssueError("external_ca_held_read_failed", "the CA could not be read", err)
	}
}

// resolveHeld records how a held issuance was resolved and reads it back.
func (s *IssuanceService) resolveHeld(ctx context.Context, tenantID string, held store.ExternalCAHeldIssue, status string, cert Certificate) (HeldResume, error) {
	if held.Status == store.ExternalCAHeldIssueHeld {
		if err := orchestrator.NewOrchestrator(s.log, s.store, s.outbox).RecordExternalCAIssueResumed(ctx, tenantID, projections.ExternalCAIssueResumed{
			AuthorityID: held.AuthorityID, CARequestID: held.CARequestID, Status: status, Serial: cert.Serial,
		}); err != nil {
			return HeldResume{}, err
		}
		resolved, err := s.store.GetExternalCAHeldIssue(ctx, tenantID, held.AuthorityID, held.CARequestID)
		if err != nil {
			return HeldResume{}, err
		}
		held = resolved
	}
	return HeldResume{Status: held.Status, Certificate: cert, Held: held}, nil
}
