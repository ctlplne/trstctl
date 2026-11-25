// SPDX-License-Identifier: BUSL-1.1

package ca

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
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
	if req.ProfileName != "" && req.profileRevision == nil {
		return fmt.Errorf("%w: held issuance has no pinned profile revision", ErrExternalProfileRefused)
	}
	held := projections.ExternalCAIssueHeld{AuthorityID: s.outboxAuthorityID, CARequestID: requestID, IssueKey: key,
		RequestBinding: req.RequestBinding, KeyOrigin: req.KeyOrigin, DNSNames: append([]string(nil), req.DNSNames...),
		ProfileName: req.ProfileName, Protocol: req.Protocol, RequestedEKUs: slices.Clone(req.resolvedEKUs)}
	if req.profileRevision != nil {
		held.ProfileVersion, held.ProfileDigest = req.profileRevision.Version, req.profileRevision.Digest
	}
	if len(req.CSR) > 0 {
		info, err := crypto.InspectCSR(req.CSR)
		if err != nil {
			return fmt.Errorf("%w: held issuance CSR cannot be inspected", ErrExternalProfileRefused)
		}
		held.DNSNames = profileDNSNames(info, req.DNSNames)
		held.IPAddresses = append([]string(nil), info.IPAddresses...)
		held.EmailAddresses = append([]string(nil), info.EmailAddresses...)
		held.URIs = append([]string(nil), info.URIs...)
		held.SubjectSPKISHA256 = info.SPKISHA256
	}
	return orchestrator.NewOrchestrator(s.log, s.store, s.outbox).RecordExternalCAIssueHeld(ctx, tenantID, held)
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
		if err := s.validateHeldCertificate(ctx, tenantID, held, cert); err != nil {
			return HeldResume{}, err
		}
		return s.resolveHeld(ctx, tenantID, held, store.ExternalCAHeldIssueIssued, cert)
	}
	cert, err := RetrieveHeldThrough(ctx, s.ca, requestID)
	switch {
	case err == nil:
		if err := s.validateHeldCertificate(ctx, tenantID, held, cert); err != nil {
			return HeldResume{}, err
		}
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

func (s *IssuanceService) validateHeldCertificate(ctx context.Context, tenantID string, held store.ExternalCAHeldIssue, cert Certificate) error {
	if !held.ProfileBindingKnown {
		return fmt.Errorf("%w: the held request predates durable profile binding", ErrExternalProfileRefused)
	}
	if held.ProfileName == "" {
		return nil
	}
	if held.ProfileVersion <= 0 || held.ProfileDigest == "" {
		return fmt.Errorf("%w: the held request has no complete pinned profile", ErrExternalProfileRefused)
	}
	record, err := s.store.GetProfileVersion(ctx, tenantID, held.ProfileName, held.ProfileVersion)
	if err != nil || store.ProfileSpecDigest(record.Spec) != held.ProfileDigest {
		return fmt.Errorf("%w: the held request's pinned profile is unavailable", ErrExternalProfileRefused)
	}
	var prof profile.CertificateProfile
	if err := json.Unmarshal(record.Spec, &prof); err != nil {
		return fmt.Errorf("%w: the held request's pinned profile cannot be decoded", ErrExternalProfileRefused)
	}
	info, err := certinfo.Inspect(cert.CertificatePEM)
	if err != nil {
		return fmt.Errorf("%w: the CA returned an invalid certificate", ErrExternalProfileRefused)
	}
	if info.IsCA || info.KeyUsageCertSign {
		return fmt.Errorf("%w: the CA returned a CA certificate for a leaf request", ErrExternalProfileRefused)
	}
	if held.SubjectSPKISHA256 == "" || info.SPKISHA256 != held.SubjectSPKISHA256 {
		return fmt.Errorf("%w: CA returned a certificate for a different subject public key", ErrExternalProfileRefused)
	}
	if len(prof.AllowedEKUs) > 0 && len(info.ExtKeyUsages) == 0 {
		return fmt.Errorf("%w: the CA returned a certificate with no constrained extended key usage", ErrExternalProfileRefused)
	}
	if len(held.RequestedEKUs) > 0 {
		for _, usage := range info.ExtKeyUsages {
			if !slices.Contains(held.RequestedEKUs, usage) {
				return fmt.Errorf("%w: CA returned extended key usage outside the held request", ErrExternalProfileRefused)
			}
		}
	}
	allowedName := func(got string, allowed []string, equalFold bool) bool {
		for _, want := range allowed {
			if equalFold && strings.EqualFold(strings.TrimSuffix(got, "."), strings.TrimSuffix(want, ".")) || !equalFold && got == want {
				return true
			}
		}
		return false
	}
	for _, group := range []struct {
		label     string
		got, want []string
		fold      bool
	}{
		{"DNS", info.DNSNames, held.DNSNames, true},
		{"IP", info.IPAddresses, held.IPAddresses, false},
		{"email", append(slices.Clone(info.EmailAddresses), info.SmtpUTF8Mailboxes...), held.EmailAddresses, false},
		{"URI", info.URIs, held.URIs, false},
	} {
		for _, name := range group.got {
			if !allowedName(name, group.want, group.fold) {
				return fmt.Errorf("%w: CA returned %s identity outside the held request", ErrExternalProfileRefused, group.label)
			}
		}
	}
	if err := crypto.CheckExternalCertificateSubject(cert.CertificatePEM, held.DNSNames, held.IPAddresses, held.EmailAddresses, held.URIs); err != nil {
		return fmt.Errorf("%w: %w", ErrExternalProfileRefused, err)
	}
	if err := prof.Validate(profile.Request{KeyAlgorithm: info.KeyAlgorithm, KeyBits: info.PublicKeyBits,
		RequestedEKUs: info.ExtKeyUsages, TTL: info.NotAfter.Sub(info.NotBefore), DNSNames: info.DNSNames,
		IPAddresses: info.IPAddresses, EmailAddresses: append(slices.Clone(info.EmailAddresses), info.SmtpUTF8Mailboxes...),
		URIs: info.URIs, Protocol: held.Protocol}); err != nil {
		return fmt.Errorf("%w: CA output violates pinned profile: %w", ErrExternalProfileRefused, err)
	}
	return nil
}

func (s *IssuanceService) validateIssuedCertificate(ctx context.Context, req IssueRequest, cert Certificate) error {
	if req.ProfileName == "" {
		return nil
	}
	if req.profileRevision == nil {
		return fmt.Errorf("%w: the issued certificate has no pinned profile revision", ErrExternalProfileRefused)
	}
	info, err := crypto.InspectCSR(req.CSR)
	if err != nil {
		return fmt.Errorf("%w: the issued certificate's CSR cannot be inspected", ErrExternalProfileRefused)
	}
	requestedEKUs := req.resolvedEKUs
	if len(requestedEKUs) == 0 {
		requestedEKUs = req.RequestedEKUs
		if len(requestedEKUs) == 0 {
			requestedEKUs = info.RequestedEKUs
		}
	}
	return s.validateHeldCertificate(ctx, req.TenantID, store.ExternalCAHeldIssue{
		ProfileBindingKnown: true, ProfileName: req.ProfileName, ProfileVersion: req.profileRevision.Version,
		ProfileDigest: req.profileRevision.Digest, Protocol: req.Protocol,
		DNSNames: profileDNSNames(info, req.DNSNames), IPAddresses: info.IPAddresses,
		EmailAddresses: info.EmailAddresses, URIs: info.URIs, RequestedEKUs: requestedEKUs,
		SubjectSPKISHA256: info.SPKISHA256,
	}, cert)
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
