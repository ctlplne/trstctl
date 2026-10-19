// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/decommission/depstate"
	"trstctl.com/trstctl/internal/decommission/release"
)

func (h *caHierarchyService) fillManagedLeafReleasePreview(
	ctx context.Context, tenantID string, req api.CACeremonyStartRequest,
	purpose string, preview *api.CACeremonyPlanPreview,
) error {
	review, err := release.NewReviewer(h.store, h.log).Preview(ctx, tenantID, req.AuthorityID,
		release.Request{CertificateID: req.DependentID,
			ExpectedCertificateSHA256: req.ExpectedCertificateSHA256,
			Reason:                    req.Reason, RiskAccepted: req.RiskAccepted}, time.Now().UTC())
	if err != nil || review.Purpose() != purpose {
		return fmt.Errorf("%w: release source changed during review: %v", api.ErrCAHierarchyConflict, err)
	}
	preview.ReleaseReview = caReleaseReview(review)
	preview.RequiredPermission = "issuers:write"
	if review.Reason == depstate.ReleaseReasonRevokedUnservedHostCustody {
		preview.Changes = []string{
			"Prepare a two-custodian disposition of the exact revoked host-held CA leaf that was never served, its original mint and local revocation events, and the operator's explicit external-use risk decision. The preview writes nothing.",
		}
		preview.Risks = []string{
			"The host agent held this leaf's private key. Local revocation and no observed deployment cannot prove it was never used elsewhere or that every relying party rejects it.",
			"Releasing this exact dependency after two distinct custodian approvals permits a later retirement request; it does not perform revocation or destroy the CA key.",
		}
		preview.VerificationSteps = []string{
			"Match the exact certificate ID, public DER digest, original mint event, exact local revocation event, CA key and explicit external-use risk decision before opening the ceremony.",
			"Verify two distinct custodian approval events authorize this exact disposition before executing the release.",
			"After release, read the retirement checklist for this CA key and verify the exact certificate is accounted for; retain the immutable release receipt and audit event.",
		}
	}
	return nil
}

func (h *caHierarchyService) enrichManagedLeafReleaseCeremony(
	ctx context.Context, tenantID string, response api.CAKeyCeremony, purpose string,
) (api.CAKeyCeremony, error) {
	reviewed, relevant, err := depstate.ParseReleasePurposeV2(purpose)
	if err != nil {
		return api.CAKeyCeremony{}, err
	}
	if !relevant {
		var revoked depstate.DependencyReleasedV3
		revoked, relevant, err = depstate.ParseReleasePurposeV3(purpose)
		if err != nil {
			return api.CAKeyCeremony{}, err
		}
		if !relevant {
			return response, nil
		}
		reviewed = revoked.DependencyReleasedV2
		response.ReleaseReview = &api.CAReleaseCeremonyReview{
			RevocationEventID: revoked.RevocationEventID, RevocationSequence: revoked.RevocationSequence,
		}
	}
	if reviewed.TenantID != tenantID {
		return api.CAKeyCeremony{}, fmt.Errorf("%w: release ceremony tenant differs from request", api.ErrCAHierarchyConflict)
	}
	review := api.CAReleaseCeremonyReview{
		KeyID: reviewed.KeyID, CertificateID: reviewed.Dependent.ID,
		SourceEventID: reviewed.SourceEventID, SourceSequence: reviewed.SourceSequence,
		Serial: reviewed.Serial, CertificateSHA256: reviewed.CertificateSHA256,
		Reason: reviewed.Reason, RiskAccepted: reviewed.RiskAccepted,
	}
	if response.ReleaseReview != nil {
		review.RevocationEventID = response.ReleaseReview.RevocationEventID
		review.RevocationSequence = response.ReleaseReview.RevocationSequence
	}
	response.ReleaseReview = &review
	if cert, lookupErr := h.store.GetCertificate(ctx, tenantID, reviewed.Dependent.ID); lookupErr == nil {
		response.ReleaseReview.Subject = cert.Subject
		response.ReleaseReview.NotAfter = cert.NotAfter
	}
	return response, nil
}

func caReleaseReview(review release.Review) *api.CAReleaseCeremonyReview {
	notAfter := review.NotAfter
	return &api.CAReleaseCeremonyReview{
		KeyID: review.KeyID, CertificateID: review.CertificateID,
		SourceEventID: review.SourceEventID, SourceSequence: review.SourceSequence,
		RevocationEventID: review.RevocationEventID, RevocationSequence: review.RevocationSequence,
		Serial: review.Serial, CertificateSHA256: review.CertificateSHA256,
		Subject: review.Subject, NotAfter: &notAfter,
		Reason: review.Reason, RiskAccepted: review.RiskAccepted,
	}
}
