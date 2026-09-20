// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/protocols/ari"
)

// ACMEARIPosture builds the authenticated operator view from two independent
// truths: the live ACME publisher map and the tenant-scoped lifecycle
// projections. A computable window is not called published unless the running
// ACME server will actually answer renewalInfo for its RFC 9773 identifier.
func (s *Server) ACMEARIPosture(
	ctx context.Context,
	tenantID, afterID string,
	limit int,
	at time.Time,
) (api.ACMEARIPosture, string, error) {
	posture := api.ACMEARIPosture{
		Served:            true,
		GeneratedAt:       at.UTC(),
		PublicationStatus: api.ACMEARIPublicationNotServed,
		SchedulerStatus:   api.ACMEARISchedulerDisabled,
		Items:             []api.ACMEARICertificatePosture{},
	}
	if s.lifecycleRenewBefore > 0 {
		posture.SchedulerStatus = api.ACMEARISchedulerEnabled
	}

	var publisher interface {
		LookupRenewalInfo(string, time.Time) (ari.RenewalInfo, bool)
	}
	if s.protocols != nil &&
		s.protocols.acme != nil &&
		s.protocols.acmeTenant == tenantID &&
		(s.protocols.activation == nil || s.protocols.activation.Active()) {
		publisher = s.protocols.acme
		posture.PublicationStatus = api.ACMEARIPublicationServed
		posture.PublicationEndpoint = "/acme/renewal-info/{certid}"
	}

	rows, err := s.store.ListACMEARIPosturePage(ctx, tenantID, afterID, limit)
	if err != nil {
		return api.ACMEARIPosture{}, "", err
	}
	posture.Items = make([]api.ACMEARICertificatePosture, 0, len(rows))
	for _, row := range rows {
		item := api.ACMEARICertificatePosture{
			CertificateID:     row.CertificateID,
			IdentityID:        row.IdentityID,
			IdentityName:      row.IdentityName,
			CertificateStatus: row.CertificateStatus,
			PublicationStatus: api.ACMEARICertificateIdentifierUnavailable,
			SchedulerStatus:   initialACMEARISchedulerStatus(row.CertificateStatus, row.IdentityID, posture.SchedulerStatus),
			SchedulerSource:   api.ACMEARISourceNone,
		}

		if len(row.CertificateDER) > 0 {
			if certID, certErr := certinfo.ARICertID(row.CertificateDER); certErr == nil {
				item.ARICertificateID = certID
				item.PublicationStatus = api.ACMEARICertificateNotPublished
				if publisher != nil {
					if info, published := publisher.LookupRenewalInfo(certID, at); published {
						item.PublicationStatus = api.ACMEARICertificatePublished
						item.SuggestedWindow = &api.ACMEARIWindow{
							Start: info.SuggestedWindow.Start.UTC(),
							End:   info.SuggestedWindow.End.UTC(),
						}
					}
				}
			}
		}
		if item.SuggestedWindow == nil && row.NotBefore != nil {
			window := ari.SuggestWindow(row.NotBefore.UTC(), row.NotAfter.UTC(), at, false)
			item.SuggestedWindow = &api.ACMEARIWindow{Start: window.Start.UTC(), End: window.End.UTC()}
		}

		if row.RotationRunID != "" {
			item.RotationRunID = row.RotationRunID
			item.SchedulerStatus = normalizeACMEARIRunStatus(row.RotationRunStatus)
			item.SchedulerSource = classifyACMEARISchedulerSource(row.RotationRunTrigger, row.RotationRunReason)
			item.SchedulerConsumed = item.SchedulerSource == api.ACMEARISourceARI
			if item.SchedulerConsumed && row.RotationRunCreated != nil {
				consumedAt := row.RotationRunCreated.UTC()
				item.ConsumedAt = &consumedAt
			}
		}

		posture.Items = append(posture.Items, item)
		posture.Summary.AffectedCertificates++
		if item.PublicationStatus == api.ACMEARICertificatePublished {
			posture.Summary.Published++
		}
		if item.SchedulerStatus == api.ACMEARIRunPending {
			posture.Summary.SchedulerPending++
		}
		if item.SchedulerConsumed {
			posture.Summary.SchedulerConsumed++
		}
		if item.SchedulerStatus == api.ACMEARIRunFailed {
			posture.Summary.SchedulerFailed++
		}
	}
	nextID := ""
	if len(rows) == limit {
		nextID = rows[len(rows)-1].CertificateID
	}
	return posture, nextID, nil
}

func initialACMEARISchedulerStatus(certificateStatus, identityID, schedulerStatus string) string {
	if certificateStatus == "active" && identityID != "" && schedulerStatus == api.ACMEARISchedulerEnabled {
		return api.ACMEARIRunPending
	}
	return api.ACMEARIRunNotApplicable
}

func normalizeACMEARIRunStatus(status string) string {
	switch status {
	case api.ACMEARIRunRunning, api.ACMEARIRunSucceeded, api.ACMEARIRunFailed:
		return status
	default:
		return api.ACMEARIRunPending
	}
}

func classifyACMEARISchedulerSource(trigger, reason string) string {
	switch {
	case trigger == "scheduler" && strings.HasPrefix(reason, lifecycleARIRenewalReasonPrefix):
		return api.ACMEARISourceARI
	case trigger == "scheduler" && strings.HasPrefix(reason, lifecycleFixedRenewalReasonPrefix):
		return api.ACMEARISourceFixedThreshold
	case trigger == "scheduler":
		return api.ACMEARISourceUnknownScheduler
	case trigger != "":
		return api.ACMEARISourceManual
	default:
		return api.ACMEARISourceNone
	}
}
