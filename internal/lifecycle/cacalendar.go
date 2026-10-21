// SPDX-License-Identifier: BUSL-1.1

package lifecycle

import (
	"context"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/projections"
)

// DefaultLeafValidity is the reference leaf validity the CA calendar measures a
// parent's remaining horizon against when the operator has not configured one.
// Ninety days is the public-TLS working ceiling and a defensible private default;
// it is only a yardstick for "is this parent still able to issue a full-length
// leaf", never a limit on what anything issues.
const DefaultLeafValidity = 90 * 24 * time.Hour

// AlertCAHorizon sweeps a tenant's active CA authorities on a year-scale clock
// and raises an alert for each one that has crossed into a tighter expiry band
// than it was last alerted at, plus a distinct alert when a parent's remaining
// horizon is already short enough to be truncating the leaves issued under it.
// It returns how many alerts were raised.
//
// The immutable decision is appended before its read-model stamp and alert
// intent commit together (AN-2/AN-6). Re-running the sweep at the same band
// recovers that exact decision and its outbox command without inventing a new
// audit event or notifying twice.
func (m *Manager) AlertCAHorizon(ctx context.Context, tenantID string) (int, error) {
	now := m.now().UTC()
	candidates, err := m.store.ListCAHorizonCandidates(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	leafValidity := m.cfg.LeafValidity
	if leafValidity <= 0 {
		leafValidity = DefaultLeafValidity
	}

	alerted := 0
	for _, ca := range candidates {
		if ca.NotAfter == nil {
			// A22: the row never recorded an expiry. The authority's own
			// certificate is the source of truth when it parses; otherwise the
			// unknown expiry is a real state that alerts once at warning.
			derived, ok := caNotAfterFromPEM(ca.CertificatePEM)
			if !ok {
				if ca.AlertedMonths != nil && *ca.AlertedMonths <= CAHorizonUnknownExpiryBand {
					continue
				}
				dependents, err := m.store.CountActiveLeavesForAuthority(ctx, tenantID, ca.ID)
				if err != nil {
					return alerted, err
				}
				detail := caUnknownExpiryDetail(ca.Kind, dependents)
				if err := m.orch.RecordCAAuthorityHorizonAlert(ctx, tenantID, projections.CAAuthorityHorizonAlerted{
					CAAuthorityID: ca.ID, CommonName: ca.CommonName, Kind: ca.Kind,
					HorizonMonths: CAHorizonUnknownExpiryBand, ExpiryUnknown: true,
					DependentCertificates: dependents, AlertKind: notify.KindCAHorizon,
					AlertDetail: detail, Severity: CAHorizonSeverity(CAHorizonUnknownExpiryBand),
				}); err != nil {
					return alerted, err
				}
				alerted++
				continue
			}
			ca.NotAfter = &derived
		}
		notAfter := ca.NotAfter.UTC()
		band, inBand := CAHorizonBand(now, notAfter)
		if !inBand {
			// A23: beyond the widest threshold the authority is real and known;
			// it announces itself once as a planning entry and is then quiet
			// until it crosses into a band.
			band = CAHorizonBeyondBand
		}
		if ca.AlertedMonths != nil && *ca.AlertedMonths <= band {
			// Already alerted at this band or a tighter one. Re-alerting happens
			// on the next tightening, not on the next sweep.
			continue
		}

		dependents, err := m.store.CountActiveLeavesForAuthority(ctx, tenantID, ca.ID)
		if err != nil {
			return alerted, err
		}
		compressed, actual := CompressedValidity(now, notAfter, leafValidity)
		renewBy := CARenewBy(notAfter, leafValidity)

		kind := notify.KindCAHorizon
		detail := caHorizonDetail(ca.Kind, band, MonthsRemaining(now, notAfter), dependents)
		if compressed {
			// The compressing case is a different problem with a different fix, so
			// it gets its own kind rather than a longer sentence on the same one:
			// renewing the parent restores full leaf validity, and until it is
			// renewed every new leaf under it is quietly short.
			kind = notify.KindCAValidityCompression
			detail = caCompressionDetail(ca.Kind, leafValidity, actual, dependents)
		}

		horizonMonths := band
		alert := notify.Alert{
			Kind:                  kind,
			TenantID:              tenantID,
			AuthorityID:           ca.ID,
			AuthorityKind:         ca.Kind,
			Subject:               ca.CommonName,
			NotAfter:              notAfter,
			Detail:                detail,
			Severity:              CAHorizonSeverity(band),
			HorizonMonths:         &horizonMonths,
			RenewBy:               renewBy,
			DependentCertificates: &dependents,
		}
		if err := m.orch.RecordCAAuthorityHorizonAlert(ctx, tenantID, projections.CAAuthorityHorizonAlerted{
			CAAuthorityID: ca.ID, CommonName: ca.CommonName, Kind: ca.Kind,
			NotAfter: notAfter, HorizonMonths: band,
			MonthsRemaining: MonthsRemaining(now, notAfter), RenewBy: renewBy,
			ValidityCompressed: compressed, DependentCertificates: dependents,
			AlertKind: alert.Kind, AlertDetail: alert.Detail, Severity: alert.Severity,
		}); err != nil {
			return alerted, err
		}
		alerted++
	}
	return alerted, nil
}

func caHorizonDetail(kind string, band, remaining, dependents int) string {
	if band == CAHorizonBeyondBand {
		return fmt.Sprintf(
			"%s CA is on the expiry calendar with %d month(s) remaining, beyond the %d-month planning horizon; %d active certificate(s) chain to it. "+
				"No action is due yet: this entry records when the trust-anchor migration will have to start",
			caKindLabel(kind), remaining, CAHorizonThresholdMonths[0], dependents)
	}
	if band == 0 {
		return fmt.Sprintf("%s CA has expired; %d active certificate(s) chain to it and cannot be replaced under it",
			caKindLabel(kind), dependents)
	}
	return fmt.Sprintf(
		"%s CA is inside the %d-month expiry horizon (%d month(s) remaining) with %d active certificate(s) chaining to it; "+
			"replacing a trust anchor requires distributing it to every relying party first, so start the migration from this horizon, not from the expiry date",
		caKindLabel(kind), band, remaining, dependents)
}

// caUnknownExpiryDetail names the state an operator must resolve: a CA whose
// expiry nobody recorded and whose certificate cannot say.
func caUnknownExpiryDetail(kind string, dependents int) string {
	return fmt.Sprintf(
		"%s CA has no recorded expiry and its stored certificate does not yield one; %d active certificate(s) chain to it. "+
			"An unknown expiry is not a healthy one: record the authority's certificate or re-key it so its horizon can be tracked",
		caKindLabel(kind), dependents)
}

// caNotAfterFromPEM derives an expiry from the authority's stored certificate.
func caNotAfterFromPEM(pem string) (time.Time, bool) {
	der, err := certinfo.LeafDER([]byte(pem))
	if err != nil {
		return time.Time{}, false
	}
	info, err := certinfo.Inspect(der)
	if err != nil || info.NotAfter.IsZero() {
		return time.Time{}, false
	}
	return info.NotAfter.UTC(), true
}

func caCompressionDetail(kind string, want, actual time.Duration, dependents int) string {
	return fmt.Sprintf(
		"%s CA has less life left (%d day(s)) than the %d-day validity its leaves are issued with, so every new leaf under it is being truncated to the parent's expiry; "+
			"%d active certificate(s) chain to it. Issuance keeps succeeding — the certificates just get shorter — so renew or re-key the authority to restore full leaf validity",
		caKindLabel(kind), int(actual.Hours()/24), int(want.Hours()/24), dependents)
}

func caKindLabel(kind string) string {
	switch kind {
	case "root":
		return "Root"
	case "intermediate":
		return "Intermediate"
	case "":
		return "CA"
	default:
		return kind
	}
}
