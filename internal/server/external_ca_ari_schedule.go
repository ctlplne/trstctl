// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/protocols/ari"
	"trstctl.com/trstctl/internal/store"
)

const upstreamARIQueuedGrace = 6 * time.Hour

func (s *Server) lifecycleRenewalReasonForCertificate(
	ctx context.Context, tenantID string, cert store.Certificate, now, fixedCutoff time.Time,
) (string, bool, error) {
	if cert.IssuingExternalCAID == "" {
		reason, due := lifecycleRenewalReason(cert, now, fixedCutoff)
		return reason, due, nil
	}
	observation, err := s.store.GetACMEUpstreamARI(ctx, tenantID, cert.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		reason, due := lifecycleRenewalReason(cert, now, fixedCutoff)
		return reason, due, nil
	}
	if err != nil {
		return "", false, err
	}
	if observation.AuthorityID != cert.IssuingExternalCAID || observation.Fingerprint != cert.Fingerprint {
		return "", false, errors.New("server: upstream ARI observation differs from served certificate")
	}
	reason, due := upstreamARIRenewalReason(cert, observation, now, fixedCutoff)
	return reason, due, nil
}

// The CA's fetched window is authoritative while it is available. Spread work
// deterministically within the window, but retain a short expiry emergency
// fallback so an impossible or stale CA hint cannot expire a serving leaf.
func upstreamARIRenewalReason(cert store.Certificate, observation store.ACMEUpstreamARI, now, fixedCutoff time.Time) (string, bool) {
	if cert.NotAfter == nil {
		return "", false
	}
	if observation.Status == "queued" && now.Sub(observation.UpdatedAt) < upstreamARIQueuedGrace {
		if !externalARIEmergencyDue(cert, now) {
			return "", false
		}
		return lifecycleFixedRenewalReasonPrefix + cert.NotAfter.UTC().Format(time.RFC3339), true
	}
	if !observation.CanSchedule() {
		return lifecycleRenewalReason(cert, now, fixedCutoff)
	}
	window := ari.RenewalInfo{SuggestedWindow: ari.Window{
		Start: observation.WindowStart.UTC(), End: observation.WindowEnd.UTC(),
	}}
	seed := fnv.New64a()
	_, _ = seed.Write([]byte(cert.Fingerprint))
	target := ari.RenewAt(window, int64(seed.Sum64()>>1))
	if !now.Before(target) {
		return fmt.Sprintf(lifecycleUpstreamARIRenewalReasonPrefix+"%s..%s",
			window.SuggestedWindow.Start.Format(time.RFC3339),
			window.SuggestedWindow.End.Format(time.RFC3339)), true
	}
	if externalARIEmergencyDue(cert, now) {
		return lifecycleFixedRenewalReasonPrefix + cert.NotAfter.UTC().Format(time.RFC3339), true
	}
	return "", false
}

func externalARIEmergencyDue(cert store.Certificate, now time.Time) bool {
	if cert.NotAfter == nil {
		return false
	}
	lead := 24 * time.Hour
	if cert.NotBefore != nil {
		lifetime := cert.NotAfter.Sub(*cert.NotBefore)
		if lifetime > 0 && lifetime/10 < lead {
			lead = lifetime / 10
		}
	}
	return !now.Before(cert.NotAfter.Add(-lead))
}
