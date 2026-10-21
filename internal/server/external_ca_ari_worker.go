// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/protocols/ari"
)

const (
	defaultARIPollInterval = 6 * time.Hour
	minimumARIPollInterval = time.Minute
	maximumARIPollInterval = 24 * time.Hour
	initialARIErrorRetry   = 5 * time.Minute
)

type externalARIFetchPayload struct {
	CertificateID    string `json:"certificate_id"`
	AuthorityID      string `json:"authority_id"`
	ARICertificateID string `json:"ari_certificate_id"`
	Fingerprint      string `json:"fingerprint"`
	Provenance       string `json:"provenance,omitempty"`
}

// deliverExternalCAARI performs only public, unauthenticated GETs from the
// external-CA bulkhead. It will not let an outbox payload choose an arbitrary
// URL or turn a certificate of another tenant/issuer into a network target.
func (d *issuanceDispatcher) deliverExternalCAARI(ctx context.Context, m orchestrator.Message) error {
	if d.externalCAs == nil || d.store == nil || d.log == nil {
		return orchestrator.DefiniteNoEffect(errors.New("server: external ACME ARI receiver is unavailable"))
	}
	if m.RequiredAgentRole != "control_plane" {
		return orchestrator.DefiniteNoEffect(errors.New("server: external ACME ARI command is not control-plane bound"))
	}
	var command externalARIFetchPayload
	if err := json.Unmarshal(m.Payload, &command); err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: decode external ACME ARI command: %w", err))
	}
	entry, found := d.externalCAs.byID[command.AuthorityID]
	if !found || entry.meta.Type != "letsencrypt" || entry.ariFetch == nil ||
		(entry.tenantID != "" && entry.tenantID != m.TenantID) {
		return orchestrator.DefiniteNoEffect(errors.New("server: external ACME ARI authority is not configured for tenant"))
	}
	provenance, ok := projections.NormalizeACMEUpstreamARIProvenance(command.Provenance)
	if !ok {
		return orchestrator.DefiniteNoEffect(errors.New("server: external ACME ARI command carries an unknown provenance"))
	}
	cert, err := d.store.GetCertificate(ctx, m.TenantID, command.CertificateID)
	if errors.Is(err, pgx.ErrNoRows) {
		return orchestrator.DefiniteNoEffect(errors.New("server: external ACME ARI certificate is absent"))
	}
	if err != nil {
		return err
	}
	// An authenticated-issuer command must match the certificate's recorded
	// external issuer; an issuer-key-id command (A51) is only valid on a leaf
	// with no authenticated issuer, and the key id is re-matched below.
	boundIssuer := command.AuthorityID
	if provenance == projections.ACMEUpstreamARIProvenanceIssuerKeyID {
		boundIssuer = ""
	}
	if cert.Fingerprint != command.Fingerprint || cert.IssuingExternalCAID != boundIssuer ||
		len(cert.CertificateDER) == 0 || !ari.ValidCertID(command.ARICertificateID) {
		return orchestrator.DefiniteNoEffect(errors.New("server: external ACME ARI certificate binding differs"))
	}
	leaf, err := certinfo.Inspect(cert.CertificateDER)
	if err != nil || leaf.IsCA || leaf.SHA256Fingerprint != cert.Fingerprint || leaf.SerialNumber != cert.Serial ||
		cert.NotAfter == nil || !leaf.NotAfter.Equal(*cert.NotAfter) {
		return orchestrator.DefiniteNoEffect(errors.New("server: external ACME ARI retained leaf differs from inventory"))
	}
	if provenance == projections.ACMEUpstreamARIProvenanceIssuerKeyID && !entry.matchesARIIssuer(leaf.AuthorityKeyID) {
		return orchestrator.DefiniteNoEffect(errors.New("server: external ACME ARI discovered leaf no longer matches a declared issuer key id"))
	}
	derivedID, err := certinfo.ARICertID(cert.CertificateDER)
	if err != nil || derivedID != command.ARICertificateID {
		return orchestrator.DefiniteNoEffect(errors.New("server: external ACME ARI identifier differs from retained certificate"))
	}
	canonicalID := evidenceID("external-ari-observed", m.TenantID, m.IdempotencyKey, m.ID)
	if m.Attempts > 1 {
		canonical, exists, err := d.log.EventByID(ctx, canonicalID)
		if err != nil {
			return err
		}
		if exists {
			return d.projectExternalARICanonical(ctx, canonical, m.TenantID, command)
		}
	}
	if cert.Status != "active" || cert.NotAfter == nil || !cert.NotAfter.After(time.Now().UTC()) {
		return nil // No fetch or new poll after revocation, replacement or expiry.
	}
	prior, err := d.store.GetACMEUpstreamARI(ctx, m.TenantID, command.CertificateID)
	if errors.Is(err, pgx.ErrNoRows) {
		return orchestrator.DeferDelivery(errors.New("server: external ACME ARI request projection is pending"))
	}
	if err != nil {
		return err
	}
	priorProvenance, _ := projections.NormalizeACMEUpstreamARIProvenance(prior.Provenance)
	if prior.AuthorityID != command.AuthorityID || priorProvenance != provenance ||
		prior.ARICertificateID != command.ARICertificateID || prior.Fingerprint != command.Fingerprint {
		return orchestrator.DefiniteNoEffect(errors.New("server: external ACME ARI projection binding differs"))
	}
	info, retryAfter, fetchErr := entry.ariFetch(ctx, command.ARICertificateID)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	now := time.Now().UTC()
	observed := projections.ACMEUpstreamARIObserved{
		CertificateID: command.CertificateID, AuthorityID: command.AuthorityID,
		ARICertificateID: command.ARICertificateID, Fingerprint: command.Fingerprint,
		FailureCount: prior.FailureCount,
	}
	if provenance == projections.ACMEUpstreamARIProvenanceIssuerKeyID {
		observed.Provenance = provenance
	}
	switch {
	case fetchErr == nil:
		observed.Status = "ready"
		observed.FailureCount = 0
		observed.WindowStart = &info.SuggestedWindow.Start
		observed.WindowEnd = &info.SuggestedWindow.End
		observed.NextPollAt = now.Add(boundedARIPoll(retryAfter))
	case errors.Is(fetchErr, ari.ErrNotAdvertised):
		observed.Status = "unavailable"
		observed.ErrorClass = "not_advertised"
		observed.NextPollAt = now.Add(defaultARIPollInterval)
	default:
		observed.Status = "error"
		observed.FailureCount++
		observed.ErrorClass = classifyExternalARIError(fetchErr)
		observed.NextPollAt = now.Add(ariErrorRetry(observed.FailureCount))
	}
	data, err := json.Marshal(observed)
	if err != nil {
		return err
	}
	canonical, err := d.log.Append(ctx, events.Event{
		ID: canonicalID, Type: projections.EventACMEUpstreamARIObserved,
		TenantID: m.TenantID, Time: now, Data: data,
	})
	if err != nil {
		return err
	}
	return d.projectExternalARICanonical(ctx, canonical, m.TenantID, command)
}

func (d *issuanceDispatcher) projectExternalARICanonical(
	ctx context.Context, event events.Event, tenantID string, command externalARIFetchPayload,
) error {
	if event.Type != projections.EventACMEUpstreamARIObserved || event.TenantID != tenantID ||
		event.SchemaVersion != events.DefaultSchemaVersion {
		return orchestrator.DefiniteNoEffect(errors.New("server: external ACME ARI canonical event differs"))
	}
	var retained projections.ACMEUpstreamARIObserved
	if err := json.Unmarshal(event.Data, &retained); err != nil {
		return err
	}
	retainedProvenance, _ := projections.NormalizeACMEUpstreamARIProvenance(retained.Provenance)
	commandProvenance, _ := projections.NormalizeACMEUpstreamARIProvenance(command.Provenance)
	if retained.CertificateID != command.CertificateID ||
		retained.AuthorityID != command.AuthorityID ||
		retained.ARICertificateID != command.ARICertificateID ||
		retained.Fingerprint != command.Fingerprint || retainedProvenance != commandProvenance {
		return orchestrator.DefiniteNoEffect(errors.New("server: external ACME ARI canonical certificate binding differs"))
	}
	return projections.New(d.store).Apply(ctx, event)
}

func boundedARIPoll(hint time.Duration) time.Duration {
	if hint <= 0 {
		return defaultARIPollInterval
	}
	if hint < minimumARIPollInterval {
		return minimumARIPollInterval
	}
	if hint > maximumARIPollInterval {
		return maximumARIPollInterval
	}
	return hint
}

func ariErrorRetry(failureCount int) time.Duration {
	interval := initialARIErrorRetry
	for i := 1; i < failureCount && interval < defaultARIPollInterval; i++ {
		interval *= 2
	}
	if interval > defaultARIPollInterval {
		return defaultARIPollInterval
	}
	return interval
}

func classifyExternalARIError(err error) string {
	switch {
	case errors.Is(err, egress.ErrBlocked), errors.Is(err, netsec.ErrSSRFBlocked):
		return "egress_refused"
	case errors.Is(err, context.DeadlineExceeded):
		return "upstream_timeout"
	default:
		return "upstream_unavailable"
	}
}
