// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const externalARIDiscoveryLimit = 100

// discoverExternalARICandidates emits at most one hundred initial fetch
// commands per sweep. The chosen issuer comes from an authenticated immutable
// certificate fact, never the identity's editable current CA selection. No
// upstream HTTP happens here: the event projector writes a same-transaction
// outbox intent owned by the external-CA worker bulkhead.
func (s *Server) discoverExternalARICandidates(ctx context.Context, at time.Time) (int, error) {
	if s.externalCAs == nil || s.store == nil || s.log == nil || s.proj == nil {
		return 0, nil
	}
	ids := make([]string, 0, len(s.externalCAs.byID))
	for id, entry := range s.externalCAs.byID {
		if entry.meta.Type == "letsencrypt" && entry.ariFetch != nil {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	queued := 0
	for _, authorityID := range ids {
		entry := s.externalCAs.byID[authorityID]
		tenants, err := s.store.TenantsWithMissingACMEUpstreamARI(ctx, authorityID, entry.tenantID, at, externalARIDiscoveryLimit)
		if err != nil {
			return queued, err
		}
		for _, tenantID := range tenants {
			remaining := externalARIDiscoveryLimit - queued
			if remaining == 0 {
				return queued, nil
			}
			candidates, err := s.store.ListMissingACMEUpstreamARI(ctx, tenantID, store.ZeroUUID, authorityID, at, remaining)
			if err != nil {
				return queued, err
			}
			for _, candidate := range candidates {
				if err := s.requestExternalARI(ctx, tenantID, candidate, projections.ACMEUpstreamARIProvenanceAuthenticatedIssuer); err != nil {
					return queued, err
				}
				queued++
			}
		}
	}
	discovered, err := s.discoverIssuerKeyIDARICandidates(ctx, ids, at, externalARIDiscoveryLimit-queued)
	return queued + discovered, err
}

// discoverIssuerKeyIDARICandidates is the A51 pass: discovered leaves with no
// authenticated issuer are matched by Authority Key Identifier to the
// authorities that declare ari_issuer_key_ids. The match is made here, on the
// retained public leaf, and re-made by the worker before any upstream GET.
// Leaves that match no authority are inspected again on the next sweep; the
// per-sweep page keeps that bounded.
func (s *Server) discoverIssuerKeyIDARICandidates(ctx context.Context, authorityIDs []string, at time.Time, limit int) (int, error) {
	declaring := make([]string, 0, len(authorityIDs))
	for _, id := range authorityIDs {
		if len(s.externalCAs.byID[id].ariIssuerKeyIDs) > 0 {
			declaring = append(declaring, id)
		}
	}
	if len(declaring) == 0 || limit <= 0 {
		return 0, nil
	}
	queued := 0
	seen := map[string]struct{}{}
	for _, authorityID := range declaring {
		entry := s.externalCAs.byID[authorityID]
		tenants, err := s.store.TenantsWithDiscoveredLeavesMissingACMEUpstreamARI(ctx, entry.tenantID, at, externalARIDiscoveryLimit)
		if err != nil {
			return queued, err
		}
		for _, tenantID := range tenants {
			if _, done := seen[tenantID]; done {
				continue
			}
			seen[tenantID] = struct{}{}
			candidates, err := s.store.ListDiscoveredLeavesMissingACMEUpstreamARI(ctx, tenantID, store.ZeroUUID, at, externalARIDiscoveryLimit)
			if err != nil {
				return queued, err
			}
			for _, candidate := range candidates {
				if queued >= limit {
					return queued, nil
				}
				matched, ok := s.matchDiscoveredLeafToAuthority(tenantID, candidate, declaring)
				if !ok {
					continue
				}
				if err := s.requestExternalARI(ctx, tenantID, matched, projections.ACMEUpstreamARIProvenanceIssuerKeyID); err != nil {
					return queued, err
				}
				queued++
			}
		}
	}
	return queued, nil
}

// matchDiscoveredLeafToAuthority reads the leaf's Authority Key Identifier and
// returns the candidate bound to the first declaring authority (in id order)
// that is configured for the tenant and names that key id.
func (s *Server) matchDiscoveredLeafToAuthority(tenantID string, candidate store.ACMEUpstreamARIDiscoveredCandidate, declaring []string) (store.ACMEUpstreamARICandidate, bool) {
	leaf, err := certinfo.Inspect(candidate.CertificateDER)
	if err != nil || leaf.IsCA || leaf.AuthorityKeyID == "" {
		return store.ACMEUpstreamARICandidate{}, false
	}
	for _, authorityID := range declaring {
		entry := s.externalCAs.byID[authorityID]
		if entry.tenantID != "" && entry.tenantID != tenantID {
			continue
		}
		if entry.matchesARIIssuer(leaf.AuthorityKeyID) {
			return store.ACMEUpstreamARICandidate{
				CertificateID: candidate.CertificateID, AuthorityID: authorityID, Fingerprint: candidate.Fingerprint,
				Serial: candidate.Serial, CertificateDER: candidate.CertificateDER, NotAfter: candidate.NotAfter,
			}, true
		}
	}
	return store.ACMEUpstreamARICandidate{}, false
}

func (s *Server) requestExternalARI(ctx context.Context, tenantID string, candidate store.ACMEUpstreamARICandidate, provenance string) error {
	leaf, err := certinfo.Inspect(candidate.CertificateDER)
	if err != nil || leaf.IsCA || leaf.SHA256Fingerprint != candidate.Fingerprint ||
		leaf.SerialNumber != candidate.Serial || !leaf.NotAfter.Equal(candidate.NotAfter) {
		return errors.New("server: external ACME ARI candidate differs from signed public leaf")
	}
	certID, err := certinfo.ARICertID(candidate.CertificateDER)
	if err != nil {
		return fmt.Errorf("server: derive external ACME ARI certificate identifier: %w", err)
	}
	payload := projections.ACMEUpstreamARIRequested{
		CertificateID: candidate.CertificateID, AuthorityID: candidate.AuthorityID,
		ARICertificateID: certID, Fingerprint: candidate.Fingerprint,
	}
	if provenance == projections.ACMEUpstreamARIProvenanceIssuerKeyID {
		payload.Provenance = provenance
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("external-ari-requested\x00"+tenantID+"\x00"+candidate.CertificateID)).String()
	canonical, found, err := s.log.EventByID(ctx, eventID)
	if err != nil {
		return err
	}
	if !found {
		canonical, err = s.log.Append(ctx, events.Event{
			ID: eventID, Type: projections.EventACMEUpstreamARIRequested,
			TenantID: tenantID, Data: data,
		})
		if err != nil {
			return err
		}
	}
	if canonical.Type != projections.EventACMEUpstreamARIRequested || canonical.TenantID != tenantID ||
		string(canonical.Data) != string(data) {
		return errors.New("server: retained external ACME ARI request differs from exact certificate")
	}
	return s.proj.Apply(ctx, canonical)
}
