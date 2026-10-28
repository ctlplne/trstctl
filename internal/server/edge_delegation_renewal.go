// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A220: a host re-requests its delegated edge CA over the agent channel, with
// a fresh TPM attestation, inside the renewal window before expiry, where the
// segment's operator allowed it. The renewal is held to the mint's gate (the
// same attestation verifier, the segment's current roots, constraints and
// provider allowlist) and keeps the delegated CA's key. The 30-day bound
// stays: the renewed delegation gets the old one's lifetime, and a delegation
// that already expired, was revoked or was renewed does not renew. A refused
// renewal leaves the delegation to expire.

const (
	defaultEdgeRenewalWindowDays = 7
	maxEdgeRenewalWindowDays     = 29
)

// errEdgeRenewalTooEarly is a renewal asked for before the window opens.
var errEdgeRenewalTooEarly = errors.New("edge delegation renewal window is not open")

// edgeRenewalWindow is how long before expiry a delegation may renew.
func edgeRenewalWindow(p store.EdgeSegmentPolicy) time.Duration {
	days := p.RenewalWindowDays
	if days <= 0 {
		days = defaultEdgeRenewalWindowDays
	}
	return time.Duration(days) * 24 * time.Hour
}

func edgeRootsPEM(p store.EdgeSegmentPolicy) [][]byte {
	roots := make([][]byte, 0, len(p.AttestationRootsPEM))
	for _, root := range p.AttestationRootsPEM {
		roots = append(roots, []byte(root))
	}
	return roots
}

// edgeAttestationRefusal maps a verifier refusal onto the API's error kinds.
func edgeAttestationRefusal(err error) error {
	if errors.Is(err, deviceattest.ErrEdgeCSRInvalid) {
		return fmt.Errorf("%w: %s", api.ErrEdgeDelegationInvalid, err.Error())
	}
	return fmt.Errorf("%w: %s", api.ErrEdgeDelegationRefused, err.Error())
}

// edgeMint is everything mintAndRecord signs and records.
type edgeMint struct {
	segmentID, caID, host, commonName string
	ttl                               time.Duration
	csrDER                            []byte
	policy                            store.EdgeSegmentPolicy
	provider                          string
	custody                           edgeCustodyEvidence
	attestation                       deviceattest.EdgeCAAttestation
	renewedFrom                       string
}

// mintAndRecord signs the delegated CA under the parent CA with the
// segment's constraints and records it. Constraints come from the segment's
// POLICY, never from the request: an edge host does not get to choose its
// own scope.
func (s *edgeDelegationService) mintAndRecord(ctx context.Context, tenantID string, m edgeMint) (store.EdgeDelegation, error) {
	ca, err := s.store.GetCAAuthority(ctx, tenantID, m.caID)
	if err != nil {
		return store.EdgeDelegation{}, err
	}
	if ca.Status != "active" {
		return store.EdgeDelegation{}, fmt.Errorf("%w: CA %s is %s", api.ErrEdgeDelegationRefused, m.caID, ca.Status)
	}
	parentSigner, err := s.signerForAuthority(ctx, ca)
	if err != nil {
		return store.EdgeDelegation{}, err
	}
	parentDER, err := firstCertDER(ca.CertificatePEM)
	if err != nil {
		return store.EdgeDelegation{}, err
	}
	issued, err := crypto.MintDelegatedEdgeCAFromCSR(parentDER, parentSigner, m.csrDER, crypto.EdgeCARequest{
		CommonName:          m.commonName,
		PermittedDNSDomains: m.policy.PermittedDNSDomains,
		ExcludedDNSDomains:  m.policy.ExcludedDNSDomains,
		TTL:                 m.ttl,
	})
	if err != nil {
		return store.EdgeDelegation{}, fmt.Errorf("%w: %v", api.ErrEdgeDelegationInvalid, err)
	}
	info, err := certinfo.Inspect(issued.CertificateDER)
	if err != nil {
		return store.EdgeDelegation{}, err
	}
	id := uuid.NewString()
	if err := s.orch.RecordEdgeDelegationIssued(ctx, tenantID, projections.EdgeDelegationIssued{
		ID: id, SegmentID: m.segmentID, CAID: m.caID, Host: m.host,
		CommonName: issued.CommonName, Serial: issued.Serial,
		// Persist the exact chain returned to the host. The event is the
		// recovery source after a lost mint response or a projection rebuild;
		// storing only the delegated certificate made the parent disappear.
		CertificatePEM:        string(issued.CertificatePEM) + ca.CertificatePEM,
		PermittedDNSDomains:   m.policy.PermittedDNSDomains,
		ExcludedDNSDomains:    m.policy.ExcludedDNSDomains,
		AttestedKeySHA256:     crypto.SHA256Hex(m.attestation.Attested.PublicKeySHA256),
		AttestationCertSHA256: crypto.SHA256Hex(m.attestation.Attested.AttestationCertificateSHA256),
		CSRKeySHA256:          crypto.SHA256Hex(m.attestation.CSRKeySHA256),
		KeyProvider:           m.provider,
		KeyStorage:            m.custody.storage,
		KeyExportable:         m.custody.exportable,
		CustodyAssurance:      m.custody.assurance,
		NotBefore:             info.NotBefore, NotAfter: info.NotAfter,
		RenewedFrom: m.renewedFrom,
	}); err != nil {
		return store.EdgeDelegation{}, err
	}
	delegation, _, err := s.store.GetEdgeDelegation(ctx, tenantID, id)
	return delegation, err
}

func (s *edgeDelegationService) renewedBy(ctx context.Context, tenantID, id string) (string, error) {
	return s.store.EdgeDelegationRenewedBy(ctx, tenantID, id)
}

// edgeRenewal is a host's re-request for the delegation whose certificate
// serial it holds.
type edgeRenewal struct {
	host, serial   string
	csrDER         []byte
	credentialJSON []byte
}

// RenewDelegation renews the host's delegation with the given serial.
func (s *edgeDelegationService) RenewDelegation(ctx context.Context, tenantID string, r edgeRenewal) (api.EdgeDelegation, error) {
	rows, err := s.store.ListEdgeDelegations(ctx, tenantID)
	if err != nil {
		return api.EdgeDelegation{}, err
	}
	serial := normalizeEdgeSerial(r.serial)
	var current *store.EdgeDelegation
	renewedBy := map[string]string{}
	for i := range rows {
		if rows[i].RenewedFrom != "" {
			renewedBy[rows[i].RenewedFrom] = rows[i].ID
		}
		if strings.EqualFold(strings.TrimSpace(rows[i].Host), strings.TrimSpace(r.host)) && serial != "" && normalizeEdgeSerial(rows[i].Serial) == serial {
			current = &rows[i]
		}
	}
	if current == nil {
		return api.EdgeDelegation{}, fmt.Errorf("%w: no delegation of host %s has serial %s", api.ErrEdgeDelegationNotFound, r.host, r.serial)
	}
	now := time.Now().UTC()
	switch {
	case renewedBy[current.ID] != "":
		return api.EdgeDelegation{}, fmt.Errorf("%w: delegation %s was already renewed as %s; renew the newest one",
			api.ErrEdgeDelegationRefused, current.ID, renewedBy[current.ID])
	case current.RevokedAt != nil || current.Status == "revoked":
		return api.EdgeDelegation{}, fmt.Errorf("%w: delegation %s is revoked", api.ErrEdgeDelegationRefused, current.ID)
	case current.Expired(now):
		return api.EdgeDelegation{}, fmt.Errorf("%w: delegation %s expired; an expired delegation does not renew, the host asks again through the attested mint",
			api.ErrEdgeDelegationRefused, current.ID)
	}
	policy, found, err := s.store.GetEdgeSegmentPolicy(ctx, tenantID, current.SegmentID)
	if err != nil {
		return api.EdgeDelegation{}, err
	}
	if !found || !policy.Enabled {
		return api.EdgeDelegation{}, fmt.Errorf("%w: segment %s no longer opts in to edge delegation", api.ErrEdgeDelegationRefused, current.SegmentID)
	}
	if !policy.RenewalEnabled {
		return api.EdgeDelegation{}, fmt.Errorf("%w: segment %s does not let hosts renew over the agent channel", api.ErrEdgeDelegationRefused, current.SegmentID)
	}
	if opens := current.NotAfter.Add(-edgeRenewalWindow(policy)); now.Before(opens) {
		return api.EdgeDelegation{}, fmt.Errorf("%w: delegation %s may renew from %s", errEdgeRenewalTooEarly, current.ID, opens.Format(time.RFC3339))
	}
	provider, custody, err := edgeCustodyForProvider(current.KeyProvider)
	if err != nil {
		return api.EdgeDelegation{}, fmt.Errorf("%w: %v", api.ErrEdgeDelegationInvalid, err)
	}
	if !containsEdgeProvider(policy.AllowedKeyProviders, provider) {
		return api.EdgeDelegation{}, fmt.Errorf("%w: key provider %s is no longer allowed by segment policy", api.ErrEdgeDelegationRefused, provider)
	}
	attestation, err := deviceattest.VerifyEdgeCAAttestation(r.credentialJSON, tenantID, current.SegmentID, r.csrDER, edgeRootsPEM(policy), provider, now)
	if err != nil {
		return api.EdgeDelegation{}, edgeAttestationRefusal(err)
	}
	if crypto.SHA256Hex(attestation.CSRKeySHA256) != edgeRecordedCSRKey(*current) {
		return api.EdgeDelegation{}, fmt.Errorf("%w: the renewal CSR is not for the delegated CA's key; a renewal keeps the key",
			api.ErrEdgeDelegationRefused)
	}
	lifetime := current.NotAfter.Sub(current.NotBefore)
	if lifetime > time.Hour {
		lifetime = lifetime.Truncate(time.Hour)
	}
	delegation, err := s.mintAndRecord(ctx, tenantID, edgeMint{
		segmentID: current.SegmentID, caID: current.CAID, host: current.Host, commonName: current.CommonName,
		ttl: lifetime, csrDER: r.csrDER, policy: policy, provider: provider, custody: custody,
		attestation: attestation, renewedFrom: current.ID,
	})
	if err != nil {
		return api.EdgeDelegation{}, err
	}
	return edgeDelegationView(delegation, now), nil
}

// edgeRecordedCSRKey is the delegated CA key digest a delegation recorded;
// delegations minted before the CSR digest existed recorded the attested key.
func edgeRecordedCSRKey(d store.EdgeDelegation) string {
	if d.CSRKeySHA256 != "" {
		return d.CSRKeySHA256
	}
	return d.AttestedKeySHA256
}

func normalizeEdgeSerial(serial string) string {
	return strings.TrimLeft(strings.ToLower(strings.ReplaceAll(strings.TrimSpace(serial), ":", "")), "0")
}
