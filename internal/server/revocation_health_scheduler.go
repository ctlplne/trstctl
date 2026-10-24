// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	adcsdiscovery "trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/revocationhealth"
	"trstctl.com/trstctl/internal/store"
)

const (
	revocationHealthInterval    = time.Hour
	revocationHealthStaleWithin = 24 * time.Hour
	revocationInventoryPageSize = 500
	revocationInventorySweepMax = 10_000
)

var revocationProbeNamespace = uuid.MustParse("69739a66-fbb7-5d8a-98e3-09dbf0e6e1cf")

type revocationIssuer struct {
	Subject     string
	Fingerprint string
	DER         []byte
}

// RunRevocationHealthScheduler is the only production producer of R1 probe
// work. It derives public endpoint context from inventory and queues bounded
// network-role relay jobs through the event/outbox spine.
func (s *Server) RunRevocationHealthScheduler(ctx context.Context) {
	if s.orch == nil || s.store == nil {
		return
	}
	sweep := func() {
		queued, err := s.RunRevocationHealthOnce(ctx)
		if err != nil && s.logger != nil {
			s.logger.Warn("revocation health scheduler sweep failed", slog.String("error", err.Error()))
		}
		if queued > 0 && s.logger != nil {
			s.logger.Info("revocation health scheduler queued endpoints", slog.Int("queued", queued))
		}
	}
	sweep()
	ticker := time.NewTicker(revocationHealthInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep()
		}
	}
}

// RunRevocationHealthOnce performs one deterministic database-clock sweep.
// Returns the number of distinct CRL/OCSP endpoints represented in queued jobs.
func (s *Server) RunRevocationHealthOnce(ctx context.Context) (int, error) {
	if s.orch == nil || s.store == nil {
		return 0, nil
	}
	now, err := s.store.DatabaseTime(ctx)
	if err != nil {
		return 0, err
	}
	bucket := now.Truncate(revocationHealthInterval).Format(time.RFC3339)
	tenants, err := s.store.TenantsWithRevocationProbeCandidates(ctx)
	if err != nil {
		return 0, err
	}
	queued := 0
	var firstErr error
	for _, tenantID := range tenants {
		targets, err := s.revocationTargets(ctx, tenantID)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		plain, groups, err := s.groupLDAPRevocationTargets(ctx, tenantID, targets)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		n, err := s.queueRevocationBatches(ctx, tenantID, bucket, plain, nil, "")
		queued += n
		if err != nil && firstErr == nil {
			firstErr = err
		}
		for _, group := range groups {
			binding := group.binding
			n, err := s.queueRevocationBatches(ctx, tenantID, bucket, group.targets, &binding, group.agentID)
			queued += n
			if err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return queued, firstErr
}

// queueRevocationBatches queues targets in bounded batches. A batch with an
// LDAP binding (A107) is pinned to the binding's relay when the AD CS source
// names one, and its job ID names the binding, so it never collides with an
// HTTP batch of the same hour.
func (s *Server) queueRevocationBatches(ctx context.Context, tenantID, bucket string, targets []revocationhealth.Target,
	binding *revocationhealth.LDAPBinding, agentID string) (int, error) {
	queued := 0
	var firstErr error
	batches := (len(targets) + revocationhealth.MaxTargets - 1) / revocationhealth.MaxTargets
	for start := 0; start < len(targets); start += revocationhealth.MaxTargets {
		end := start + revocationhealth.MaxTargets
		if end > len(targets) {
			end = len(targets)
		}
		batch := append([]revocationhealth.Target(nil), targets[start:end]...)
		batchIndex := start/revocationhealth.MaxTargets + 1
		basis := tenantID + "\x00" + bucket + "\x00" +
			fmt.Sprintf("%d/%d\x00", batchIndex, batches) + strings.Join(revocationTargetIdentities(batch), ",")
		if binding != nil {
			basis += "\x00ldap:" + binding.SourceID
		}
		intent := revocationhealth.Intent{
			ID:     uuid.NewSHA1(revocationProbeNamespace, []byte(basis)).String(),
			Bucket: bucket, BatchIndex: batchIndex, BatchCount: batches, Targets: batch,
			StaleWithinSeconds: int(revocationHealthStaleWithin.Seconds()),
			RequiredAgentRole:  revocationhealth.RequiredRoleNetwork,
			RequiredAgentID:    agentID, LDAPBinding: binding,
		}
		_, inserted, err := s.orch.QueueRevocationProbe(ctx, tenantID, intent)
		if err != nil {
			if !errors.Is(err, store.ErrIdempotencyConflict) && firstErr == nil {
				firstErr = err
			}
			continue
		}
		if inserted {
			queued += len(batch)
		}
	}
	return queued, firstErr
}

// ldapRevocationGroup is the LDAP distribution points one AD CS binding reads.
type ldapRevocationGroup struct {
	binding revocationhealth.LDAPBinding
	agentID string
	targets []revocationhealth.Target
}

// groupLDAPRevocationTargets moves each LDAP distribution point to the AD CS
// discovery source whose configuration DN covers it (A107). One whose forest
// no source covers stays in the plain batches, where the relay reports that
// it needs a binding instead of dropping it.
func (s *Server) groupLDAPRevocationTargets(ctx context.Context, tenantID string, targets []revocationhealth.Target) ([]revocationhealth.Target, []ldapRevocationGroup, error) {
	var plain, ldapTargets []revocationhealth.Target
	for _, target := range targets {
		if target.Protocol == revocationhealth.ProtocolCRL && revocationhealth.IsLDAPEndpoint(target.Endpoint) {
			ldapTargets = append(ldapTargets, target)
			continue
		}
		plain = append(plain, target)
	}
	if len(ldapTargets) == 0 {
		return targets, nil, nil
	}
	sources, err := s.store.ListDiscoverySourcesOfKind(ctx, tenantID, adcsdiscovery.SourceKind)
	if err != nil {
		return nil, nil, err
	}
	var candidates []ldapRevocationGroup
	for _, source := range sources {
		resolved, err := adcsdiscovery.ResolveInventoryIntent(source.Config)
		if err != nil {
			continue // a source whose configuration no longer resolves binds nothing
		}
		candidates = append(candidates, ldapRevocationGroup{agentID: resolved.RequiredAgentID, binding: revocationhealth.LDAPBinding{
			SourceID: source.ID, URL: resolved.URL, ConfigurationDN: resolved.ConfigurationDN,
			BindDN: resolved.BindDN, PasswordRef: resolved.PasswordRef, InsecureSkipVerify: resolved.InsecureSkipVerify,
		}})
	}
	for _, target := range ldapTargets {
		matched := false
		if dn, err := revocationhealth.LDAPEndpointDN(target.Endpoint); err == nil {
			for i := range candidates {
				if revocationhealth.LDAPDNWithin(dn, candidates[i].binding.ConfigurationDN) {
					candidates[i].targets = append(candidates[i].targets, target)
					matched = true
					break
				}
			}
		}
		if !matched {
			plain = append(plain, target)
		}
	}
	revocationhealth.SortTargets(plain)
	var groups []ldapRevocationGroup
	for _, candidate := range candidates {
		if len(candidate.targets) > 0 {
			revocationhealth.SortTargets(candidate.targets)
			groups = append(groups, candidate)
		}
	}
	return plain, groups, nil
}

func (s *Server) revocationTargets(ctx context.Context, tenantID string) ([]revocationhealth.Target, error) {
	certificates, err := s.revocationInventory(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	issuers, err := s.revocationIssuers(ctx, tenantID, certificates)
	if err != nil {
		return nil, err
	}
	byKey := map[string]revocationhealth.Target{}
	for _, certificate := range certificates {
		if certificate.Status != "active" || len(certificate.CertificateDER) == 0 {
			continue
		}
		leafDER, err := certinfo.LeafDER(certificate.CertificateDER)
		if err != nil {
			continue
		}
		info, err := certinfo.Inspect(leafDER)
		if err != nil {
			continue
		}
		issuer := matchRevocationIssuer(leafDER, info.Issuer, issuers)
		for _, endpoint := range info.CRLDistributionPoints {
			upsertRevocationTarget(byKey, buildRevocationTarget(certificate, info, leafDER, issuer, revocationhealth.ProtocolCRL, endpoint))
		}
		for _, endpoint := range info.OCSPServers {
			upsertRevocationTarget(byKey, buildRevocationTarget(certificate, info, leafDER, issuer, revocationhealth.ProtocolOCSP, endpoint))
		}
	}
	targets := make([]revocationhealth.Target, 0, len(byKey))
	for _, target := range byKey {
		if err := revocationhealth.ValidateTarget(target); err == nil {
			targets = append(targets, target)
		}
	}
	revocationhealth.SortTargets(targets)
	return targets, nil
}

func (s *Server) revocationInventory(ctx context.Context, tenantID string) ([]store.Certificate, error) {
	certificates := make([]store.Certificate, 0, revocationInventoryPageSize)
	afterID := "00000000-0000-0000-0000-000000000000"
	for len(certificates) < revocationInventorySweepMax {
		page, err := s.store.ListCertificatesPage(ctx, tenantID, afterID, nil, revocationInventoryPageSize, nil)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, page...)
		if len(page) < revocationInventoryPageSize {
			break
		}
		afterID = page[len(page)-1].ID
	}
	return certificates, nil
}

func (s *Server) revocationIssuers(ctx context.Context, tenantID string, certificates []store.Certificate) ([]revocationIssuer, error) {
	var issuers []revocationIssuer
	authorities, err := s.store.ListCAAuthorities(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, authority := range authorities {
		if authority.Status != "active" || strings.TrimSpace(authority.CertificatePEM) == "" {
			continue
		}
		der, err := certinfo.LeafDER([]byte(authority.CertificatePEM))
		if err != nil {
			continue
		}
		info, err := certinfo.Inspect(der)
		if err == nil {
			issuers = append(issuers, revocationIssuer{Subject: info.Subject, Fingerprint: info.SHA256Fingerprint, DER: der})
		}
	}
	for _, certificate := range certificates {
		if certificate.Status != "active" || len(certificate.CertificateDER) == 0 {
			continue
		}
		der, err := certinfo.LeafDER(certificate.CertificateDER)
		if err != nil {
			continue
		}
		info, err := certinfo.Inspect(der)
		if err == nil && info.IsCA {
			issuers = append(issuers, revocationIssuer{Subject: info.Subject, Fingerprint: info.SHA256Fingerprint, DER: der})
		}
	}
	sort.Slice(issuers, func(i, j int) bool { return issuers[i].Fingerprint < issuers[j].Fingerprint })
	return issuers, nil
}

func matchRevocationIssuer(leafDER []byte, issuerSubject string, candidates []revocationIssuer) revocationIssuer {
	for _, candidate := range candidates {
		if candidate.Subject == issuerSubject && crypto.VerifyLeafSignedByCA(leafDER, candidate.DER) == nil {
			return candidate
		}
	}
	for _, candidate := range candidates {
		if crypto.VerifyLeafSignedByCA(leafDER, candidate.DER) == nil {
			return candidate
		}
	}
	return revocationIssuer{Subject: issuerSubject}
}

func buildRevocationTarget(certificate store.Certificate, info certinfo.Info, leafDER []byte, issuer revocationIssuer, protocol, endpoint string) revocationhealth.Target {
	endpoint = strings.TrimSpace(endpoint)
	issuerIdentity := issuer.Fingerprint
	if issuerIdentity == "" {
		issuerIdentity = issuer.Subject
	}
	key := crypto.SHA256Hex([]byte(protocol + "\x00" + endpoint + "\x00" + issuerIdentity))
	return revocationhealth.Target{
		Key: key, Protocol: protocol, Endpoint: endpoint,
		IssuerSubject: issuer.Subject, IssuerFingerprint: issuer.Fingerprint, IssuerDER: issuer.DER,
		CertificateID: certificate.ID, CertificateSubject: info.Subject,
		CertificateFingerprint: info.SHA256Fingerprint, CertificateSerial: info.SerialNumber,
		CertificateDER: leafDER,
	}
}

func upsertRevocationTarget(targets map[string]revocationhealth.Target, candidate revocationhealth.Target) {
	current, exists := targets[candidate.Key]
	if !exists || candidate.CertificateFingerprint < current.CertificateFingerprint {
		targets[candidate.Key] = candidate
	}
}

func revocationTargetIdentities(targets []revocationhealth.Target) []string {
	identities := make([]string, 0, len(targets))
	for _, target := range targets {
		// The endpoint key deliberately excludes the representative leaf. The
		// scheduled job ID includes it: if inventory replaces that leaf inside
		// one hourly bucket, the new OCSP serial is new work, not an ignored
		// idempotency conflict against an older command body.
		identities = append(identities, target.Key+"@"+target.CertificateFingerprint+"@"+target.CertificateSerial)
	}
	return identities
}
