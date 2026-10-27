// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tlsvalidity"
)

// clientRenewedIssuance are the issuance-key prefixes of certificates trstctl
// issued to a client that renews them itself: served enrollment protocols,
// in-cluster Kubernetes issuance, attested workloads and the agent broker.
var clientRenewedIssuance = []string{"protocol-issue:", "k8s-auto:", "attested-issue:", "broker-issue:"}

// certificateBindingPage is CertificateIdentityBindings' largest page.
const certificateBindingPage = 1000

// ValidityReadiness is the server-owned dated lifetime-reduction readiness
// report (A178). It reads the scheduler's own configuration and the same
// renewable-identity inventory as the lifecycle automation plan, so a
// "scheduled" verdict means the identity the running scheduler would renew. It
// performs tenant-scoped reads only.
func (s *Server) ValidityReadiness(ctx context.Context, tenantID string, at time.Time) (tlsvalidity.Report, error) {
	at = at.UTC()
	scheduler := tlsvalidity.Scheduler{
		Enabled:     s.lifecycleRenewBefore > 0 && s.store != nil && s.orch != nil,
		RenewBefore: s.lifecycleRenewBefore,
	}
	if s.store == nil || s.orch == nil {
		return tlsvalidity.NewReport(at, scheduler, nil, nil, false, store.ValidityReadinessLimit), nil
	}
	certs, truncated, err := s.store.ListValidityReadinessCertificates(ctx, tenantID, at)
	if err != nil {
		return tlsvalidity.Report{}, err
	}
	inventory, err := s.store.ListLifecycleAutomationInventoryForReport(ctx, tenantID)
	if err != nil {
		return tlsvalidity.Report{}, err
	}
	renewable := make(map[string]store.LifecycleAutomationInventory, len(inventory))
	served := make(map[string]string, len(inventory))
	for _, row := range inventory {
		renewable[row.IdentityID] = row
		served[row.CertificateID] = row.IdentityID
	}
	bindings, err := s.validityCertificateBindings(ctx, tenantID, certs)
	if err != nil {
		return tlsvalidity.Report{}, err
	}
	scheduled := make(map[string]tlsvalidity.CertificateFacts)
	facts := make([]tlsvalidity.CertificateFacts, 0, len(certs))
	for _, cert := range certs {
		f := tlsvalidity.CertificateFacts{
			ID: cert.ID, Subject: cert.Subject, Issuer: cert.Issuer,
			Scope: tlsvalidity.ScopeUnknown, Automation: tlsvalidity.AutomationNone,
		}
		if cert.NotBefore != nil {
			f.NotBefore = *cert.NotBefore
		}
		if cert.NotAfter != nil {
			f.NotAfter = *cert.NotAfter
		}
		if len(cert.CertificateDER) > 0 {
			if info, err := certinfo.Inspect(cert.CertificateDER); err == nil {
				f.Scope = tlsvalidity.ClassifyCertificate(info.IsCA, info.ExtKeyUsages, info.PolicyOIDs)
				if f.NotBefore.IsZero() {
					f.NotBefore = info.NotBefore
				}
			}
		}
		switch identityID := renewableIdentity(cert.ID, served, bindings[cert.ID], renewable); {
		case identityID != "":
			identity, ok := scheduled[identityID]
			if !ok {
				identity, err = s.validityScheduledIdentity(ctx, tenantID, renewable[identityID])
				if err != nil {
					return tlsvalidity.Report{}, err
				}
				scheduled[identityID] = identity
			}
			f.Automation = tlsvalidity.AutomationScheduled
			f.IdentityID, f.IdentityName, f.Deployment = identity.IdentityID, identity.IdentityName, identity.Deployment
			f.Holds, f.ApprovalRequired, f.RenewalLifetime = identity.Holds, identity.ApprovalRequired, identity.RenewalLifetime
		case clientRenewed(cert.IssuanceIdempotencyKey):
			f.Automation = tlsvalidity.AutomationClient
		}
		facts = append(facts, f)
	}
	profiles, err := s.validityProfiles(ctx, tenantID)
	if err != nil {
		return tlsvalidity.Report{}, err
	}
	return tlsvalidity.NewReport(at, scheduler, facts, profiles, truncated, store.ValidityReadinessLimit), nil
}

// validityScheduledIdentity is the scheduler's view of one renewable identity:
// how its renewal reaches the endpoint, what holds it now, and what a renewal
// requests. The holds are the ones the automation plan and scheduler apply.
func (s *Server) validityScheduledIdentity(ctx context.Context, tenantID string, row store.LifecycleAutomationInventory) (tlsvalidity.CertificateFacts, error) {
	out := tlsvalidity.CertificateFacts{IdentityID: row.IdentityID, IdentityName: row.IdentityName, Holds: []string{}}
	switch {
	case row.DeliveryUnverified:
		out.Deployment = tlsvalidity.DeploymentFailed
	case row.DeployedStatus == "verified":
		out.Deployment = tlsvalidity.DeploymentVerified
	case row.DeployedStatus == "delivered" || row.DeployedStatus == "rolled_back":
		out.Deployment = tlsvalidity.DeploymentDelivered
	default:
		out.Deployment = tlsvalidity.DeploymentNone
	}
	if row.IdentityStatus == "renewal_failed" {
		out.Holds = append(out.Holds, tlsvalidity.ReasonRenewalFailed)
	}
	identity, err := s.store.GetIdentity(ctx, tenantID, row.IdentityID)
	if err != nil {
		return tlsvalidity.CertificateFacts{}, err
	}
	if _, paused := orchestrator.RenewalPausedTarget(identity); paused {
		out.Holds = append(out.Holds, tlsvalidity.ReasonRenewalPaused)
	}
	if row.TargetID != "" {
		conflicts, err := s.store.ConflictingTargetBindings(ctx, tenantID, row.TargetID, row.IdentityID, row.PredecessorID, false)
		if err != nil {
			return tlsvalidity.CertificateFacts{}, err
		}
		if len(conflicts) != 0 {
			out.Holds = append(out.Holds, tlsvalidity.ReasonTargetConflict)
		}
	}
	requirement, err := s.orch.ProfileApprovalRequirement(ctx, tenantID, row.IdentityID)
	switch {
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		return tlsvalidity.CertificateFacts{}, err
	case err != nil:
		// Renewal resolves the profile the same way and stops on the same
		// error — an inactive profile, or missing or mismatched retained
		// issuance evidence — so the next renewal fails until it is fixed.
		if s.logger != nil {
			s.logger.Warn("validity readiness: renewal profile unresolved", slog.String("tenant_id", tenantID),
				slog.String("identity_id", row.IdentityID), slog.String("error", err.Error()))
		}
		out.Holds = append(out.Holds, tlsvalidity.ReasonProfileUnavailable)
	default:
		out.ApprovalRequired = requirement.RequiresApproval
		out.RenewalLifetime = time.Duration(requirement.EffectiveTTLSeconds) * time.Second
	}
	return out, nil
}

// validityCertificateBindings resolves each certificate's lifecycle identities
// from retained issuance and delivery evidence, so a successor issued but not
// yet deployed is still recognized as its identity's.
func (s *Server) validityCertificateBindings(ctx context.Context, tenantID string, certs []store.Certificate) (map[string][]string, error) {
	out := make(map[string][]string, len(certs))
	for start := 0; start < len(certs); start += certificateBindingPage {
		end := min(start+certificateBindingPage, len(certs))
		ids := make([]string, 0, end-start)
		for _, cert := range certs[start:end] {
			ids = append(ids, cert.ID)
		}
		page, err := s.store.CertificateIdentityBindings(ctx, tenantID, ids)
		if err != nil {
			return nil, err
		}
		for id, identities := range page {
			out[id] = identities
		}
	}
	return out, nil
}

// renewableIdentity is the renewable identity a certificate belongs to: the one
// it is served for, else the first renewable identity its evidence binds.
func renewableIdentity(certificateID string, served map[string]string, bound []string, renewable map[string]store.LifecycleAutomationInventory) string {
	if identityID, ok := served[certificateID]; ok {
		return identityID
	}
	bound = append([]string(nil), bound...)
	sort.Strings(bound)
	for _, identityID := range bound {
		if _, ok := renewable[identityID]; ok {
			return identityID
		}
	}
	return ""
}

func clientRenewed(issuanceKey string) bool {
	for _, prefix := range clientRenewedIssuance {
		if strings.HasPrefix(issuanceKey, prefix) {
			return true
		}
	}
	return false
}

// validityProfiles reads every active profile's public-TLS statement and
// validity ceiling.
func (s *Server) validityProfiles(ctx context.Context, tenantID string) ([]tlsvalidity.ProfileFacts, error) {
	records, err := s.store.ListProfiles(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]tlsvalidity.ProfileFacts, 0, len(records))
	for _, record := range records {
		var spec profile.CertificateProfile
		if err := json.Unmarshal(record.Spec, &spec); err != nil {
			return nil, fmt.Errorf("server: decode profile %q v%d: %w", record.Name, record.Version, err)
		}
		out = append(out, tlsvalidity.ProfileFacts{
			Name: record.Name, Version: record.Version, PublicTLS: spec.PublicTLS,
			ServerAuth: spec.AllowsServerAuth(), MaxValidity: time.Duration(spec.MaxValidity),
		})
	}
	return out, nil
}
