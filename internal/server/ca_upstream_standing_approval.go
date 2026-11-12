// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A standing approval for one SPIRE server's upstream CA requests (OD-8,
// A205-L1). SPIRE rotates its CA on its own schedule, so a key ceremony per
// CSR stops it at every rotation. A ceremony (quorum, like any other) grants
// the approval once instead; it is opt-in and bound to the authority, the
// caller's principal (the plugin's token subject), the SPIFFE trust domain
// every signed CA must name, and the CA spec with its longest lifetime, and
// it expires. Every signing under it is in the event log and counted, and an
// issuers:write administrator can revoke it at once.

const (
	// maxStandingApprovalValidity bounds how long one approval lasts.
	maxStandingApprovalValidity = 90 * 24 * time.Hour
	// operationGrantUpstreamStandingApproval is the ceremony operation.
	operationGrantUpstreamStandingApproval = "grant_upstream_standing_approval"
)

// upstreamStandingApprovalPurpose is the ceremony purpose of a grant: the
// authority, the principal, the trust domain, the validity and the spec, so
// the approved grant is exactly the one executed.
func upstreamStandingApprovalPurpose(caID, principal, trustDomain string, validForSeconds int64, spec api.CASpec) (string, error) {
	if strings.TrimSpace(caID) == "" {
		return "", fmt.Errorf("%w: authority_id is required for %s", api.ErrCAHierarchyInvalid, operationGrantUpstreamStandingApproval)
	}
	if principal == "" || len(principal) > 512 || strings.TrimSpace(principal) != principal ||
		strings.IndexFunc(principal, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("%w: principal is the SPIRE server's token subject (1 to 512 characters, no spaces at either end)", api.ErrCAHierarchyInvalid)
	}
	if err := projections.ValidateSPIFFETrustDomain(trustDomain); err != nil {
		return "", fmt.Errorf("%w: trust_domain: %v", api.ErrCAHierarchyInvalid, err)
	}
	if validForSeconds <= 0 || validForSeconds > int64(maxStandingApprovalValidity/time.Second) {
		return "", fmt.Errorf("%w: valid_for_seconds must be positive and at most 90 days", api.ErrCAHierarchyInvalid)
	}
	if spec.TTLSeconds <= 0 {
		return "", fmt.Errorf("%w: spec.ttl_seconds, the longest lifetime of a CA it signs, must be positive", api.ErrCAHierarchyInvalid)
	}
	if err := validateCASpec(spec); err != nil {
		return "", err
	}
	specPurpose, err := hierarchyPurpose("create_intermediate", caID, spec)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(struct {
		CAID            string `json:"ca_id"`
		Principal       string `json:"principal"`
		TrustDomain     string `json:"trust_domain"`
		ValidForSeconds int64  `json:"valid_for_seconds"`
		Spec            string `json:"spec"`
	}{caID, principal, trustDomain, validForSeconds, specPurpose})
	if err != nil {
		return "", err
	}
	return "upstream-standing:" + crypto.SHA256Hex(payload), nil
}

// upstreamStandingApprovalCeremonyPurpose validates a grant ceremony against
// its authority: an online, active issuer and at least two custodians.
func (h *caHierarchyService) upstreamStandingApprovalCeremonyPurpose(ctx context.Context, tenantID string, req api.CACeremonyStartRequest) (string, error) {
	if req.Threshold < 2 {
		return "", fmt.Errorf("%w: a standing approval needs at least two distinct custodians", api.ErrCAHierarchyInvalid)
	}
	authorityID := strings.TrimSpace(req.AuthorityID)
	purpose, err := upstreamStandingApprovalPurpose(authorityID, req.Principal, req.TrustDomain, req.ValidForSeconds, req.Spec)
	if err != nil {
		return "", err
	}
	issuer, err := h.store.GetCAAuthority(ctx, tenantID, authorityID)
	if err != nil {
		return "", err
	}
	if err := validateOnlineCeremonyIssuer(issuer); err != nil {
		return "", err
	}
	return purpose, nil
}

// GrantUpstreamStandingApproval executes an approved grant ceremony.
func (h *caHierarchyService) GrantUpstreamStandingApproval(ctx context.Context, tenantID, caID string, req api.CAUpstreamStandingApprovalGrantRequest) (api.CAUpstreamStandingApproval, error) {
	if strings.TrimSpace(req.CeremonyID) == "" {
		return api.CAUpstreamStandingApproval{}, fmt.Errorf("%w: ceremony_id is required", api.ErrCAHierarchyInvalid)
	}
	purpose, err := upstreamStandingApprovalPurpose(caID, req.Principal, req.TrustDomain, req.ValidForSeconds, req.Spec)
	if err != nil {
		return api.CAUpstreamStandingApproval{}, err
	}
	issuer, err := h.store.GetCAAuthority(ctx, tenantID, caID)
	if err != nil {
		return api.CAUpstreamStandingApproval{}, err
	}
	if err := validateOnlineCeremonyIssuer(issuer); err != nil {
		return api.CAUpstreamStandingApproval{}, err
	}
	approvalID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenantID+"\x00upstream-standing-approval\x00"+req.CeremonyID)).String()
	var granted events.Event
	err = h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := h.store.ConsumeKeyCeremonyTx(ctx, tx, tenantID, req.CeremonyID, purpose); err != nil {
			return err
		}
		var err error
		granted, err = h.appendEvent(ctx, tenantID, projections.EventCAUpstreamStandingApprovalGranted, projections.CAUpstreamStandingApprovalGranted{
			ApprovalID: approvalID, CAID: caID, Principal: req.Principal, TrustDomain: req.TrustDomain,
			Spec: projections.CAUpstreamStandingApprovalSpec{CommonName: req.Spec.CommonName, PermittedDNSDomains: req.Spec.PermittedDNSDomains,
				MaxPathLen: req.Spec.MaxPathLen, ExtendedKeyUsages: req.Spec.ExtendedKeyUsages, TTLSeconds: req.Spec.TTLSeconds,
				SignatureAlgorithm: req.Spec.SignatureAlgorithm},
			CeremonyID: req.CeremonyID,
			ExpiresAt:  time.Now().UTC().Add(time.Duration(req.ValidForSeconds) * time.Second),
		})
		return err
	})
	if err != nil {
		return api.CAUpstreamStandingApproval{}, caHierarchyConflict(err)
	}
	if err := projections.New(h.store).Apply(ctx, granted); err != nil {
		return api.CAUpstreamStandingApproval{}, err
	}
	return h.upstreamStandingApproval(ctx, tenantID, caID, approvalID)
}

// RevokeUpstreamStandingApproval revokes an approval at once; the next CA CSR
// from its principal needs a ceremony again. Revoking a revoked approval
// changes nothing.
func (h *caHierarchyService) RevokeUpstreamStandingApproval(ctx context.Context, tenantID, caID, approvalID, reason string) (api.CAUpstreamStandingApproval, error) {
	current, err := h.upstreamStandingApproval(ctx, tenantID, caID, approvalID)
	if err != nil {
		return api.CAUpstreamStandingApproval{}, err
	}
	if current.RevokedAt != nil {
		return current, nil
	}
	revoked, err := h.appendEvent(ctx, tenantID, projections.EventCAUpstreamStandingApprovalRevoked, projections.CAUpstreamStandingApprovalRevoked{
		ApprovalID: approvalID, CAID: caID, Reason: reason,
	})
	if err != nil {
		return api.CAUpstreamStandingApproval{}, err
	}
	if err := projections.New(h.store).Apply(ctx, revoked); err != nil {
		return api.CAUpstreamStandingApproval{}, err
	}
	return h.upstreamStandingApproval(ctx, tenantID, caID, approvalID)
}

// ListUpstreamStandingApprovals lists an authority's approvals.
func (h *caHierarchyService) ListUpstreamStandingApprovals(ctx context.Context, tenantID, caID string) ([]api.CAUpstreamStandingApproval, error) {
	if _, err := h.store.GetCAAuthority(ctx, tenantID, caID); err != nil {
		return nil, err
	}
	rows, err := h.store.ListCAUpstreamStandingApprovals(ctx, tenantID, caID)
	if err != nil {
		return nil, err
	}
	out := make([]api.CAUpstreamStandingApproval, 0, len(rows))
	now := time.Now()
	for _, row := range rows {
		out = append(out, standingApprovalView(row, now))
	}
	return out, nil
}

func (h *caHierarchyService) upstreamStandingApproval(ctx context.Context, tenantID, caID, approvalID string) (api.CAUpstreamStandingApproval, error) {
	if _, err := uuid.Parse(approvalID); err != nil {
		return api.CAUpstreamStandingApproval{}, api.ErrCAUpstreamStandingApprovalNotFound
	}
	row, err := h.store.GetCAUpstreamStandingApproval(ctx, tenantID, approvalID)
	if errors.Is(err, store.ErrCAUpstreamStandingApprovalNotFound) || err == nil && row.CAID != caID {
		return api.CAUpstreamStandingApproval{}, api.ErrCAUpstreamStandingApprovalNotFound
	}
	if err != nil {
		return api.CAUpstreamStandingApproval{}, err
	}
	return standingApprovalView(row, time.Now()), nil
}

func standingApprovalView(row store.CAUpstreamStandingApproval, now time.Time) api.CAUpstreamStandingApproval {
	var spec api.CASpec
	_ = json.Unmarshal(row.Spec, &spec)
	status := "active"
	switch {
	case row.RevokedAt != nil:
		status = "revoked"
	case !now.Before(row.ExpiresAt):
		status = "expired"
	}
	return api.CAUpstreamStandingApproval{
		ID: row.ID, CAID: row.CAID, Principal: row.Principal, TrustDomain: row.TrustDomain, Spec: spec,
		CeremonyID: row.CeremonyID, GrantedBy: row.GrantedBy, GrantedAt: row.GrantedAt, ExpiresAt: row.ExpiresAt,
		Status: status, RevokedAt: row.RevokedAt, RevokedBy: row.RevokedBy, RevokeReason: row.RevokeReason,
		Signings: row.Signings, LastSignedAt: row.LastSignedAt,
	}
}

// sameApprovedSpec reports whether a request's CA spec is the approved one;
// only its lifetime may be shorter.
func sameApprovedSpec(approved, requested api.CASpec) bool {
	return approved.CommonName == requested.CommonName && approved.MaxPathLen == requested.MaxPathLen &&
		strings.EqualFold(approved.SignatureAlgorithm, requested.SignatureAlgorithm) &&
		slices.Equal(approved.PermittedDNSDomains, requested.PermittedDNSDomains) &&
		slices.Equal(approved.ExtendedKeyUsages, requested.ExtendedKeyUsages) &&
		requested.TTLSeconds > 0 && requested.TTLSeconds <= approved.TTLSeconds
}

// issueIntermediateCSRUnderStandingApproval signs a CA CSR sent without a
// ceremony when its caller holds an active approval at the authority and the
// CSR names exactly the approved trust domain within the approved spec.
func (h *caHierarchyService) issueIntermediateCSRUnderStandingApproval(ctx context.Context, tenantID, caID string, req api.CAIssueIntermediateRequest) (api.CAIssuedIntermediate, error) {
	principal := ""
	if a, ok := events.ActorFromContext(ctx); ok {
		principal = a.Subject
	}
	if principal == "" {
		return api.CAIssuedIntermediate{}, fmt.Errorf("%w: ceremony_id is required", api.ErrCAHierarchyInvalid)
	}
	if len(req.CSRDER) == 0 {
		return api.CAIssuedIntermediate{}, fmt.Errorf("%w: CSR is required", api.ErrCAHierarchyInvalid)
	}
	if err := validateCASpec(req.Spec); err != nil {
		return api.CAIssuedIntermediate{}, err
	}
	requested, err := crypto.CSRRequestedIdentifiers(req.CSRDER)
	if err != nil {
		return api.CAIssuedIntermediate{}, fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
	}
	ca, err := h.store.GetCAAuthority(ctx, tenantID, caID)
	if err != nil {
		return api.CAIssuedIntermediate{}, err
	}
	signer, err := h.signerForAuthority(ctx, ca)
	if err != nil {
		return api.CAIssuedIntermediate{}, err
	}
	caDER, err := firstCertDER(ca.CertificatePEM)
	if err != nil {
		return api.CAIssuedIntermediate{}, err
	}
	profile := cryptoProfile(req.Spec)
	if len(profile.PermittedDNSDomains) == 0 {
		profile.PermittedDNSDomains = append([]string(nil), ca.PermittedDNSNames...)
	}
	csrSHA := crypto.SHA256Hex(req.CSRDER)
	var issued crypto.IssuedHierarchyCA
	var info certinfo.Info
	var signed events.Event
	err = h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		approval, ok, err := h.store.ActiveCAUpstreamStandingApprovalTx(ctx, tx, tenantID, caID, principal, time.Now())
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: ceremony_id is required: %s holds no active standing approval at this authority", api.ErrCAHierarchyInvalid, principal)
		}
		var approved api.CASpec
		if err := json.Unmarshal(approval.Spec, &approved); err != nil {
			return err
		}
		want := "spiffe://" + approval.TrustDomain
		if len(requested.URIs) != 1 || requested.URIs[0] != want || len(requested.DNSNames) > 0 || len(requested.IPAddresses) > 0 ||
			len(requested.EmailAddresses) > 0 {
			return fmt.Errorf("%w: under its standing approval the CSR must name exactly %s and nothing else", api.ErrCAHierarchyInvalid, want)
		}
		if !sameApprovedSpec(approved, req.Spec) {
			return fmt.Errorf("%w: the CA spec is not the approved one, or its lifetime is longer than the approved %d seconds",
				api.ErrCAHierarchyInvalid, approved.TTLSeconds)
		}
		// The signed CA vouches for its trust domain's SPIFFE IDs only: a URI
		// name constraint every verifier enforces.
		profile.PermittedURIDomains = []string{approval.TrustDomain}
		if err := h.emit(ctx, tenantID, projections.EventCAIntermediateCSRSignRequested, map[string]any{
			"ca_id": caID, "ceremony_id": approval.CeremonyID, "csr_sha256": csrSHA,
		}); err != nil {
			return err
		}
		issued, err = crypto.SignIntermediateHierarchyCAFromCSR(caDER, signer, req.CSRDER, profile)
		if err != nil {
			return fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
		}
		info, err = certinfo.Inspect(issued.CertificateDER)
		if err != nil {
			return err
		}
		if err := h.emit(ctx, tenantID, projections.EventCAIntermediateCSRIssued, map[string]any{
			"ca_id": caID, "serial": info.SerialNumber, "subject": info.Subject, "ceremony_id": approval.CeremonyID,
			"csr_sha256": csrSHA,
		}); err != nil {
			return err
		}
		signed, err = h.appendEvent(ctx, tenantID, projections.EventCAUpstreamStandingApprovalSigned, projections.CAUpstreamStandingApprovalSigned{
			ApprovalID: approval.ID, CAID: caID, CSRSHA256: csrSHA, Serial: info.SerialNumber,
		})
		return err
	})
	if err != nil {
		return api.CAIssuedIntermediate{}, caHierarchyConflict(err)
	}
	if err := projections.New(h.store).Apply(ctx, signed); err != nil {
		return api.CAIssuedIntermediate{}, err
	}
	out := append([]byte{}, issued.CertificatePEM...)
	out = append(out, []byte(ca.CertificatePEM)...)
	return api.CAIssuedIntermediate{CertificatePEM: string(out), Serial: info.SerialNumber, NotAfter: info.NotAfter}, nil
}
