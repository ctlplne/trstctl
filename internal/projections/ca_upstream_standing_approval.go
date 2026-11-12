// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// A standing approval for one SPIRE server's upstream CA requests (OD-8).
const (
	// EventCAUpstreamStandingApprovalGranted records an approval a ceremony
	// granted.
	EventCAUpstreamStandingApprovalGranted = "ca.upstream_standing_approval.granted"
	// EventCAUpstreamStandingApprovalRevoked records its revocation.
	EventCAUpstreamStandingApprovalRevoked = "ca.upstream_standing_approval.revoked"
	// EventCAUpstreamStandingApprovalSigned records one CA CSR signed under
	// it, beside the signing's own ca.intermediate_csr.* events.
	EventCAUpstreamStandingApprovalSigned = "ca.upstream_standing_approval.signed"
)

// CAUpstreamStandingApprovalSpec is the CA spec an approval signs under; its
// TTL is the maximum lifetime of a CA it signs.
type CAUpstreamStandingApprovalSpec struct {
	CommonName          string   `json:"common_name"`
	PermittedDNSDomains []string `json:"permitted_dns_domains"`
	MaxPathLen          int      `json:"max_path_len"`
	ExtendedKeyUsages   []string `json:"extended_key_usages"`
	TTLSeconds          int64    `json:"ttl_seconds"`
	SignatureAlgorithm  string   `json:"signature_algorithm"`
}

// CAUpstreamStandingApprovalGranted is a granted approval. The granting
// administrator is the event's actor.
type CAUpstreamStandingApprovalGranted struct {
	ApprovalID  string                         `json:"approval_id"`
	CAID        string                         `json:"ca_id"`
	Principal   string                         `json:"principal"`
	TrustDomain string                         `json:"trust_domain"`
	Spec        CAUpstreamStandingApprovalSpec `json:"spec"`
	CeremonyID  string                         `json:"ceremony_id"`
	ExpiresAt   time.Time                      `json:"expires_at"`
}

// CAUpstreamStandingApprovalRevoked is a revoked approval. The revoking
// administrator is the event's actor.
type CAUpstreamStandingApprovalRevoked struct {
	ApprovalID string `json:"approval_id"`
	CAID       string `json:"ca_id"`
	Reason     string `json:"reason"`
}

// CAUpstreamStandingApprovalSigned is one CA CSR signed under an approval.
type CAUpstreamStandingApprovalSigned struct {
	ApprovalID string `json:"approval_id"`
	CAID       string `json:"ca_id"`
	CSRSHA256  string `json:"csr_sha256"`
	Serial     string `json:"serial"`
}

var spiffeTrustDomainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,253}[a-z0-9])?$`)

// ValidateSPIFFETrustDomain checks a SPIFFE trust domain name: lowercase
// letters, digits, dots, dashes and underscores, as the SPIFFE ID spec
// allows.
func ValidateSPIFFETrustDomain(td string) error {
	if !spiffeTrustDomainRE.MatchString(td) {
		return fmt.Errorf("%q is not a SPIFFE trust domain", td)
	}
	return nil
}

// ValidateCAUpstreamStandingApprovalGranted checks a grant.
func ValidateCAUpstreamStandingApprovalGranted(pl CAUpstreamStandingApprovalGranted) error {
	if _, err := uuid.Parse(pl.ApprovalID); err != nil {
		return errors.New("an upstream standing approval needs a UUID approval_id")
	}
	if _, err := uuid.Parse(pl.CAID); err != nil {
		return errors.New("an upstream standing approval needs a UUID ca_id")
	}
	if pl.Principal == "" || len(pl.Principal) > 512 {
		return errors.New("an upstream standing approval names its principal (at most 512 characters)")
	}
	if err := ValidateSPIFFETrustDomain(pl.TrustDomain); err != nil {
		return err
	}
	if pl.Spec.TTLSeconds <= 0 || pl.CeremonyID == "" || pl.ExpiresAt.IsZero() {
		return errors.New("an upstream standing approval needs a positive maximum lifetime, its ceremony and an expiry")
	}
	return nil
}

func (p *Projector) applyCAUpstreamStandingApprovalTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventCAUpstreamStandingApprovalGranted:
		var pl CAUpstreamStandingApprovalGranted
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if err := ValidateCAUpstreamStandingApprovalGranted(pl); err != nil {
			return true, fmt.Errorf("projections: %s: %w", e.Type, err)
		}
		if !pl.ExpiresAt.After(e.Time) {
			return true, fmt.Errorf("projections: %s: the approval expires before it was granted", e.Type)
		}
		spec, err := json.Marshal(pl.Spec)
		if err != nil {
			return true, err
		}
		grantedBy := ""
		if e.Actor != nil {
			grantedBy = e.Actor.Subject
		}
		return true, p.store.ApplyCAUpstreamStandingApprovalGrantedTx(ctx, tx, store.CAUpstreamStandingApproval{
			TenantID: e.TenantID, ID: pl.ApprovalID, CAID: pl.CAID, Principal: pl.Principal, TrustDomain: pl.TrustDomain,
			Spec: spec, MaxTTLSeconds: pl.Spec.TTLSeconds, CeremonyID: pl.CeremonyID, GrantedBy: grantedBy,
			GrantedAt: e.Time, ExpiresAt: pl.ExpiresAt, EventSequence: e.Sequence,
		})
	case EventCAUpstreamStandingApprovalRevoked:
		var pl CAUpstreamStandingApprovalRevoked
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if _, err := uuid.Parse(pl.ApprovalID); err != nil {
			return true, fmt.Errorf("projections: %s: approval_id is not a UUID", e.Type)
		}
		revokedBy := ""
		if e.Actor != nil {
			revokedBy = e.Actor.Subject
		}
		return true, p.store.ApplyCAUpstreamStandingApprovalRevokedTx(ctx, tx, e.TenantID, pl.ApprovalID, revokedBy, pl.Reason, e.Time, e.Sequence)
	case EventCAUpstreamStandingApprovalSigned:
		var pl CAUpstreamStandingApprovalSigned
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if _, err := uuid.Parse(pl.ApprovalID); err != nil {
			return true, fmt.Errorf("projections: %s: approval_id is not a UUID", e.Type)
		}
		return true, p.store.ApplyCAUpstreamStandingApprovalSignedTx(ctx, tx, e.TenantID, pl.ApprovalID, e.Time, e.Sequence)
	default:
		return false, nil
	}
}
