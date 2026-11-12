// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// A standing approval for an access bundle's delegated account (OD-9).
const (
	// EventAccessBundleStandingApprovalGranted records an approval an
	// administrator granted for one bundle, account and role.
	EventAccessBundleStandingApprovalGranted = "access.bundle_standing_approval.granted"
	// EventAccessBundleStandingApprovalRevoked records its revocation.
	EventAccessBundleStandingApprovalRevoked = "access.bundle_standing_approval.revoked"
	// EventAccessBundleStandingApprovalUsed records one session request it
	// approved, beside the request's own approval decision.
	EventAccessBundleStandingApprovalUsed = "access.bundle_standing_approval.used"
)

// MaxAccessBundleStandingApprovalValidity is the longest a standing approval
// may last from its grant.
const MaxAccessBundleStandingApprovalValidity = 90 * 24 * time.Hour

// AccessBundleStandingApprovalGranted is the payload of
// access.bundle_standing_approval.granted.
type AccessBundleStandingApprovalGranted struct {
	ID         string    `json:"id"`
	BundleID   string    `json:"bundle_id"`
	TargetType string    `json:"target_type"`
	TargetID   string    `json:"target_id"`
	Role       string    `json:"role"`
	Reason     string    `json:"reason"`
	ExpiresAt  time.Time `json:"expires_at"`
	GrantedBy  string    `json:"granted_by"`
}

// AccessBundleStandingApprovalRevoked is the payload of
// access.bundle_standing_approval.revoked.
type AccessBundleStandingApprovalRevoked struct {
	ID        string `json:"id"`
	BundleID  string `json:"bundle_id"`
	RevokedBy string `json:"revoked_by"`
	Reason    string `json:"reason"`
}

// AccessBundleStandingApprovalUsed is the payload of
// access.bundle_standing_approval.used: the run whose session request the
// approval approved, and that request's approval. The approval's synthetic
// approver (standing-approval:<id>) is the event's actor.
type AccessBundleStandingApprovalUsed struct {
	ID                string `json:"id"`
	BundleID          string `json:"bundle_id"`
	RunID             string `json:"run_id"`
	Principal         string `json:"principal"`
	RequestID         string `json:"request_id"`
	ApprovalRequestID string `json:"approval_request_id"`
}

// ValidateAccessBundleStandingApprovalGranted checks a grant made at.
func ValidateAccessBundleStandingApprovalGranted(pl AccessBundleStandingApprovalGranted, at time.Time) error {
	if _, err := uuid.Parse(pl.ID); err != nil {
		return errors.New("a standing approval needs a UUID id")
	}
	if _, err := uuid.Parse(pl.BundleID); err != nil {
		return errors.New("a standing approval needs a UUID bundle_id")
	}
	if pl.TargetType == "" || len(pl.TargetType) > 64 || pl.TargetID == "" || len(pl.TargetID) > 200 || pl.Role == "" || len(pl.Role) > 128 {
		return errors.New("a standing approval names one account (target type, target and role)")
	}
	if reason := strings.TrimSpace(pl.Reason); reason == "" || len(pl.Reason) > 500 {
		return errors.New("a standing approval needs a reason (at most 500 characters)")
	}
	if !pl.ExpiresAt.After(at) {
		return errors.New("a standing approval expires after it is granted")
	}
	return nil
}

func (p *Projector) applyAccessBundleStandingApprovalTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventAccessBundleStandingApprovalGranted:
		var d AccessBundleStandingApprovalGranted
		if err := decodeAccessBundle(e, &d); err != nil {
			return true, err
		}
		if err := ValidateAccessBundleStandingApprovalGranted(d, e.Time); err != nil {
			return true, fmt.Errorf("projections: %s: %w", e.Type, err)
		}
		return true, p.store.ApplyAccessBundleStandingApprovalGrantedTx(ctx, tx, store.AccessBundleStandingApproval{
			TenantID: e.TenantID, ID: d.ID, BundleID: d.BundleID, TargetType: d.TargetType, TargetID: d.TargetID, Role: d.Role,
			Reason: d.Reason, GrantedBy: d.GrantedBy, GrantedAt: e.Time, ExpiresAt: d.ExpiresAt,
		}, e.ID, e.Sequence)
	case EventAccessBundleStandingApprovalRevoked:
		var d AccessBundleStandingApprovalRevoked
		if err := decodeAccessBundle(e, &d); err != nil {
			return true, err
		}
		if _, err := uuid.Parse(d.ID); err != nil {
			return true, fmt.Errorf("projections: %s: id is not a UUID", e.Type)
		}
		return true, p.store.ApplyAccessBundleStandingApprovalRevokedTx(ctx, tx, e.TenantID, d.ID, d.RevokedBy, d.Reason, e.Time, e.ID, e.Sequence)
	case EventAccessBundleStandingApprovalUsed:
		var d AccessBundleStandingApprovalUsed
		if err := decodeAccessBundle(e, &d); err != nil {
			return true, err
		}
		if _, err := uuid.Parse(d.ID); err != nil {
			return true, fmt.Errorf("projections: %s: id is not a UUID", e.Type)
		}
		actor := ""
		if e.Actor != nil {
			actor = e.Actor.Subject
		}
		return true, p.store.ApplyAccessBundleStandingApprovalUsedTx(ctx, tx, e.TenantID, d.ID, d.RunID, d.Principal, actor, e.Time, e.ID, e.Sequence)
	}
	return false, nil
}
