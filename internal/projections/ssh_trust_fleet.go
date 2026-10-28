// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/base64"
	"errors"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/sshtrustrollout"
	"trstctl.com/trstctl/internal/store"
)

const EventSSHTrustFleetStarted = "ssh.trust_fleet.started"
const EventSSHTrustFleetObserved = "ssh.trust_fleet.observed"

type SSHTrustFleetStarted struct {
	ID         string                     `json:"id"`
	Plan       sshtrustrollout.Plan       `json:"plan"`
	PlanDigest string                     `json:"plan_digest"`
	Approval   store.OperationApprovalUse `json:"approval"`
}

type SSHTrustFleetObserved struct {
	JobID             int64                  `json:"job_id"`
	Attempt           int                    `json:"attempt"`
	Report            sshtrustrollout.Report `json:"report"`
	EvidenceDigest    string                 `json:"evidence_digest"`
	ReceiptStatement  string                 `json:"receipt_statement"`
	ReceiptSignature  string                 `json:"receipt_signature_base64"`
	SignerFingerprint string                 `json:"signer_fingerprint"`
}

func ValidateSSHTrustFleetStarted(p SSHTrustFleetStarted) error {
	if !canonicalUUID(p.ID) {
		return errors.New("SSH trust rollout needs a canonical ID")
	}
	digest, err := p.Plan.Digest()
	if err != nil {
		return err
	}
	if digest != p.PlanDigest {
		return errors.New("SSH trust reviewed effect digest differs")
	}
	a := p.Approval
	if a.ResourceKind != "ssh_trust_rollout" || a.ResourceID != sshtrustrollout.ResourceID(digest) || a.Action != "apply" || a.FromState != "planned" || a.ToState != "queued" || a.TargetVersion != 1 || a.RequiredApprovals < 1 || !canonicalUUID(a.RequestID) || a.Requester == "" {
		return errors.New("SSH trust rollout needs an exact single-use approval")
	}
	found := false
	ready := false
	for _, ref := range a.EvidenceRefs {
		if ref == digest {
			found = true
		}
	}
	for _, host := range p.Plan.Hosts {
		if host.State == "ready" {
			ready = true
		}
	}
	if !found || !ready {
		return errors.New("SSH trust approval must bind a ready effect and its exact plan digest")
	}
	return nil
}

func ValidateSSHTrustFleetObserved(p SSHTrustFleetObserved) error {
	if p.JobID <= 0 || p.Attempt <= 0 || !canonicalUUID(p.Report.RolloutID) || !canonicalUUID(p.Report.AgentID) || p.ReceiptStatement == "" || len(p.ReceiptStatement) > 32<<10 || !optionalSHA256Hex(p.SignerFingerprint) || p.SignerFingerprint == "" {
		return errors.New("SSH trust observation needs its signed job and peer evidence")
	}
	signature, err := base64.StdEncoding.DecodeString(p.ReceiptSignature)
	if err != nil || len(signature) == 0 || len(signature) > 16<<10 {
		return errors.New("SSH trust observation has no bounded receipt signature")
	}
	return nil
}

func (p *Projector) applySSHTrustFleetTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventSSHTrustFleetStarted:
		var started SSHTrustFleetStarted
		if err := decode(e, &started); err != nil {
			return true, err
		}
		if err := ValidateSSHTrustFleetStarted(started); err != nil {
			return true, err
		}
		if e.ID != started.ID {
			return true, errors.New("SSH trust rollout source ID differs")
		}
		if err := validateApprovalActor(e, started.Approval.Requester); err != nil {
			return true, err
		}
		if err := p.store.ConsumeOperationApprovalTx(ctx, tx, e.TenantID, started.Approval, e.ID, e.Time); err != nil {
			return true, err
		}
		return true, p.store.ApplySSHTrustFleetStartedTx(ctx, tx, store.SSHTrustFleetRollout{TenantID: e.TenantID, ID: started.ID, Plan: started.Plan, PlanDigest: started.PlanDigest, ApprovalRequestID: started.Approval.RequestID, Requester: started.Approval.Requester}, e.Time, e.Sequence)
	case EventSSHTrustFleetObserved:
		var observed SSHTrustFleetObserved
		if err := decode(e, &observed); err != nil {
			return true, err
		}
		if err := ValidateSSHTrustFleetObserved(observed); err != nil {
			return true, err
		}
		// The receiver verified this signature against the exact mTLS peer before
		// append. Retain the canonical statement and fingerprint for audit/rebuild.
		return true, p.store.ApplySSHTrustFleetObservedTx(ctx, tx, e.TenantID, e.ID, observed.JobID, observed.Attempt, observed.Report, observed.EvidenceDigest, e.Time, e.Sequence)
	default:
		return false, nil
	}
}
