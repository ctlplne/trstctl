// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/discovery"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

var rogueRevocationNamespace = uuid.MustParse("3f6a9c1e-7b24-4d58-a0e3-9c5b2d71f846")

// ErrRogueRevocationExists refuses a second revocation of a finding at an
// authority while one is queued or after the authority confirmed it.
var ErrRogueRevocationExists = errors.New("orchestrator: this finding's revocation at that authority is already queued or confirmed")

// ErrRogueFindingNotRevocable refuses a finding that names no certificate an
// issuer can revoke by serial.
var ErrRogueFindingNotRevocable = errors.New("orchestrator: only a Certificate Transparency finding with a certificate serial can be revoked at its issuer")

// RogueCertificateRevocationRequest revokes one CT finding's certificate at one
// external authority (A163). The caller has checked the authority is one the
// tenant may use and that it revokes by serial.
type RogueCertificateRevocationRequest struct {
	DiscoveryID    string
	AuthorityID    string
	Reason         string
	IdempotencyKey string
}

// RequestRogueCertificateRevocation appends the request and queues its
// revocation.publish delivery in one tenant transaction. A retry with the same
// key returns the same request.
func (o *Orchestrator) RequestRogueCertificateRevocation(ctx context.Context, tenantID string,
	in RogueCertificateRevocationRequest) (projections.RogueCertificateRevocationRequested, string, error) {
	var empty projections.RogueCertificateRevocationRequested
	if o == nil || o.log == nil || o.store == nil || o.outbox == nil {
		return empty, "", errors.New("orchestrator: rogue certificate revocation is not configured")
	}
	authorityID := strings.TrimSpace(in.AuthorityID)
	reason := strings.TrimSpace(in.Reason)
	if authorityID == "" {
		return empty, "", errors.New("orchestrator: a rogue certificate revocation needs the authority that issued it")
	}
	if !crypto.IsValidRevocationReason(reason) || reason == "removeFromCRL" {
		return empty, "", fmt.Errorf("orchestrator: %q is not a revocation reason", reason)
	}
	finding, err := o.store.GetDiscoveryFinding(ctx, tenantID, strings.TrimSpace(in.DiscoveryID))
	if err != nil {
		return empty, "", err
	}
	var meta struct {
		Serial string `json:"serial"`
	}
	_ = json.Unmarshal(finding.Metadata, &meta)
	serial := strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(meta.Serial)))
	if finding.Kind != "ct_unexpected_issuance" || serial == "" || len(serial) > 64 || strings.Trim(serial, "0123456789abcdef") != "" {
		return empty, "", ErrRogueFindingNotRevocable
	}
	requested := projections.RogueCertificateRevocationRequested{
		DiscoveryID: finding.ID, AuthorityID: authorityID, Serial: serial, Reason: reason,
		ReasonCode: crypto.CRLReasonCode(crypto.RevocationReason(reason)), Fingerprint: finding.Fingerprint,
	}
	raw, err := json.Marshal(requested)
	if err != nil {
		return empty, "", err
	}
	eventID := uuid.NewSHA1(rogueRevocationNamespace, []byte(tenantID+"\x00"+finding.ID+"\x00"+authorityID+"\x00"+reason+"\x00"+
		strings.TrimSpace(in.IdempotencyKey))).String()
	command, err := json.Marshal(store.RogueCertificateRevocationCommand{
		RogueEventID: eventID, DiscoveryID: finding.ID, AuthorityID: authorityID, Serial: serial, Reason: reason,
	})
	if err != nil {
		return empty, "", err
	}
	err = o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		retained, found, err := o.log.EventByID(ctx, eventID)
		if err != nil {
			return err
		}
		if found {
			if retained.TenantID != tenantID || retained.Type != projections.EventRogueCertificateRevocationRequested || !bytes.Equal(retained.Data, raw) {
				return fmt.Errorf("%w: rogue certificate revocation differs from the retained one", store.ErrIdempotencyConflict)
			}
			return nil
		}
		existing, ok, err := o.store.GetRogueCertificateRevocationTx(ctx, tx, tenantID, finding.ID, authorityID)
		if err != nil {
			return err
		}
		if ok && existing.State != "failed" {
			return ErrRogueRevocationExists
		}
		event, err := o.log.Append(ctx, events.Event{
			ID: eventID, Type: projections.EventRogueCertificateRevocationRequested, TenantID: tenantID, Data: raw,
		})
		if err != nil {
			return err
		}
		if event.ID != eventID || event.Type != projections.EventRogueCertificateRevocationRequested ||
			event.TenantID != tenantID || !bytes.Equal(event.Data, raw) {
			return fmt.Errorf("%w: rogue certificate revocation differs from the retained one", store.ErrIdempotencyConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, event); err != nil {
			return err
		}
		_, err = o.outbox.EnqueueIfAbsent(ctx, tx, Entry{
			TenantID: tenantID, Destination: store.RogueRevocationDestination,
			IdempotencyKey: store.RogueRevocationKey(eventID), Payload: command,
			EffectLane: store.RogueRevocationDestination + ":authority:" + authorityID,
		})
		return err
	})
	if err != nil {
		if errors.Is(err, ErrRogueRevocationExists) {
			return empty, "", err
		}
		return empty, "", fmt.Errorf("orchestrator: queue rogue certificate revocation: %w", err)
	}
	return requested, eventID, nil
}

// RecordRogueCertificateRevokedAtIssuer records the authority's confirmation
// under an event id derived from the request, so a retried delivery records
// once.
func (o *Orchestrator) RecordRogueCertificateRevokedAtIssuer(ctx context.Context, tenantID, eventID string,
	in projections.RogueCertificateRevokedAtIssuer) error {
	if o == nil || o.log == nil || strings.TrimSpace(eventID) == "" || in.RequestEventID == "" {
		return errors.New("orchestrator: a rogue certificate revocation result needs its event id and request")
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		event, err := o.log.Append(ctx, events.Event{ID: eventID, Type: projections.EventRogueCertificateRevokedAtIssuer, TenantID: tenantID, Data: raw})
		if err != nil {
			return err
		}
		if event.ID != eventID || event.Type != projections.EventRogueCertificateRevokedAtIssuer || event.TenantID != tenantID || !bytes.Equal(event.Data, raw) {
			return fmt.Errorf("%w: rogue certificate revocation result differs from the retained one", store.ErrIdempotencyConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, event); err != nil {
			return err
		}
		return o.remediateRogueFindingTx(ctx, tx, tenantID, eventID, in)
	})
}

// remediateRogueFindingTx resolves the CT finding an issuer's confirmed
// revocation was requested for (A163-L2): its triage moves to remediated with
// the confirmation's result event as the evidence of the fix, so nobody has to
// resolve it by hand. The change has an identity of its own derived from the
// result, so a redelivery appends nothing more. A finding whose triage cannot
// move to remediated (an operator claimed it as managed or dismissed it) keeps
// the operator's decision, and one already remediated is left as it is.
func (o *Orchestrator) remediateRogueFindingTx(ctx context.Context, tx pgx.Tx, tenantID, resultEventID string, in projections.RogueCertificateRevokedAtIssuer) error {
	finding, err := o.store.GetDiscoveryFinding(ctx, tenantID, in.DiscoveryID)
	if err != nil {
		return err
	}
	current := discovery.TriageStatus(finding.TriageStatus)
	if current == discovery.TriageRemediated || discovery.ValidateTriageTransition(current, discovery.TriageRemediated) != nil {
		return nil
	}
	raw, err := json.Marshal(projections.DiscoveryFindingTriageChanged{
		ID: finding.ID, Status: string(discovery.TriageRemediated), Actor: "trstctl",
		Reason:      "revoked at its issuer " + in.AuthorityID + ", which confirmed the revocation of serial " + in.Serial,
		EvidenceRef: resultEventID,
	})
	if err != nil {
		return err
	}
	eventID := "discovery.finding.remediated:" + crypto.SHA256Hex([]byte(tenantID+"\x00"+resultEventID))
	event, err := o.log.Append(ctx, events.Event{ID: eventID, Type: projections.EventDiscoveryFindingTriageChanged, TenantID: tenantID, Data: raw})
	if err != nil {
		return err
	}
	if event.ID != eventID || event.Type != projections.EventDiscoveryFindingTriageChanged || event.TenantID != tenantID || !bytes.Equal(event.Data, raw) {
		return fmt.Errorf("%w: the rogue finding's remediation differs from the retained one", store.ErrIdempotencyConflict)
	}
	return o.proj.ApplyTx(ctx, tx, event)
}
