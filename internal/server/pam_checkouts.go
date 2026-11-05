// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A261 part 2: check-outs of vaulted accounts. A check-out of a vaulted
// target's account is requested for independent review through the
// operation approval engine — reviewers see the target, its account secret,
// the reason and how long the credential lives. Its requester reveals the
// account's current credential once, with the approval's exact ID and intent
// digest: the reveal's event consumes the approval in the same transaction
// and records the secret version shown, never the credential. Checking it in,
// or its deadline passing, queues the static rotation (A240's engine) that
// retires the revealed credential, and ends the check-out with that command.

const (
	pamCheckoutMinTTL      = time.Minute
	pamCheckoutReasonMax   = 512
	pamCheckoutExpiryBatch = 100
	pamCheckoutExpiryActor = "pam-checkout-expiry"
)

// pamAccountRotation reaches the static rotation engine that retires a
// check-out's revealed credential.
type pamAccountRotation struct {
	// check says whether a rotation could retire the account's credential now.
	check func(ctx context.Context, tenantID, providerID, key, currentAccount string) error
	// queue queues the check-out's one rotation and returns its command ID.
	queue func(ctx context.Context, tenantID, providerID, key, currentAccount, requestID string) (string, error)
}

func pamCheckoutRevealedEventID(tenantID, requestID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl-pam-checkout-revealed\x00"+tenantID+"\x00"+requestID)).String()
}

func pamCheckoutEndedEventID(tenantID, requestID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl-pam-checkout-ended\x00"+tenantID+"\x00"+requestID)).String()
}

// pamCheckoutDigest binds a check-out's review: its request, target, account,
// reason, lifetime and requester.
func pamCheckoutDigest(requestID, targetType, targetID, providerID, accountSecret, reason, requester string, ttlSeconds int) (string, error) {
	raw, err := json.Marshal(struct {
		Domain        string `json:"domain"`
		RequestID     string `json:"request_id"`
		TargetType    string `json:"target_type"`
		TargetID      string `json:"target_id"`
		ProviderID    string `json:"provider_id"`
		AccountSecret string `json:"account_secret"`
		Reason        string `json:"reason"`
		Requester     string `json:"requester"`
		TTLSeconds    int    `json:"ttl_seconds"`
	}{"trstctl.pam.checkout.v1", requestID, targetType, targetID, providerID, accountSecret, reason, requester, ttlSeconds})
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(raw), nil
}

// pamCheckoutEvidence reads the target and lifetime a check-out's review
// recorded.
func pamCheckoutEvidence(refs []string) (targetType, targetID string, ttlSeconds int, ok bool) {
	for _, ref := range refs {
		if v, found := strings.CutPrefix(ref, "pam-checkout-target:"); found {
			targetType, targetID, _ = strings.Cut(v, "/")
		} else if v, found := strings.CutPrefix(ref, "pam-checkout-ttl:"); found {
			ttlSeconds, _ = strconv.Atoi(v)
		}
	}
	return targetType, targetID, ttlSeconds, targetType != "" && targetID != "" && ttlSeconds > 0
}

// checkoutTarget is the vaulted database target a check-out names.
func (s *pamService) checkoutTarget(ctx context.Context, tenantID, targetType, targetID string) (*pamDatabaseTarget, error) {
	if !isPAMDatabaseType(targetType) || targetID == "" {
		return nil, fmt.Errorf("%w: a check-out names a vaulted postgres or mysql target", api.ErrPAMInvalid)
	}
	target, err := s.databaseTarget(ctx, tenantID, targetType, targetID)
	if err != nil {
		return nil, err
	}
	if target.cfg.AccountSecret == "" {
		return nil, fmt.Errorf("%w: %s target %q is not vaulted; only a vaulted account can be checked out", api.ErrPAMInvalid, targetType, targetID)
	}
	if s.secretReader == nil || s.rotation.check == nil || s.rotation.queue == nil {
		return nil, fmt.Errorf("%w: check-outs need the secrets API", api.ErrPAMInvalid)
	}
	return target, nil
}

// vaultedAccount reads a vaulted account's current credential, its version
// and the account it signs in as. The caller wipes value.
func (s *pamService) vaultedAccount(ctx context.Context, tenantID, targetType, accountSecret string) (value []byte, version int, account string, err error) {
	value, version, err = s.secretReader(ctx, tenantID, accountSecret)
	if err != nil {
		return nil, 0, "", fmt.Errorf("%w: account secret %q is not readable", api.ErrPAMRejected, accountSecret)
	}
	account, ok := dynsecret.CredentialAccount(pamDatabaseProviderTypes[targetType], value)
	if !ok {
		secret.Wipe(value)
		return nil, 0, "", fmt.Errorf("%w: account secret %q does not hold a %s connection string", api.ErrPAMRejected, accountSecret,
			pamDatabaseKinds[targetType])
	}
	return value, version, account, nil
}

func (s *pamService) RequestPAMCheckout(ctx context.Context, tenantID, requester string, req api.PAMCheckoutRequest) (api.PAMCheckoutReview, error) {
	originalReason := strings.TrimSpace(req.Reason)
	template, policyRefs, _, err := s.pamRequestTemplate(ctx, tenantID, req.TargetType, req.TargetID, req.TemplateID)
	if err != nil {
		return api.PAMCheckoutReview{}, err
	}
	requiredApprovals := s.requiredApprovals
	reason := strings.TrimSpace(req.Reason)
	if template != nil {
		if accessrules.ForTarget(template.ID, template.Revision, template.CommandRules, req.TargetType) != nil {
			return api.PAMCheckoutReview{}, fmt.Errorf("%w: this template requires command rules; a revealed credential bypasses the gateway", api.ErrPAMInvalid)
		}
		if template.RequireRecording {
			return api.PAMCheckoutReview{}, fmt.Errorf("%w: this template requires recording; a check-out cannot be recorded", api.ErrPAMInvalid)
		}
		if reason != "" {
			reason = template.Reason + ": " + reason
		} else {
			reason = template.Reason
		}
		requiredApprovals = max(requiredApprovals, template.RequiredApprovals)
		if req.TTLSeconds > template.MaxTTLSeconds {
			req.TTLSeconds = template.MaxTTLSeconds
		}
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	switch {
	case requester == "":
		return api.PAMCheckoutReview{}, fmt.Errorf("%w: an authenticated requester is required", api.ErrPAMInvalid)
	case !validUUID(req.RequestID):
		return api.PAMCheckoutReview{}, fmt.Errorf("%w: request_id must be a UUID", api.ErrPAMInvalid)
	case reason == "" || utf8.RuneCountInString(reason) > pamCheckoutReasonMax || strings.ContainsAny(reason, "\r\n"):
		return api.PAMCheckoutReview{}, fmt.Errorf("%w: reason must be one line of 1-%d characters", api.ErrPAMInvalid, pamCheckoutReasonMax)
	case ttl < pamCheckoutMinTTL || ttl > s.maxTTL:
		return api.PAMCheckoutReview{}, fmt.Errorf("%w: ttl_seconds must be %d-%d", api.ErrPAMInvalid, int(pamCheckoutMinTTL.Seconds()), int(s.maxTTL.Seconds()))
	}
	target, err := s.checkoutTarget(ctx, tenantID, req.TargetType, req.TargetID)
	if err != nil {
		return api.PAMCheckoutReview{}, err
	}
	// Nobody reviews a check-out that a rotation could not retire.
	value, _, account, err := s.vaultedAccount(ctx, tenantID, req.TargetType, target.cfg.AccountSecret)
	if err != nil {
		return api.PAMCheckoutReview{}, err
	}
	secret.Wipe(value)
	if err := s.rotation.check(ctx, tenantID, target.cfg.ProviderID, target.cfg.AccountSecret, account); err != nil {
		return api.PAMCheckoutReview{}, err
	}
	digest, err := pamCheckoutDigest(req.RequestID, req.TargetType, req.TargetID, target.cfg.ProviderID, target.cfg.AccountSecret, reason,
		requester, req.TTLSeconds)
	if err != nil {
		return api.PAMCheckoutReview{}, err
	}
	approval, err := s.pamEnsureReviewedRequest(ctx, tenantID, orchestrator.OperationApprovalIntent{
		ResourceKind: "pam_checkout", ResourceID: "pam-checkout:" + req.RequestID, ResourceName: req.TargetType + "/" + req.TargetID,
		Action: "reveal", Requester: requester, FromState: "vaulted", ToState: "revealed", Reason: reason,
		EvidenceRefs: []string{"pam-checkout-sha256:" + digest, "pam-checkout-target:" + req.TargetType + "/" + req.TargetID,
			"pam-checkout-account:" + target.cfg.AccountSecret, "pam-checkout-ttl:" + strconv.Itoa(req.TTLSeconds), "pam-checkout-template:" + req.TemplateID, pamCheckoutPolicyRef(policyRefs)},
		RequiredApprovals: requiredApprovals, TTL: s.approvalTTL,
	}, pamAutoApprovalRequest{Kind: "checkout", TargetType: req.TargetType, TargetID: req.TargetID, Reason: originalReason, TTLSeconds: req.TTLSeconds}, req.RequestID)
	if err != nil {
		return api.PAMCheckoutReview{}, err
	}
	return api.PAMCheckoutReview{RequestID: req.RequestID, ApprovalRequestID: approval.ID, IntentDigest: approval.IntentDigest,
		Status: approval.Status, ApprovalCount: approval.ApprovalCount, RequiredApprovals: approval.RequiredApprovals,
		ExpiresAt: approval.ExpiresAt}, nil
}

func (s *pamService) RevealPAMCheckout(ctx context.Context, tenantID, requester, requestID string, req api.PAMCheckoutRevealRequest) (*api.PAMCheckoutReveal, error) {
	if requester == "" || !validUUID(requestID) || !validUUID(req.ApprovalRequestID) || req.IntentDigest == "" {
		return nil, fmt.Errorf("%w: the check-out's request_id and the approval's exact approval_request_id and intent_digest are required", api.ErrPAMInvalid)
	}
	eventID := pamCheckoutRevealedEventID(tenantID, requestID)
	canonical, found, err := s.log.EventByID(ctx, eventID)
	if err != nil {
		return nil, err
	}
	if found {
		// Revealed already: its record is finished, the credential is not
		// shown again.
		if canonical.Type != projections.EventPAMCheckoutRevealed || canonical.TenantID != tenantID {
			return nil, fmt.Errorf("%w: the check-out's request_id belongs to another record", orchestrator.ErrIdempotencyConflict)
		}
		if err := s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error { return s.projector.ApplyTx(ctx, tx, canonical) }); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: this check-out's credential was already revealed; it is shown once", api.ErrPAMTargetConflict)
	}
	approval, err := s.store.GetOperationApproval(ctx, tenantID, req.ApprovalRequestID)
	if err != nil {
		return nil, err
	}
	if approval.ResourceKind != "pam_checkout" || approval.ResourceID != "pam-checkout:"+requestID || approval.Action != "reveal" ||
		approval.Requester != requester || approval.IntentDigest != req.IntentDigest {
		return nil, fmt.Errorf("%w: the approval does not belong to this requester and check-out", api.ErrPAMRejected)
	}
	targetType, targetID, ttlSeconds, ok := pamCheckoutEvidence(approval.EvidenceRefs)
	if !ok {
		return nil, fmt.Errorf("%w: the approval is not a check-out's review", api.ErrPAMRejected)
	}
	target, err := s.checkoutTarget(ctx, tenantID, targetType, targetID)
	if err != nil {
		return nil, err
	}
	// Re-read the folder and template before revealing: a policy changed
	// after review requires a fresh review, and recording can never be bypassed.
	requestedTemplate := ""
	for _, ref := range approval.EvidenceRefs {
		if v, ok := strings.CutPrefix(ref, "pam-checkout-template:"); ok {
			requestedTemplate = v
		}
	}
	template, policyRefs, _, err := s.pamRequestTemplate(ctx, tenantID, targetType, targetID, requestedTemplate)
	if err != nil {
		return nil, err
	}
	if template != nil && accessrules.ForTarget(template.ID, template.Revision, template.CommandRules, targetType) != nil {
		return nil, fmt.Errorf("%w: command rules cannot be enforced after credential reveal", api.ErrPAMInvalid)
	}
	if template != nil && template.RequireRecording {
		return nil, fmt.Errorf("%w: this template requires recording; a check-out cannot be recorded", api.ErrPAMInvalid)
	}
	matchedPolicy := containsExactString(approval.EvidenceRefs, pamCheckoutPolicyRef(policyRefs))
	legacyPolicy := true
	for _, ref := range approval.EvidenceRefs {
		if strings.HasPrefix(ref, "pam-checkout-policy:") {
			legacyPolicy = false
		}
	}
	if !matchedPolicy && (!legacyPolicy || len(policyRefs) != 0) {
		return nil, fmt.Errorf("%w: the folder or template changed since review; request a new review", api.ErrPAMRejected)
	}
	digest, err := pamCheckoutDigest(requestID, targetType, targetID, target.cfg.ProviderID, target.cfg.AccountSecret, approval.Reason,
		requester, ttlSeconds)
	if err != nil {
		return nil, err
	}
	if !containsExactString(approval.EvidenceRefs, "pam-checkout-sha256:"+digest) {
		return nil, fmt.Errorf("%w: the target's vaulted account changed since its review; request a new review", api.ErrPAMRejected)
	}
	use, err := store.OperationApprovalUseFromRequest(approval)
	if err != nil {
		return nil, err
	}
	value, version, _, err := s.vaultedAccount(ctx, tenantID, targetType, target.cfg.AccountSecret)
	if err != nil {
		return nil, err
	}
	now := s.clock().UTC()
	payload := projections.PAMCheckoutRevealed{RequestID: requestID, TargetType: targetType, TargetID: targetID,
		ProviderID: target.cfg.ProviderID, AccountSecret: target.cfg.AccountSecret, SecretVersion: version, Reason: approval.Reason,
		ExpiresAt: now.Add(time.Duration(ttlSeconds) * time.Second), Approval: use, Actor: requester, At: now}
	data, err := json.Marshal(payload)
	if err != nil {
		secret.Wipe(value)
		return nil, err
	}
	err = s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := s.store.ValidateOperationApprovalUseTx(ctx, tx, tenantID, use, now); err != nil {
			return err
		}
		candidate := events.Event{ID: eventID, Type: projections.EventPAMCheckoutRevealed, TenantID: tenantID,
			Time: now.Truncate(time.Microsecond), Data: data}
		if actor, ok := events.ActorFromContext(ctx); ok {
			candidate.Actor = &actor
		}
		canonical, err := s.log.Append(ctx, candidate)
		if err != nil {
			return err
		}
		if canonical.Type != candidate.Type || canonical.TenantID != tenantID || !bytes.Equal(canonical.Data, data) {
			// Another reveal of this check-out landed first.
			return fmt.Errorf("%w: this check-out's credential was already revealed; it is shown once", api.ErrPAMTargetConflict)
		}
		return s.projector.ApplyTx(ctx, tx, canonical)
	})
	if err != nil {
		secret.Wipe(value)
		return nil, err
	}
	checkout, err := s.store.GetPAMCheckout(ctx, tenantID, requestID)
	if err != nil {
		secret.Wipe(value)
		return nil, err
	}
	return &api.PAMCheckoutReveal{Checkout: pamCheckoutView(checkout), Credential: value}, nil
}

func (s *pamService) CheckInPAMCheckout(ctx context.Context, tenantID, actor, requestID string) (api.PAMCheckout, error) {
	if actor == "" {
		return api.PAMCheckout{}, fmt.Errorf("%w: an authenticated principal is required", api.ErrPAMInvalid)
	}
	if !validUUID(requestID) {
		return api.PAMCheckout{}, store.ErrPAMCheckoutNotFound
	}
	c, err := s.store.GetPAMCheckout(ctx, tenantID, requestID)
	if err != nil {
		return api.PAMCheckout{}, err
	}
	if c.Status == "revealed" {
		if err := s.endCheckout(ctx, c, "checked_in", actor); err != nil {
			return api.PAMCheckout{}, err
		}
		if c, err = s.store.GetPAMCheckout(ctx, tenantID, requestID); err != nil {
			return api.PAMCheckout{}, err
		}
	}
	// An ended check-out answers a repeated check-in with how it ended.
	return pamCheckoutView(c), nil
}

// endCheckout queues the rotation that retires a check-out's revealed
// credential and records the check-out ended with that command. A check-in
// racing the deadline lands on one rotation and one ended event.
func (s *pamService) endCheckout(ctx context.Context, c store.PAMCheckout, status, actor string) error {
	if s.secretReader == nil || s.rotation.queue == nil {
		return fmt.Errorf("%w: check-outs need the secrets API", api.ErrPAMInvalid)
	}
	value, _, account, err := s.vaultedAccount(ctx, c.TenantID, c.TargetType, c.AccountSecret)
	if err != nil {
		return err
	}
	secret.Wipe(value)
	commandID, err := s.rotation.queue(ctx, c.TenantID, c.ProviderID, c.AccountSecret, account, c.RequestID)
	if err != nil {
		return err
	}
	data, err := json.Marshal(projections.PAMCheckoutEnded{RequestID: c.RequestID, Status: status, RotationCommandID: commandID,
		Actor: actor, At: s.clock().UTC()})
	if err != nil {
		return err
	}
	candidate := events.Event{ID: pamCheckoutEndedEventID(c.TenantID, c.RequestID), Type: projections.EventPAMCheckoutEnded,
		TenantID: c.TenantID, Time: s.clock().UTC().Truncate(time.Microsecond), Data: data}
	if eventActor, ok := events.ActorFromContext(ctx); ok {
		candidate.Actor = &eventActor
	}
	canonical, err := s.log.Append(ctx, candidate)
	if err != nil {
		return err
	}
	if canonical.Type != candidate.Type || canonical.TenantID != c.TenantID {
		return fmt.Errorf("%w: the check-out's ended record belongs to another record", orchestrator.ErrIdempotencyConflict)
	}
	return s.store.WithTenant(ctx, c.TenantID, func(tx pgx.Tx) error { return s.projector.ApplyTx(ctx, tx, canonical) })
}

// expireCheckouts ends every check-out past its deadline at now, each with
// the rotation that retires its revealed credential. One that cannot be
// ended stays revealed, past its deadline, for the next tick.
func (s *pamService) expireCheckouts(ctx context.Context, now time.Time) {
	due, err := s.store.ListDuePAMCheckouts(ctx, now, pamCheckoutExpiryBatch)
	if err != nil {
		return
	}
	ctx = events.ContextWithActor(ctx, events.Actor{Subject: pamCheckoutExpiryActor, Roles: []string{"worker"}})
	for _, c := range due {
		_ = s.endCheckout(ctx, c, "expired", pamCheckoutExpiryActor)
	}
}

func (s *pamService) ListPAMCheckouts(ctx context.Context, tenantID string) ([]api.PAMCheckout, error) {
	items, err := s.store.ListPAMCheckouts(ctx, tenantID, 500)
	if err != nil {
		return nil, err
	}
	out := make([]api.PAMCheckout, 0, len(items))
	for _, c := range items {
		out = append(out, pamCheckoutView(c))
	}
	return out, nil
}

func (s *pamService) GetPAMCheckout(ctx context.Context, tenantID, requestID string) (api.PAMCheckout, error) {
	if !validUUID(requestID) {
		return api.PAMCheckout{}, store.ErrPAMCheckoutNotFound
	}
	c, err := s.store.GetPAMCheckout(ctx, tenantID, requestID)
	if err != nil {
		return api.PAMCheckout{}, err
	}
	return pamCheckoutView(c), nil
}

func pamCheckoutView(c store.PAMCheckout) api.PAMCheckout {
	return api.PAMCheckout{RequestID: c.RequestID, TargetType: c.TargetType, TargetID: c.TargetID, ProviderID: c.ProviderID,
		AccountSecret: c.AccountSecret, SecretVersion: c.SecretVersion, RequestedBy: c.RequestedBy, Reason: c.Reason,
		ApprovalRequestID: c.ApprovalRequestID, RevealedAt: c.RevealedAt, ExpiresAt: c.ExpiresAt, Status: c.Status, EndedAt: c.EndedAt,
		EndedBy: c.EndedBy, RotationCommandID: c.RotationCommandID}
}

func (s *Server) RequestPAMCheckout(ctx context.Context, tenantID, requester string, req api.PAMCheckoutRequest) (api.PAMCheckoutReview, error) {
	if s.pam == nil {
		return api.PAMCheckoutReview{}, api.ErrPAMUnavailable
	}
	return s.pam.RequestPAMCheckout(ctx, tenantID, requester, req)
}

func (s *Server) RevealPAMCheckout(ctx context.Context, tenantID, requester, requestID string, req api.PAMCheckoutRevealRequest) (*api.PAMCheckoutReveal, error) {
	if s.pam == nil {
		return nil, api.ErrPAMUnavailable
	}
	return s.pam.RevealPAMCheckout(ctx, tenantID, requester, requestID, req)
}

func (s *Server) CheckInPAMCheckout(ctx context.Context, tenantID, actor, requestID string) (api.PAMCheckout, error) {
	if s.pam == nil {
		return api.PAMCheckout{}, api.ErrPAMUnavailable
	}
	return s.pam.CheckInPAMCheckout(ctx, tenantID, actor, requestID)
}

func (s *Server) ListPAMCheckouts(ctx context.Context, tenantID string) ([]api.PAMCheckout, error) {
	if s.pam == nil {
		return nil, api.ErrPAMUnavailable
	}
	return s.pam.ListPAMCheckouts(ctx, tenantID)
}

func (s *Server) GetPAMCheckout(ctx context.Context, tenantID, requestID string) (api.PAMCheckout, error) {
	if s.pam == nil {
		return api.PAMCheckout{}, api.ErrPAMUnavailable
	}
	return s.pam.GetPAMCheckout(ctx, tenantID, requestID)
}

func pamCheckoutPolicyRef(refs []string) string {
	raw, _ := json.Marshal(refs)
	return "pam-checkout-policy:" + crypto.SHA256Hex(raw)
}
