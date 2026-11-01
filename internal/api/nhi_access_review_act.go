// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/store"
)

// Access reviews that act (Q1). A revoke decision revokes the reviewed
// credential through that credential's own revoke path, once: every attempt
// uses the item's idempotency key, so a retried request or the leader's
// reconcile cannot revoke twice. The item records what trstctl did and closes
// only when the credential reads revoked, never on the request alone. A keep
// decision renews the owner's attestation when the item names an owner; it
// changes no right upstream.

// nhiReviewActGrace keeps the reconcile from acting on a decision whose own
// request may still be acting on it.
const nhiReviewActGrace = 2 * time.Minute

// nhiReviewTarget states read from the reviewed credential.
const (
	nhiReviewTargetRevoked = "revoked"
	nhiReviewTargetFailed  = "failed"
)

// NHIReviewIdempotencyKey is the one key every attempt to act on a review item
// uses.
func NHIReviewIdempotencyKey(campaignID, itemID string) string {
	return "nhi-review:" + campaignID + ":" + itemID
}

// nhiReviewRevokeReason is what the credential's own revoke path records: the
// campaign and the reviewer's reason.
func nhiReviewRevokeReason(campaignID string, item store.NHIReviewItem) string {
	reason := []rune("access review " + campaignID + ": " + item.DecisionReason)
	if len(reason) > 480 {
		reason = reason[:480]
	}
	return string(reason)
}

// RevokeReviewedCredential runs the reviewed credential's own revoke and says
// what it did. trstctl revokes PAM sessions, API tokens, machine sessions and
// dynamic-secret leases itself; any other kind is left to its own revocation
// (manual), and its item closes when trstctl sees the credential revoked.
func (a *API) RevokeReviewedCredential(ctx context.Context, tenantID, campaignID string, item store.NHIReviewItem) (string, string) {
	key := NHIReviewIdempotencyKey(campaignID, item.ItemID)
	reason := nhiReviewRevokeReason(campaignID, item)
	kind, id, _ := strings.Cut(item.NHIID, ":")
	switch kind {
	case "pam":
		if a.pam == nil {
			return store.NHIReviewRevocationManual, "PAM is not served here; revoke the session where it is served"
		}
		// A session already ending reports ErrPAMTerminal: the earlier request
		// stands and the item closes when the session reads revoked.
		if _, err := a.pam.RevokePAMSession(ctx, tenantID, id, item.DecisionBy, reason, key); err != nil && !errors.Is(err, ErrPAMTerminal) {
			return store.NHIReviewRevocationFailed, "the PAM session's revocation was refused: " + err.Error()
		}
		return store.NHIReviewRevocationRequested, "PAM session revocation requested; the item closes when the session reads revoked"
	case "token", "msession":
		// A machine session's bearer is the API token with the session's ID;
		// revoking that token ends the session. An already revoked token is
		// left as it is.
		if a.orch == nil {
			return store.NHIReviewRevocationManual, "API token revocation is not served here"
		}
		if err := a.orch.RevokeAPIToken(ctx, tenantID, id, reason); err != nil {
			return store.NHIReviewRevocationFailed, "the API token's revocation was refused: " + err.Error()
		}
		return store.NHIReviewRevocationRequested, "API token revoked; the item closes when the token reads revoked"
	case "lease":
		return a.revokeReviewedLease(ctx, tenantID, id, item.DecisionBy, key)
	}
	return store.NHIReviewRevocationManual, "trstctl does not revoke a " + item.NHIKind +
		" from a review: revoke it through its own revocation, and the item closes when trstctl sees it revoked"
}

func (a *API) revokeReviewedLease(ctx context.Context, tenantID, leaseID, reviewer, key string) (string, string) {
	if a.secrets == nil {
		return store.NHIReviewRevocationManual, "dynamic secrets are not served here; revoke the lease where it is served"
	}
	engine, err := a.secrets.dynamicLeaseEngine(tenantID)
	if err == nil {
		var binding string
		if binding, err = dynamicLeaseMutationBinding("revoke", reviewer, leaseID, 0); err == nil {
			if revoker, ok := engine.(boundDynamicLeaseRevoker); ok {
				_, err = revoker.RevokeBound(ctx, leaseID, key, binding)
			} else {
				err = engine.Revoke(ctx, leaseID)
			}
		}
	}
	if err != nil {
		return store.NHIReviewRevocationFailed, "the dynamic-secret lease's revocation was refused: " + err.Error()
	}
	return store.NHIReviewRevocationRequested, "dynamic-secret lease revocation requested; the item closes when the lease reads revoked"
}

// actOnNHIReviewDecision carries out a recorded decision: a revoke runs the
// credential's revoke and records what happened; a keep renews the named
// owner's attestation.
func (a *API) actOnNHIReviewDecision(ctx context.Context, tenantID string, campaign store.NHIReviewCampaign, itemID string) (store.NHIReviewCampaign, error) {
	for _, item := range campaign.Items {
		if item.ItemID != itemID {
			continue
		}
		switch item.Status {
		case "revoked":
			status, detail := a.RevokeReviewedCredential(ctx, tenantID, campaign.ID, item)
			return a.orch.RecordNHIReviewRevocation(ctx, tenantID, campaign.ID, item.ItemID, status, detail)
		case "certified":
			if ownerID, ok := strings.CutPrefix(item.OwnerRef, "wl:"); ok && ownerID != "" {
				if _, err := a.orch.AttestOwnership(ctx, tenantID, ownerID, item.DecisionBy); err != nil {
					return campaign, err
				}
			}
		}
	}
	return campaign, nil
}

// checkNHIReviewKeep refuses a keep decision whose owner cannot be attested
// before anything is recorded, so a keep never stands without its attestation.
func (a *API) checkNHIReviewKeep(ctx context.Context, tenantID, campaignID, itemID string) error {
	campaign, err := a.store.GetNHIReviewCampaign(ctx, tenantID, campaignID)
	if err != nil {
		return nil // the decision reports the missing campaign
	}
	for _, item := range campaign.Items {
		ownerID, ok := strings.CutPrefix(item.OwnerRef, "wl:")
		if item.ItemID != itemID || !ok || ownerID == "" {
			continue
		}
		owner, err := a.store.GetOwner(ctx, tenantID, ownerID)
		if err != nil {
			return errStatus(http.StatusConflict, "owner "+ownerID+" cannot be read, so a keep decision cannot renew its attestation")
		}
		if !owner.OwnershipComplete() {
			return errStatus(http.StatusConflict, "owner "+ownerID+" has no application_id or environment, so a keep decision cannot renew its attestation; complete the owner first")
		}
	}
	return nil
}

// nhiReviewTargetState reads whether the reviewed credential is revoked, with
// the evidence that says so, or whether its own revoke reported failing.
func (a *API) nhiReviewTargetState(ctx context.Context, tenantID, nhiID string, now time.Time) (string, string, error) {
	kind, id, _ := strings.Cut(nhiID, ":")
	at := func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return " at " + t.UTC().Format(time.RFC3339)
	}
	switch kind {
	case "pam":
		if a.pam == nil {
			return "", "", nil
		}
		s, err := a.pam.GetPAMSession(ctx, tenantID, id)
		if err != nil {
			return "", "", nhiReviewReadError(err)
		}
		switch s.Status {
		case store.PAMSessionStatusRevoked:
			return nhiReviewTargetRevoked, "PAM session revoked" + at(s.EndedAt), nil
		case store.PAMSessionStatusExpired:
			return nhiReviewTargetRevoked, "PAM session expired" + at(s.EndedAt), nil
		case store.PAMSessionStatusRevocationFailed:
			return nhiReviewTargetFailed, "the PAM session's revocation failed; revoke it again from PAM", nil
		}
	case "token", "msession":
		t, err := a.store.GetAPIToken(ctx, tenantID, id)
		if err != nil {
			return "", "", nhiReviewReadError(err)
		}
		if t.RevokedAt != nil {
			by := ""
			if t.RevokedBy != "" {
				by = " by " + t.RevokedBy
			}
			return nhiReviewTargetRevoked, "API token revoked" + at(t.RevokedAt) + by, nil
		}
		if t.ExpiresAt != nil && !now.Before(*t.ExpiresAt) {
			return nhiReviewTargetRevoked, "API token expired" + at(t.ExpiresAt), nil
		}
	case "lease":
		if a.secrets == nil {
			return "", "", nil
		}
		engine, err := a.secrets.dynamicLeaseEngine(tenantID)
		if err != nil {
			return "", "", err
		}
		lease, err := getDynamicLeaseContext(ctx, engine, id)
		if err != nil {
			return "", "", nhiReviewReadError(err)
		}
		if lease.State == dynsecret.LeaseRevoked {
			return nhiReviewTargetRevoked, "dynamic-secret lease revoked" + at(lease.RevokedAt), nil
		}
	case "cert":
		c, err := a.store.GetCertificate(ctx, tenantID, id)
		if err != nil {
			return "", "", nhiReviewReadError(err)
		}
		if c.RevokedAt != nil {
			return nhiReviewTargetRevoked, "certificate " + c.Serial + " revoked" + at(c.RevokedAt), nil
		}
		if c.NotAfter != nil && !now.Before(*c.NotAfter) {
			return nhiReviewTargetRevoked, "certificate " + c.Serial + " expired" + at(c.NotAfter), nil
		}
	case "id":
		it, err := a.store.GetIdentity(ctx, tenantID, id)
		if err != nil {
			return "", "", nhiReviewReadError(err)
		}
		if it.Status == "revoked" {
			return nhiReviewTargetRevoked, "identity " + it.Name + " revoked", nil
		}
	}
	return "", "", nil
}

// nhiReviewReadError treats a credential trstctl no longer holds as not yet
// evidence: its item stays open and visible instead of failing every pass.
func nhiReviewReadError(err error) error {
	if store.IsNotFound(err) {
		return nil
	}
	return err
}

// ReconcileNHIReviewRevocations finishes the tenant's revoke decisions: a
// decision whose act was interrupted acts now with the same idempotency key,
// and an item closes when its credential reads revoked. It returns how many
// items closed.
func (a *API) ReconcileNHIReviewRevocations(ctx context.Context, tenantID string, now time.Time) (int, error) {
	if a.orch == nil || a.store == nil {
		return 0, nil
	}
	items, err := a.store.ListNHIReviewItemsAwaitingClosure(ctx, tenantID, 200)
	if err != nil {
		return 0, err
	}
	closed := 0
	var firstErr error
	note := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return closed, err
		}
		if item.RevocationStatus == "" {
			if item.DecidedAt != nil && now.Sub(*item.DecidedAt) < nhiReviewActGrace {
				continue
			}
			status, detail := a.RevokeReviewedCredential(ctx, tenantID, item.CampaignID, item)
			if _, err := a.orch.RecordNHIReviewRevocation(ctx, tenantID, item.CampaignID, item.ItemID, status, detail); err != nil {
				note(err)
				continue
			}
			item.RevocationStatus = status
		}
		state, detail, err := a.nhiReviewTargetState(ctx, tenantID, item.NHIID, now)
		if err != nil {
			note(err)
			continue
		}
		switch {
		case state == nhiReviewTargetRevoked:
			if _, err := a.orch.CloseNHIReviewItem(ctx, tenantID, item.CampaignID, item.ItemID, detail); err != nil {
				note(err)
				continue
			}
			closed++
		case state == nhiReviewTargetFailed && item.RevocationStatus != store.NHIReviewRevocationFailed:
			if _, err := a.orch.RecordNHIReviewRevocation(ctx, tenantID, item.CampaignID, item.ItemID, store.NHIReviewRevocationFailed, detail); err != nil {
				note(err)
			}
		}
	}
	return closed, firstErr
}
