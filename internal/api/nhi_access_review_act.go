// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/orchestrator"
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
	// nhiReviewTargetGone: trstctl no longer holds the credential's record
	// (Q1-L3). There is nothing left to revoke, so a revoke decision's item
	// closes on that evidence instead of staying open on every pass.
	nhiReviewTargetGone = "gone"
)

// nhiReviewGoneEvidence opens the closing evidence of an item closed because
// its credential is gone; the item's closed_as reads it (Q1-L3).
const nhiReviewGoneEvidence = "gone: "

// nhiReviewClosedAs says how a closed revoke item closed: on the credential
// read revoked, or on the credential being gone.
func nhiReviewClosedAs(item store.NHIReviewItem) string {
	if item.RevocationStatus != store.NHIReviewRevocationClosed {
		return ""
	}
	if strings.HasPrefix(item.ClosingEvidence, nhiReviewGoneEvidence) {
		return nhiReviewTargetGone
	}
	return nhiReviewTargetRevoked
}

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
// what it did. trstctl revokes PAM sessions, API tokens, machine sessions,
// dynamic-secret leases and brokered accounts itself, and certificates and
// identities as the reviewer through their own gate (Q1-L1); any other kind,
// or one the gate refuses the reviewer, is left to its own revocation
// (manual), and its item closes when trstctl sees the credential revoked.
func (a *API) RevokeReviewedCredential(ctx context.Context, tenantID, campaignID string, item store.NHIReviewItem) (string, string) {
	return a.revokeReviewedCredentialWithKey(ctx, tenantID, campaignID, item, NHIReviewIdempotencyKey(campaignID, item.ItemID))
}

// revokeReviewedCredentialWithKey is one attempt at the reviewed credential's
// revoke under key: the decision's own key, or a retry's (Q1-L2).
func (a *API) revokeReviewedCredentialWithKey(ctx context.Context, tenantID, campaignID string, item store.NHIReviewItem, key string) (string, string) {
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
	case "cert":
		return a.revokeReviewedCertificate(ctx, tenantID, id, key)
	case "id":
		return a.revokeReviewedIdentity(ctx, tenantID, id, reason, key)
	case "pam-account":
		// A276: a brokered account a reviewer did not certify is disabled;
		// an operator-configured one is removed from configuration by hand.
		if a.pam == nil {
			return store.NHIReviewRevocationManual, "PAM is not served here; disable the account where it is served"
		}
		targetType, targetID, _ := strings.Cut(id, "/")
		if _, err := a.pam.DisablePAMTarget(ctx, tenantID, targetType, targetID, item.DecisionBy, reason); err != nil {
			if errors.Is(err, ErrPAMTargetConflict) {
				return store.NHIReviewRevocationManual, "the account is configured by the operator or already disabled: " + err.Error()
			}
			return store.NHIReviewRevocationFailed, "the account's disabling was refused: " + err.Error()
		}
		return store.NHIReviewRevocationRequested, "brokered account disabled; the item closes when it reads disabled"
	}
	return store.NHIReviewRevocationManual, "trstctl does not revoke a " + item.NHIKind +
		" from a review: revoke it through its own revocation, and the item closes when trstctl sees it revoked"
}

// reviewRevocationPrincipal is the reviewer's own authority for a review's
// revocation (Q1-L1): the principal of the decision request. The reconcile
// and its retries act without one, so a certificate or identity they would
// revoke is left to an operator with that authority.
func reviewRevocationPrincipal(ctx context.Context) (authz.Principal, bool) {
	p, ok := ctx.Value(principalCtxKey).(authz.Principal)
	return p, ok && strings.TrimSpace(p.Subject) != ""
}

// reviewRevocationReason is the RFC 5280 reason a review's certificate
// revocation records: the access is no longer needed.
const reviewRevocationReason = "cessationOfOperation"

// revokeReviewedCertificate revokes a reviewed certificate as the reviewer,
// through the same revocation an operator's request runs: the certificate's
// gate (certs:issue, ABAC, policy, dual control) and the trstctl CA that
// issued it, which publishes the revocation (Q1-L1).
func (a *API) revokeReviewedCertificate(ctx context.Context, tenantID, certificateID, key string) (string, string) {
	principal, ok := reviewRevocationPrincipal(ctx)
	if !ok {
		return store.NHIReviewRevocationManual, "a certificate is revoked with its reviewer's authority, which this pass does not carry; revoke it through Certificates, and the item closes when it reads revoked"
	}
	if a.orch == nil || a.certRevocationAuthority == nil {
		return store.NHIReviewRevocationManual, "certificate revocation is not served here; revoke it where it is served"
	}
	result, err := a.revokeCertificatesAs(ctx, tenantID, key, "access-review", principal,
		bulkRevokeRequest{CertificateIDs: []string{certificateID}, Reason: reviewRevocationReason})
	var denial *gateError
	switch {
	case errors.As(err, &denial):
		return store.NHIReviewRevocationManual, "the certificate's revocation gate refused the reviewer: " + denial.detail +
			"; revoke it through Certificates with that authority, and the item closes when it reads revoked"
	case err != nil:
		return store.NHIReviewRevocationFailed, "the certificate's revocation was refused: " + err.Error()
	}
	for _, item := range result.Items {
		switch item.Status {
		case "revoked":
			return store.NHIReviewRevocationRequested, "certificate revoked (cessationOfOperation) by the trstctl CA that issued it; the item closes when it reads revoked"
		case "queued":
			return store.NHIReviewRevocationRequested, "certificate revocation queued at its issuing authority; the item closes when it reads revoked"
		case "skipped":
			return store.NHIReviewRevocationRequested, "the certificate was already revoked; the item closes when it reads revoked"
		default:
			return store.NHIReviewRevocationManual, "no authority trstctl serves can revoke the certificate (" + item.Error + "); revoke it at its issuer, and the item closes when it reads revoked"
		}
	}
	return store.NHIReviewRevocationFailed, "the certificate's revocation reported nothing"
}

// revokeReviewedIdentity moves a reviewed identity to revoked as the
// reviewer, through its lifecycle gate (Q1-L1): its certificate is revoked
// at its CA and its deployments are told, exactly as an operator's
// transition does.
func (a *API) revokeReviewedIdentity(ctx context.Context, tenantID, identityID, reason, key string) (string, string) {
	principal, ok := reviewRevocationPrincipal(ctx)
	if !ok {
		return store.NHIReviewRevocationManual, "an identity is revoked with its reviewer's authority, which this pass does not carry; revoke it through Identities, and the item closes when it reads revoked"
	}
	if a.orch == nil {
		return store.NHIReviewRevocationManual, "identity transitions are not served here; revoke it where it is served"
	}
	if !principal.Can(authz.IdentitiesWrite, authz.Scope{TenantID: tenantID}) {
		return store.NHIReviewRevocationManual, "the reviewer lacks identities:write; revoke it through Identities with that authority, and the item closes when it reads revoked"
	}
	_, _, err := a.executeIdentityTransition(ctx, tenantID, principal, identityID,
		transitionRequest{To: string(orchestrator.StateRevoked), Reason: reason}, key)
	var refused *apiError
	var transition *orchestrator.TransitionError
	switch {
	case err == nil:
		return store.NHIReviewRevocationRequested, "identity revoked through its lifecycle (its certificate revoked at its CA, its deployments told); the item closes when it reads revoked"
	case errors.As(err, &transition) && transition.From == orchestrator.StateRevoked:
		return store.NHIReviewRevocationRequested, "the identity was already revoked; the item closes when it reads revoked"
	case errors.As(err, &refused) && (refused.status == http.StatusForbidden || refused.status == http.StatusConflict):
		return store.NHIReviewRevocationManual, "the identity's lifecycle gate refused the reviewer: " + refused.detail +
			"; revoke it through Identities with that authority or approval, and the item closes when it reads revoked"
	}
	return store.NHIReviewRevocationFailed, "the identity's revocation was refused: " + err.Error()
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
				// Q1-L6: one campaign attests an owner once. A keep on the
				// owner's next item records nothing more while the attestation
				// an earlier keep of this campaign made is still current.
				attested, err := a.ownerAttestedByCampaign(ctx, tenantID, campaign, item, ownerID)
				if err != nil {
					return campaign, err
				}
				if attested {
					continue
				}
				if _, err := a.orch.AttestOwnership(ctx, tenantID, ownerID, item.DecisionBy); err != nil {
					return campaign, err
				}
			}
		}
	}
	return campaign, nil
}

// ownerAttestedByCampaign reports whether another item of the campaign kept
// the same owner and the owner was attested after the campaign began, with its
// model unchanged since: then this keep's attestation would only repeat it
// (Q1-L6).
func (a *API) ownerAttestedByCampaign(ctx context.Context, tenantID string, campaign store.NHIReviewCampaign, item store.NHIReviewItem, ownerID string) (bool, error) {
	earlier := false
	for _, other := range campaign.Items {
		if other.ItemID != item.ItemID && other.OwnerRef == item.OwnerRef && other.Status == "certified" {
			earlier = true
			break
		}
	}
	if !earlier {
		return false, nil
	}
	owner, err := a.store.GetOwner(ctx, tenantID, ownerID)
	if err != nil {
		return false, err
	}
	if owner.OwnershipVerifiedAt == nil || owner.OwnershipVerifiedAt.Before(campaign.CreatedAt) || owner.OwnershipModelDigest == "" {
		return false, nil
	}
	digest, err := store.OwnerModelDigest(owner)
	return err == nil && digest == owner.OwnershipModelDigest, nil
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
			return nhiReviewReadError(err, "the PAM session")
		}
		switch s.Status {
		case store.PAMSessionStatusRevoked:
			return nhiReviewTargetRevoked, "PAM session revoked" + at(s.EndedAt), nil
		case store.PAMSessionStatusExpired:
			return nhiReviewTargetRevoked, "PAM session expired" + at(s.EndedAt), nil
		case store.PAMSessionStatusRevocationFailed:
			return nhiReviewTargetFailed, "the PAM session's revocation failed; revoke it again from PAM", nil
		}
	case "pam-account":
		if a.pam == nil {
			return "", "", nil
		}
		targetType, targetID, _ := strings.Cut(id, "/")
		target, err := a.pam.GetPAMTarget(ctx, tenantID, targetType, targetID)
		if err != nil {
			return nhiReviewReadError(err, "the brokered account")
		}
		if !target.Enabled {
			return nhiReviewTargetRevoked, "brokered account disabled" + at(target.DisabledAt), nil
		}
	case "token", "msession":
		t, err := a.store.GetAPIToken(ctx, tenantID, id)
		if err != nil {
			return nhiReviewReadError(err, "the API token")
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
			return nhiReviewReadError(err, "the dynamic-secret lease")
		}
		if lease.State == dynsecret.LeaseRevoked {
			return nhiReviewTargetRevoked, "dynamic-secret lease revoked" + at(lease.RevokedAt), nil
		}
	case "cert":
		c, err := a.store.GetCertificate(ctx, tenantID, id)
		if err != nil {
			return nhiReviewReadError(err, "the certificate")
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
			return nhiReviewReadError(err, "the identity")
		}
		if it.Status == "revoked" {
			return nhiReviewTargetRevoked, "identity " + it.Name + " revoked", nil
		}
	}
	return "", "", nil
}

// nhiReviewReadError reads a credential trstctl no longer holds as gone
// (Q1-L3), with what is gone; any other read error stays an error.
func nhiReviewReadError(err error, what string) (string, string, error) {
	if store.IsNotFound(err) {
		return nhiReviewTargetGone, nhiReviewGoneEvidence + "trstctl no longer holds " + what + "; its record was removed, so there is nothing left to revoke", nil
	}
	return "", "", err
}

// ReconcileNHIReviewRevocations finishes the tenant's revoke decisions: a
// decision whose act was interrupted acts now with the same idempotency key,
// a failed revocation is retried once its backoff passes (Q1-L2), and an item
// closes when its credential reads revoked or is gone (Q1-L3). It returns how
// many items closed.
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
		case state == nhiReviewTargetRevoked || state == nhiReviewTargetGone:
			if _, err := a.orch.CloseNHIReviewItem(ctx, tenantID, item.CampaignID, item.ItemID, detail); err != nil {
				note(err)
				continue
			}
			closed++
		case state == nhiReviewTargetFailed && item.RevocationStatus != store.NHIReviewRevocationFailed:
			if _, err := a.orch.RecordNHIReviewRevocation(ctx, tenantID, item.CampaignID, item.ItemID, store.NHIReviewRevocationFailed, detail); err != nil {
				note(err)
			}
		case nhiReviewAutoRetryDue(item, now):
			if _, err := a.autoRetryNHIReviewRevocation(ctx, tenantID, item); err != nil {
				note(err)
			}
		}
	}
	return closed, firstErr
}
