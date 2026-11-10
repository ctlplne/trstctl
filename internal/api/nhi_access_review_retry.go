// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// Q1-L2: a failed review revocation is retried. The reviewer's decision
// stands; what failed is the credential's own revoke, and some of those
// refusals pass (a provider that was down comes back). The leader's reconcile
// retries on its own, on a backoff that grows with how long the revocation has
// been failing, for a week after the first request; an operator retries at any
// time with a reason. Each attempt carries its own idempotency key — a revoke
// path such as PAM refuses to retry a failed revocation under the key that
// failed — while a replay of one attempt keeps its key and revokes nothing
// twice.

const (
	nhiReviewRetryMin    = 5 * time.Minute
	nhiReviewRetryMax    = 6 * time.Hour
	nhiReviewRetryWindow = 7 * 24 * time.Hour
	nhiReviewRetryReason = 200
)

// NHIReviewRevocationRetryRequest is an operator's retry of a failed review
// revocation: why it is retried now.
type NHIReviewRevocationRetryRequest struct {
	Reason string `json:"reason"`
}

// nhiReviewRetryKey names one retry attempt of an item's revocation.
func nhiReviewRetryKey(campaignID, itemID, attempt string) string {
	return NHIReviewIdempotencyKey(campaignID, itemID) + ":retry:" + attempt
}

// nhiReviewAutoRetryDue reports whether the reconcile retries a failed
// revocation now: it waits as long as the revocation has been failing (at
// least five minutes, at most six hours) since the last attempt, and stops a
// week after the first request, leaving the item failed and visible for an
// operator.
func nhiReviewAutoRetryDue(item store.NHIReviewItem, now time.Time) bool {
	if item.RevocationStatus != store.NHIReviewRevocationFailed || item.RevocationRequestedAt == nil {
		return false
	}
	first := *item.RevocationRequestedAt
	if now.Sub(first) > nhiReviewRetryWindow {
		return false
	}
	wait := min(max(item.UpdatedAt.Sub(first), nhiReviewRetryMin), nhiReviewRetryMax)
	return !now.Before(item.UpdatedAt.Add(wait))
}

// autoRetryNHIReviewRevocation runs one automatic retry. Its key is fixed by
// the failure it retries, so a reconcile that dies after acting repeats the
// same request instead of making a new one.
func (a *API) autoRetryNHIReviewRevocation(ctx context.Context, tenantID string, item store.NHIReviewItem) (string, error) {
	key := nhiReviewRetryKey(item.CampaignID, item.ItemID, "auto:"+item.UpdatedAt.UTC().Format(time.RFC3339Nano))
	status, detail := a.revokeReviewedCredentialWithKey(ctx, tenantID, item.CampaignID, item, key)
	if _, err := a.orch.RecordNHIReviewRevocation(ctx, tenantID, item.CampaignID, item.ItemID, status,
		"automatic retry after a failed revocation: "+detail); err != nil {
		return "", err
	}
	return status, nil
}

// retryNHIReviewRevocation is an operator's retry of a failed review
// revocation, with a reason. The retry's key derives from this request's
// Idempotency-Key, so an exact replay returns the first answer and a new
// request is a new attempt.
//
//trstctl:mutation
func (a *API) retryNHIReviewRevocation(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	campaignID := r.PathValue("id")
	itemID := r.PathValue("item_id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil || a.store == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "NHI access reviews are not configured")
		}
		var req NHIReviewRevocationRetryRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		reason := strings.TrimSpace(req.Reason)
		if reason == "" || utf8.RuneCountInString(reason) > nhiReviewRetryReason {
			return 0, nil, errStatus(http.StatusBadRequest, "a revocation retry needs a reason of at most 200 characters")
		}
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		campaign, err := a.store.GetNHIReviewCampaign(ctx, tenantID, campaignID)
		if store.IsNotFound(err) {
			return 0, nil, errStatus(http.StatusNotFound, "NHI access review not found")
		}
		if err != nil {
			return 0, nil, err
		}
		var item *store.NHIReviewItem
		for i := range campaign.Items {
			if campaign.Items[i].ItemID == itemID {
				item = &campaign.Items[i]
			}
		}
		switch {
		case item == nil:
			return 0, nil, errStatus(http.StatusNotFound, "NHI access review item not found")
		case item.Status != "revoked":
			return 0, nil, errStatus(http.StatusConflict, "only a revoke decision's revocation can be retried; this item is "+item.Status)
		case item.RevocationStatus != store.NHIReviewRevocationFailed:
			return 0, nil, errStatus(http.StatusConflict, "only a failed revocation can be retried; this one is "+item.RevocationStatus)
		}
		key := nhiReviewRetryKey(campaignID, itemID, "operator:"+crypto.SHA256Hex([]byte(tenantID + "\x00" + idempotencyKey))[:32])
		status, detail := a.revokeReviewedCredentialWithKey(ctx, tenantID, campaignID, *item, key)
		campaign, err = a.orch.RecordNHIReviewRevocation(ctx, tenantID, campaignID, itemID, status,
			"retried by "+subject+" ("+reason+"): "+detail)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toNHIReviewCampaignResponse(campaign, true), nil
	})
}
