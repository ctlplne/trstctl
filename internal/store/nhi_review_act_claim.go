// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// WithNHIReviewActClaim runs fn while holding the review item's in-flight act
// claim (Q1-L10): a PostgreSQL SESSION advisory lock keyed by tenant, campaign
// and item, taken on the tenant service session (the request's own when one is
// held, so nested projection locks reuse it, else one taken here), never a SQL
// transaction held across the act's IO. A decision request holds it from
// before its decision is recorded until what it did is recorded; the access
// review reconcile acts on a decided item only while holding it. The claim
// lives exactly as long as its holder's database session: a holder that
// returns releases it, and a process that dies releases it with its
// connection, so the reconcile acts on the next pass after a request dies and
// never while one still acts. It never waits: when another session holds the
// claim it returns acquired false and fn does not run.
func (s *Store) WithNHIReviewActClaim(ctx context.Context, tenantID, campaignID, itemID string, fn func(context.Context) error) (acquired bool, result error) {
	if s == nil || fn == nil {
		return false, errors.New("store: review act claim is incomplete")
	}
	parsed, err := uuid.Parse(tenantID)
	campaignID, itemID = strings.TrimSpace(campaignID), strings.TrimSpace(itemID)
	if err != nil || campaignID == "" || itemID == "" || len(campaignID) > 128 || len(itemID) > 128 {
		return false, errors.New("store: review act claim needs a tenant UUID, campaign and item")
	}
	tenantID = parsed.String()
	// Campaign and item IDs are UUIDs: one item's claim has one name however
	// a request spelled them.
	if canonical, err := uuid.Parse(campaignID); err == nil {
		campaignID = canonical.String()
	}
	if canonical, err := uuid.Parse(itemID); err == nil {
		itemID = canonical.String()
	}
	if held, _ := ctx.Value(tenantServiceFenceKey{}).(*tenantServiceFence); held == nil {
		work, release, err := s.BeginTenantService(ctx, tenantID)
		if err != nil {
			return false, err
		}
		defer release()
		ctx = work
	} else if held.store != s || held.tenantID != tenantID || !held.active.Load() {
		return false, errors.New("store: review act claim has a foreign or expired tenant service session")
	}
	name := nhiReviewActClaimName(tenantID, campaignID, itemID)
	conn, done, err := s.borrowTenantServiceSession(ctx)
	if err != nil {
		return false, err
	}
	if conn == nil {
		done()
		return false, errors.New("store: review act claim has no tenant service session")
	}
	err = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, name).Scan(&acquired)
	if err != nil {
		// A canceled query may have taken the session lock without returning
		// the result. Closing the connection is the only unambiguous release.
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = conn.Conn().Close(cleanup)
		cancel()
	}
	done()
	if err != nil {
		return false, fmt.Errorf("store: take the review act claim: %w", err)
	}
	if !acquired {
		return false, nil
	}
	defer func() {
		conn, done, err := s.borrowTenantServiceSession(ctx)
		if err != nil || conn == nil {
			if result == nil {
				result = errors.Join(errors.New("store: release the review act claim: no tenant service session"), err)
			}
			return
		}
		defer done()
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		var released bool
		unlockErr := conn.QueryRow(cleanup, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, name).Scan(&released)
		if unlockErr != nil || !released {
			_ = conn.Conn().Close(cleanup)
			if result == nil {
				result = fmt.Errorf("store: release the review act claim: %v (released=%v)", unlockErr, released)
			}
		}
	}()
	return true, fn(ctx)
}

// nhiReviewActClaimName is the advisory lock name of one review item's act
// claim.
func nhiReviewActClaimName(tenantID, campaignID, itemID string) string {
	return "nhi-review-act\x1f" + tenantID + "\x1f" + campaignID + "\x1f" + itemID
}

// GetNHIReviewItem reads one review item; the reconcile reads it again under
// the item's act claim before it acts (Q1-L10).
func (s *Store) GetNHIReviewItem(ctx context.Context, tenantID, campaignID, itemID string) (NHIReviewItem, error) {
	var out NHIReviewItem
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		item, err := scanNHIReviewItem(tx.QueryRow(ctx,
			`SELECT `+nhiReviewItemColumns+`
			   FROM nhi_access_review_items
			  WHERE tenant_id = $1
			    AND campaign_id = $2
			    AND item_id = $3`,
			tenantID, campaignID, itemID))
		out = item
		return err
	})
	return out, err
}
