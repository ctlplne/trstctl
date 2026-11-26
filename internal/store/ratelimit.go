// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

// RateLimitTake attempts to take one token from the (tenant, bucket) token bucket
// (R2.3). The bucket holds at most capacity tokens and refills at refillPerSec
// tokens/second; a fresh bucket starts full. It returns whether the take was
// admitted and, when shed, how long until a token is available. The bucket row is
// locked FOR UPDATE so concurrent takes serialize, and the whole operation runs in
// the tenant's RLS context (AN-1).
func (s *Store) RateLimitTake(ctx context.Context, tenantID, bucket string, capacity, refillPerSec float64) (allowed bool, retryAfter time.Duration, err error) {
	return s.RateLimitTakeCost(ctx, tenantID, bucket, capacity, refillPerSec, 1)
}

// RateLimitTakeCost charges a weighted amount to the same durable token bucket.
// Callers use bytes as tokens to bound retained event volume across replicas.
func (s *Store) RateLimitTakeCost(ctx context.Context, tenantID, bucket string, capacity, refillPerSec, cost float64) (allowed bool, retryAfter time.Duration, err error) {
	if capacity <= 0 || refillPerSec < 0 || cost <= 0 || cost > capacity ||
		math.IsNaN(capacity) || math.IsNaN(refillPerSec) || math.IsNaN(cost) ||
		math.IsInf(capacity, 0) || math.IsInf(refillPerSec, 0) || math.IsInf(cost, 0) {
		return false, 0, errors.New("store: invalid rate limit capacity, refill, or cost")
	}
	err = s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var tokens, elapsedSeconds float64
		// Elapsed time is measured by the DATABASE, not this process. updated_at is
		// written with the database's now(), so comparing it against the app clock
		// mixed two clocks that are never guaranteed to agree — and control-plane
		// replicas each bring their own. Skew ahead of the database inflated the
		// refill and let callers exceed their limit; skew behind it made
		// time.Since negative, so every take SUBTRACTED from the bucket and drove a
		// tenant into a throttle that waiting could not clear. Both clocks here are
		// now the transaction's now(), which is also what the write below stores,
		// so the interval is exactly previous-take to this-take with no drift and
		// no double counting.
		readBucket := func() error {
			return tx.QueryRow(ctx,
				`SELECT tokens, GREATEST(0, EXTRACT(EPOCH FROM (now() - updated_at)))
			   FROM rate_limits WHERE tenant_id = $1 AND bucket = $2 FOR UPDATE`,
				tenantID, bucket).Scan(&tokens, &elapsedSeconds)
		}
		scanErr := readBucket()
		if errors.Is(scanErr, pgx.ErrNoRows) {
			// A missing row cannot be locked by SELECT FOR UPDATE. Seed it
			// under the unique key, then read it with a row lock. Concurrent
			// first takes now serialize instead of each spending a full bucket.
			if _, err := tx.Exec(ctx,
				`INSERT INTO rate_limits (tenant_id, bucket, tokens, updated_at)
				 VALUES ($1, $2, $3, now()) ON CONFLICT (tenant_id, bucket) DO NOTHING`,
				tenantID, bucket, capacity); err != nil {
				return err
			}
			scanErr = readBucket()
		}
		if scanErr != nil {
			return scanErr
		}
		// Refill by the time elapsed since the last take, capped at capacity.
		tokens = math.Min(capacity, tokens+elapsedSeconds*refillPerSec)

		if tokens >= cost {
			allowed = true
			tokens -= cost
		} else {
			allowed = false
			if refillPerSec > 0 {
				retryAfter = time.Duration((cost - tokens) / refillPerSec * float64(time.Second))
			} else {
				retryAfter = time.Hour // a non-refilling bucket effectively never frees a token
			}
		}

		_, execErr := tx.Exec(ctx,
			`INSERT INTO rate_limits (tenant_id, bucket, tokens, updated_at)
			 VALUES ($1, $2, $3, now())
			 ON CONFLICT (tenant_id, bucket) DO UPDATE SET tokens = $3, updated_at = now()`,
			tenantID, bucket, tokens)
		return execErr
	})
	return allowed, retryAfter, err
}
