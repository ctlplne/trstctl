// SPDX-License-Identifier: MPL-2.0

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
	err = s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var tokens float64
		var updated time.Time
		scanErr := tx.QueryRow(ctx,
			`SELECT tokens, updated_at FROM rate_limits WHERE tenant_id = $1 AND bucket = $2 FOR UPDATE`,
			tenantID, bucket).Scan(&tokens, &updated)
		switch {
		case scanErr == nil:
			// Refill by the time elapsed since the last take, capped at capacity.
			tokens = math.Min(capacity, tokens+time.Since(updated).Seconds()*refillPerSec)
		case errors.Is(scanErr, pgx.ErrNoRows):
			tokens = capacity // a fresh bucket starts full
		default:
			return scanErr
		}

		if tokens >= 1 {
			allowed = true
			tokens -= 1
		} else {
			allowed = false
			if refillPerSec > 0 {
				retryAfter = time.Duration((1 - tokens) / refillPerSec * float64(time.Second))
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
