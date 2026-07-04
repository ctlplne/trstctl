// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// NotificationThresholdDelivery is the projected delivery fact for one expiry
// threshold alert on one notification channel.
type NotificationThresholdDelivery struct {
	TenantID      string
	Subject       string
	ThresholdDays int
	Channel       string
	SentAt        time.Time
}

// HasThresholdNotificationOnChannel reports whether the tenant has already sent
// this subject/threshold/channel tuple.
func (s *Store) HasThresholdNotificationOnChannel(ctx context.Context, tenantID, subject string, threshold int, channel string) (bool, error) {
	var found bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (
			    SELECT 1
			      FROM notification_threshold_deliveries
			     WHERE tenant_id = $1
			       AND subject = $2
			       AND threshold_days = $3
			       AND channel = $4
			)`,
			tenantID, strings.TrimSpace(subject), threshold, normalizeNotificationChannel(channel)).Scan(&found)
	})
	return found, err
}

// ApplyNotificationThresholdDeliveredTx projects a
// notification.threshold.delivered event. Replays are idempotent: the first sent
// timestamp is preserved and the last sent timestamp moves forward.
func (s *Store) ApplyNotificationThresholdDeliveredTx(ctx context.Context, tx pgx.Tx, rec NotificationThresholdDelivery) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO notification_threshold_deliveries
		        (tenant_id, subject, threshold_days, channel, first_sent_at, last_sent_at)
		 VALUES ($1, $2, $3, $4, $5, $5)
		 ON CONFLICT (tenant_id, subject, threshold_days, channel)
		 DO UPDATE SET
		        first_sent_at = LEAST(notification_threshold_deliveries.first_sent_at, EXCLUDED.first_sent_at),
		        last_sent_at = GREATEST(notification_threshold_deliveries.last_sent_at, EXCLUDED.last_sent_at)`,
		rec.TenantID, strings.TrimSpace(rec.Subject), rec.ThresholdDays, normalizeNotificationChannel(rec.Channel), rec.SentAt.UTC())
	return err
}

func normalizeNotificationChannel(channel string) string {
	return strings.ToLower(strings.TrimSpace(channel))
}
