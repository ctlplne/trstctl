// SPDX-License-Identifier: BUSL-1.1

package editionseam

import (
	"context"

	"trstctl.com/trstctl/internal/notify"
)

// AlertObserver sees every alert on the notification surface before its
// channels do (MSP-3: a Provider's PSA tickets). alertRef is the alert's
// outbox idempotency key, stable across the row's retries, so an observer
// can record each alert once. An error retries the notification row; its
// channels keep their per-channel receipts, so nothing is sent twice. Core
// attaches none; the licensed composition root may.
type AlertObserver interface {
	ObserveAlert(ctx context.Context, tenantID, alertRef string, alert notify.Alert) error
}
