// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"context"
	"encoding/json"
	"errors"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// Indexed replay tests append sparse facts and, in one case, a real sealed
// posture receipt. Admit only an unsealed migration start or a posture wrapper
// authenticated under the event's tenant and exact outbox identity.
func openPQCIndexedFixture(ctx context.Context, cfg config.NATS, key seal.KeyWrapper) (*events.Log, error) {
	return events.Open(ctx, cfg, events.WithRequiredAppendAdmission(),
		events.WithAppendAdmission(func(ctx context.Context, event events.Event,
			publish func(context.Context) (events.Event, error),
		) (events.Event, error) {
			switch event.Type {
			case projections.EventLicensedCryptoMigrationStarted:
				var start projections.LicensedCryptoMigrationStarted
				if json.Unmarshal(event.Data, &start) != nil || len(start.TLSPostures) != 0 {
					return events.Event{}, errors.New("PQC fixture: sealed migration start is not admitted")
				}
			case EventTLSFindingCompleted:
				if events.SealedBearingEvent(event) {
					var completed TLSFindingCompleted
					if key == nil || json.Unmarshal(event.Data, &completed) != nil ||
						completed.Intent.RunID == "" || completed.Intent.AssetID == "" {
						return events.Event{}, errors.New("PQC fixture: sealed completion is incomplete")
					}
					idempotencyKey := "licensed-crypto-migration-tls:" + completed.Intent.RunID + ":" + completed.Intent.AssetID
					var opened pqcMigrationTLSPosturePayload
					if _, err := openTLSPostureOutbox(key, event.TenantID,
						licensedCryptoMigrationTLSPostureDestination, idempotencyKey,
						completed.Intent.SealedOutboxPayload, &opened); err != nil {
						return events.Event{}, err
					}
				}
			default:
				if events.SealedBearingEvent(event) {
					return events.Event{}, errors.New("PQC fixture: undeclared sealed event")
				}
			}
			return publish(ctx)
		}))
}
