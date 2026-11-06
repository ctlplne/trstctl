// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/pamdiscovery"
)

const EventPAMDiscoveryScanQueued = "pam.discovery.scan_queued"

func (p *Projector) applyPAMDiscoveryScanQueuedTx(ctx context.Context, tx pgx.Tx, e events.Event) error {
	var intent pamdiscovery.ScanIntent
	if err := decode(e, &intent); err != nil {
		return err
	}
	if err := intent.Validate(); err != nil {
		return err
	}
	if e.ID != intent.RunID {
		return errors.New("PAM discovery: queued source ID differs")
	}
	return p.store.ApplyPAMDiscoveryScanQueuedTx(ctx, tx, e.TenantID, intent)
}
func addPAMDiscoveryOutboxPrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	exact := events.PrivacyFieldOpaqueExact
	policies[privacyEventPolicyKey{EventPAMDiscoveryScanQueued, 1}] = privacyRules(privacyRule("/run_id", exact), privacyRule("/completion_event_id", exact), privacyRule("/provider_id", exact), privacyRule("/source_saved_at", exact), privacyRule("/requested_by", events.PrivacyFieldIdentityExact), privacyRule("/queued_at", exact))
}
func addPAMDiscoveryOutboxPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventPAMDiscoveryScanQueued, 1}] = privacyPayloadShape[pamdiscovery.ScanIntent]()
}
