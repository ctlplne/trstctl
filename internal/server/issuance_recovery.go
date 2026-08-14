// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func recoverCertificatesByIssuanceKey(ctx context.Context, st *store.Store, log *events.Log, tenantID, key string) ([]store.Certificate, error) {
	certs, err := st.ListCertificatesByIssuanceIdempotencyKey(ctx, tenantID, key)
	if err != nil {
		return nil, err
	}
	if len(certs) > 0 || log == nil {
		return certs, nil
	}
	// Recovery asks one small question: did this exact issuance key already append
	// a certificate before its idempotency transaction rolled back? Rebuilding
	// every extension projection answers a much larger boot-time question and made
	// each ordinary issuance slower as retained history grew. Scan immutable event
	// envelopes, select only matching certificate events, and idempotently apply
	// those rows. Full catch-up remains the startup/tailer responsibility.
	var retained []events.Event
	if err := log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID != tenantID || event.Type != projections.EventCertificateRecorded {
			return nil
		}
		var payload projections.CertificateRecorded
		if err := json.Unmarshal(event.Data, &payload); err != nil {
			return fmt.Errorf("server: decode retained certificate event %s: %w", event.ID, err)
		}
		if payload.IssuanceIdempotencyKey == key {
			retained = append(retained, event)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("server: scan issued certificate recovery events: %w", err)
	}
	projector := projections.New(st)
	for _, event := range retained {
		if err := projector.Apply(ctx, event); err != nil {
			return nil, fmt.Errorf("server: recover issued certificate projection: %w", err)
		}
	}
	return st.ListCertificatesByIssuanceIdempotencyKey(ctx, tenantID, key)
}
