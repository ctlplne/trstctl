// SPDX-License-Identifier: LicenseRef-trstctl-EE

package orchestrator

import (
	"context"
	"errors"

	"trstctl.com/trstctl/internal/editionseam"
	coreorch "trstctl.com/trstctl/internal/orchestrator"
)

// NewLicensedOutboxFactory returns the PCAS licensed-outbox factory (INT-04). The
// control-plane attach seam registers it on the server's outbox dispatcher, gated on
// the PCAS license, which makes the INT-03 succession worker a real production caller:
// a pcas.succession-request message enqueued by the API is drained here and turned
// into a mint over the signer transport, recorded + published + high-water advanced in
// one transaction. A pcas.rp-publish message is acknowledged (the minted record is
// already durable and served by GET chain; transparency-log submission lands in
// INT-19).
func NewLicensedOutboxFactory() editionseam.LicensedOutboxFactory {
	return func(d editionseam.LicensedOutboxDeps) (editionseam.LicensedOutboxHandler, error) {
		if d.Store == nil {
			return nil, errors.New("pcas outbox: nil store")
		}
		return &licensedOutboxHandler{orch: New(d.Store, d.Minter), hasMinter: d.Minter != nil}, nil
	}
}

type licensedOutboxHandler struct {
	orch      *Orchestrator
	hasMinter bool
}

// DeliverLicensed routes the PCAS outbox destinations. It returns handled=false for a
// non-PCAS destination so a composed handler can try the next edition's handler.
func (h *licensedOutboxHandler) DeliverLicensed(ctx context.Context, m coreorch.Message) (bool, error) {
	switch m.Destination {
	case RequestDestination: // pcas.succession-request
		if !h.hasMinter {
			return true, errors.New("pcas: no out-of-process signer configured; cannot mint (fail closed)")
		}
		return true, NewSuccessionRequestWorker(h.orch).Deliver(ctx, m)
	case PublishDestination: // pcas.rp-publish
		// The minted record is already durable in succession_records (RunSuccession)
		// and served by GET chain. Transparency-log submission and stapling push land
		// in INT-19; here it is a successful no-op so the outbox row marks delivered.
		return true, nil
	default:
		return false, nil
	}
}
