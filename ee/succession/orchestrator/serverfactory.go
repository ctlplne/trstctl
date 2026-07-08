// SPDX-License-Identifier: LicenseRef-trstctl-EE

package orchestrator

import (
	"context"
	"errors"
	"time"

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
		return &licensedOutboxHandler{
			orch:      New(d.Store, d.Minter),
			breadth:   NewBreadthWorker(d.Store, d.KEMCustody),
			hasMinter: d.Minter != nil,
			hasKEM:    d.KEMCustody != nil,
			observer:  d.FeatureObserver,
		}, nil
	}
}

type licensedOutboxHandler struct {
	orch      *Orchestrator
	breadth   *BreadthWorker
	hasMinter bool
	hasKEM    bool
	observer  func(feature, action, outcome string, seconds float64)
}

// DeliverLicensed routes the PCAS outbox destinations. It returns handled=false for a
// non-PCAS destination so a composed handler can try the next edition's handler.
func (h *licensedOutboxHandler) DeliverLicensed(ctx context.Context, m coreorch.Message) (bool, error) {
	feature, action, observed := pcasOutboxFeatureAction(m.Destination)
	start := time.Now()
	observe := func(err error) {
		if observed {
			h.observe(feature, action, start, err)
		}
	}
	switch m.Destination {
	case RequestDestination: // pcas.succession-request
		if !h.hasMinter {
			err := errors.New("pcas: no out-of-process signer configured; cannot mint (fail closed)")
			observe(err)
			return true, err
		}
		err := NewSuccessionRequestWorker(h.orch).Deliver(ctx, m)
		observe(err)
		return true, err
	case PublishDestination: // pcas.rp-publish
		// The minted record is already durable in succession_records (RunSuccession)
		// and served by GET chain. Transparency-log submission and stapling push land
		// in INT-19; here it is a successful no-op so the outbox row marks delivered.
		observe(nil)
		return true, nil
	case KEMRewrapDestination, RecoveryRequestDestination, FederationImportDestination:
		if !h.hasKEM {
			err := errors.New("pcas: no out-of-process signer KEM custody configured; cannot run breadth worker (fail closed)")
			observe(err)
			return true, err
		}
		err := h.breadth.Deliver(ctx, m)
		observe(err)
		return true, err
	default:
		return false, nil
	}
}

func (h *licensedOutboxHandler) observe(feature, action string, start time.Time, err error) {
	if h.observer == nil {
		return
	}
	outcome := "success"
	if err != nil {
		outcome = "error"
	}
	h.observer(feature, action, outcome, time.Since(start).Seconds())
}

func pcasOutboxFeatureAction(destination string) (feature, action string, ok bool) {
	switch destination {
	case RequestDestination:
		return "pcas_succession", "mint", true
	case PublishDestination:
		return "pcas_succession", "publish", true
	case KEMRewrapDestination:
		return "pcas_kem", "rewrap", true
	case RecoveryRequestDestination:
		return "pcas_recovery", "mint", true
	case FederationImportDestination:
		return "pcas_federation", "import", true
	default:
		return "", "", false
	}
}
