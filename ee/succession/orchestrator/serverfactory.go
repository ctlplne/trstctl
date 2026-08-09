// SPDX-License-Identifier: LicenseRef-trstctl-EE

package orchestrator

import (
	"context"
	"errors"
	"strings"
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
func NewLicensedOutboxFactory(opts ...FactoryOption) editionseam.LicensedOutboxFactory {
	cfg := factoryConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
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
			topics:    cfg.topics.resolved(),
		}, nil
	}
}

// FactoryOption customizes the PCAS licensed-outbox factory.
type FactoryOption func(*factoryConfig)

type factoryConfig struct {
	topics BreadthTopics
}

// WithBreadthTopics resolves the breadth destinations from operator
// configuration (pcas.{recovery,federation,kem}.outbox_topic), so the dispatch
// side drains exactly what the API side enqueues (AUD-7). Blank values keep the
// canonical constants. The handler additionally keeps draining the canonical
// constants when a topic is re-pointed: rows enqueued under the old name before
// a config change must not be orphaned to the dead-letter queue by a restart.
func WithBreadthTopics(recovery, federation, kem string) FactoryOption {
	return func(c *factoryConfig) {
		c.topics = BreadthTopics{Recovery: recovery, Federation: federation, KEM: kem}
	}
}

// BreadthTopics carries the resolved breadth outbox destinations.
type BreadthTopics struct {
	Recovery   string
	Federation string
	KEM        string
}

// resolved fills blanks with the canonical constants.
func (t BreadthTopics) resolved() BreadthTopics {
	if strings.TrimSpace(t.Recovery) == "" {
		t.Recovery = RecoveryRequestDestination
	}
	if strings.TrimSpace(t.Federation) == "" {
		t.Federation = FederationImportDestination
	}
	if strings.TrimSpace(t.KEM) == "" {
		t.KEM = KEMRewrapDestination
	}
	return t
}

type licensedOutboxHandler struct {
	orch      *Orchestrator
	breadth   *BreadthWorker
	hasMinter bool
	hasKEM    bool
	observer  func(feature, action, outcome string, seconds float64)
	topics    BreadthTopics
}

// DeliverLicensed routes the PCAS outbox destinations. It returns handled=false for a
// non-PCAS destination so a composed handler can try the next edition's handler.
func (h *licensedOutboxHandler) DeliverLicensed(ctx context.Context, m coreorch.Message) (bool, error) {
	feature, action, observed := h.featureAction(m.Destination)
	start := time.Now()
	observe := func(err error) {
		if observed {
			h.observe(feature, action, start, err)
		}
	}
	switch {
	case m.Destination == RequestDestination: // pcas.succession-request
		if !h.hasMinter {
			err := errors.New("pcas: no out-of-process signer configured; cannot mint (fail closed)")
			observe(err)
			return true, err
		}
		err := NewSuccessionRequestWorker(h.orch).Deliver(ctx, m)
		observe(err)
		return true, err
	case m.Destination == PublishDestination: // pcas.rp-publish
		// The minted record is already durable in succession_records (RunSuccession)
		// and served by GET chain. Transparency-log submission and stapling push land
		// in INT-19; here it is a successful no-op so the outbox row marks delivered.
		observe(nil)
		return true, nil
	case h.breadthKind(m.Destination) != "":
		if !h.hasKEM {
			err := errors.New("pcas: no out-of-process signer KEM custody configured; cannot run breadth worker (fail closed)")
			observe(err)
			return true, err
		}
		err := h.breadth.DeliverKind(ctx, h.breadthKind(m.Destination), m)
		observe(err)
		return true, err
	default:
		return false, nil
	}
}

// breadthKind maps a destination to its breadth family, honoring BOTH the
// operator-configured topic and the canonical constant — a repointed topic must
// not orphan rows enqueued under the previous name (AUD-7).
func (h *licensedOutboxHandler) breadthKind(destination string) breadthKind {
	topics := h.topics.resolved()
	switch destination {
	case topics.KEM, KEMRewrapDestination:
		return breadthKEM
	case topics.Recovery, RecoveryRequestDestination:
		return breadthRecovery
	case topics.Federation, FederationImportDestination:
		return breadthFederation
	default:
		return ""
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

func (h *licensedOutboxHandler) featureAction(destination string) (feature, action string, ok bool) {
	switch destination {
	case RequestDestination:
		return "pcas_succession", "mint", true
	case PublishDestination:
		return "pcas_succession", "publish", true
	}
	switch h.breadthKind(destination) {
	case breadthKEM:
		return "pcas_kem", "rewrap", true
	case breadthRecovery:
		return "pcas_recovery", "mint", true
	case breadthFederation:
		return "pcas_federation", "import", true
	default:
		return "", "", false
	}
}
