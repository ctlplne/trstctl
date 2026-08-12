// SPDX-License-Identifier: LicenseRef-trstctl-EE

package decommission

import (
	decapi "trstctl.com/trstctl/ee/decommission/api"
	"trstctl.com/trstctl/ee/decommission/reprotect"
	"trstctl.com/trstctl/ee/decommission/retirement"
	decstore "trstctl.com/trstctl/ee/decommission/store"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	corestore "trstctl.com/trstctl/internal/store"
)

// RuntimeConfig wires the VDEC control-plane runtime from the core composition
// root. It deliberately accepts only feature-neutral core substrates.
type RuntimeConfig struct {
	Store *corestore.Store
	Log   *events.Log
}

// Runtime is the production VDEC control-plane assembly. The outbox factory and
// the API options factory are BOTH mounted by cmd/trstctl/ee_attach.go under the
// single VDEC license block. Mounting only the outbox factory was AUD-2/AUD-3:
// the handler had no producer and the retirement checklist had no source, so a
// licensed deployment logged "attached" and could neither start re-protection
// nor answer the checklist.
type Runtime struct {
	Store                     *decstore.Repo
	ReprotectionOutboxFactory editionseam.LicensedOutboxFactory
	RetirementOutboxFactory   editionseam.LicensedOutboxFactory
	RetirementProjection      *retirement.Projection
	ProjectionOptions         []projections.Option
	// APIOptionsFactory serves the H4 surface: the retirement checklist source
	// behind core's GET route, re-protection production, and the irreversible
	// command producer whose outbox receiver alone reaches the signer.
	APIOptionsFactory editionseam.LicensedAPIOptionsFactory
}

// NewRuntime builds the VDEC runtime over the PostgreSQL-backed store seam. A nil
// store is allowed for attach-only tests and remains fail-closed at delivery time.
func NewRuntime(cfg RuntimeConfig) (*Runtime, error) {
	repo := decstore.New(cfg.Store)
	retirementProjection := retirement.NewProjection(cfg.Store, orchestrator.NewOutbox(cfg.Store))
	return &Runtime{
		Store:                     repo,
		ReprotectionOutboxFactory: reprotect.NewLicensedOutboxFactory(reprotect.WithStore(repo)),
		RetirementOutboxFactory:   retirement.NewOutboxFactory(retirementProjection),
		RetirementProjection:      retirementProjection,
		ProjectionOptions:         []projections.Option{projections.WithEventProjection(retirementProjection)},
		APIOptionsFactory:         decapi.NewAPIOptionsFactory(retirementProjection),
	}, nil
}
