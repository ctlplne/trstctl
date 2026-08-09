// SPDX-License-Identifier: LicenseRef-trstctl-EE

package decommission

import (
	decapi "trstctl.com/trstctl/ee/decommission/api"
	"trstctl.com/trstctl/ee/decommission/reprotect"
	decstore "trstctl.com/trstctl/ee/decommission/store"
	"trstctl.com/trstctl/internal/editionseam"
	corestore "trstctl.com/trstctl/internal/store"
)

// RuntimeConfig wires the VDEC control-plane runtime from the core composition
// root. It deliberately accepts only feature-neutral core substrates.
type RuntimeConfig struct {
	Store *corestore.Store
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
	// APIOptionsFactory serves the H4 surface: the retirement checklist source
	// behind core's GET route, and POST /ca/keys/{id}/reprotect — the production
	// producer for the re-protection outbox handler above.
	APIOptionsFactory editionseam.LicensedAPIOptionsFactory
}

// NewRuntime builds the VDEC runtime over the PostgreSQL-backed store seam. A nil
// store is allowed for attach-only tests and remains fail-closed at delivery time.
func NewRuntime(cfg RuntimeConfig) (*Runtime, error) {
	repo := decstore.New(cfg.Store)
	return &Runtime{
		Store:                     repo,
		ReprotectionOutboxFactory: reprotect.NewLicensedOutboxFactory(reprotect.WithStore(repo)),
		APIOptionsFactory:         decapi.NewAPIOptionsFactory(),
	}, nil
}
