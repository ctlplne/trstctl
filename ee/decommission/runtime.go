// SPDX-License-Identifier: LicenseRef-trstctl-EE

package decommission

import (
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

// Runtime is the production VDEC control-plane assembly. The outbox factory is
// mounted by cmd/trstctl/ee_attach.go under the single VDEC license block.
type Runtime struct {
	Store                     *decstore.Repo
	ReprotectionOutboxFactory editionseam.LicensedOutboxFactory
}

// NewRuntime builds the VDEC runtime over the PostgreSQL-backed store seam. A nil
// store is allowed for attach-only tests and remains fail-closed at delivery time.
func NewRuntime(cfg RuntimeConfig) (*Runtime, error) {
	repo := decstore.New(cfg.Store)
	return &Runtime{
		Store:                     repo,
		ReprotectionOutboxFactory: reprotect.NewLicensedOutboxFactory(reprotect.WithStore(repo)),
	}, nil
}
