// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqcmigration

import (
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Runtime is the single production PQC migration object graph. API reads,
// outbox completion projection, boot replay, and the live projection tail all
// share exactly one progress projection instance.
type Runtime struct {
	Progress          *ProgressProjection
	APIOptionsFactory editionseam.LicensedAPIOptionsFactory
	OutboxFactory     editionseam.LicensedOutboxFactory
	ProjectionOptions []projections.Option
}

func NewRuntime(st *store.Store) *Runtime {
	progress := NewProgressProjection(st)
	return &Runtime{
		Progress:          progress,
		APIOptionsFactory: NewAPIOptionsFactory(progress),
		OutboxFactory:     NewOutboxFactory(progress),
		ProjectionOptions: []projections.Option{WithProgressProjection(progress)},
	}
}
