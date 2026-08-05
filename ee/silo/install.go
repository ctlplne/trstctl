// SPDX-License-Identifier: LicenseRef-trstctl-EE

package silo

import (
	"time"

	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenancy"
)

type Installation struct {
	Registry *MemRegistry
	Router   *Router
	// Durable reports whether placement survives a restart. An in-memory
	// installation reverts every tenant to the shared default on the next
	// deploy, and a sovereignty claim that does that silently is worse than no
	// claim.
	Durable bool
	// PG is the durable registry when there is one.
	PG *PGRegistry
}

func InstallInMemory() *Installation {
	registry := NewMemRegistry()
	router := NewRouter(registry, time.Minute)
	tenancy.SetRouter(router)
	return &Installation{Registry: registry, Router: router, Durable: false}
}

// InstallDurable wires silo placement to PostgreSQL (L4).
//
// The in-memory registry reverted every tenant to the shared default on
// restart, silently. Durable is what a sovereignty claim requires: a customer
// who bought hard isolation must still have it after a deploy.
//
// Falls back to in-memory when no store is available rather than refusing to
// start, but the fallback is VISIBLE via Installation.Durable so a caller can
// tell an unbacked placement from a real one.
func InstallDurable(st *corestore.Store) *Installation {
	if st == nil {
		inst := InstallInMemory()
		inst.Durable = false
		return inst
	}
	registry := NewPGRegistry(st)
	router := NewRouter(registry, time.Minute)
	tenancy.SetRouter(router)
	return &Installation{Router: router, Durable: true, PG: registry}
}
