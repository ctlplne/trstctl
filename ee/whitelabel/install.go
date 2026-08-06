// SPDX-License-Identifier: LicenseRef-trstctl-EE

package whitelabel

import (
	"time"

	"trstctl.com/trstctl/internal/branding"
	corestore "trstctl.com/trstctl/internal/store"
)

type Installation struct {
	Store    *MemStore
	Resolver *Resolver
	// Durable reports whether a configured brand survives a deploy. In-memory
	// loses it silently, and a white-label feature that reverts to our name
	// without saying so is the product failing quietly.
	Durable bool
	PG      *PGStore
}

func InstallInMemory() *Installation {
	store := NewMemStore()
	resolver := NewResolver(store, time.Minute)
	branding.SetSource(resolver)
	return &Installation{Store: store, Resolver: resolver, Durable: false}
}

// InstallDurable wires branding to PostgreSQL (L3, AUD-14).
//
// The in-memory store lost a provider's brand on every deploy, silently. The
// fallback when no store exists stays VISIBLE via Installation.Durable so a
// caller can tell a brand that will survive from one that will not.
func InstallDurable(st *corestore.Store) *Installation {
	if st == nil {
		inst := InstallInMemory()
		inst.Durable = false
		return inst
	}
	store := NewPGStore(st)
	resolver := NewResolver(store, time.Minute)
	branding.SetSource(resolver)
	return &Installation{Resolver: resolver, Durable: true, PG: store}
}
