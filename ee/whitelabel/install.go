package whitelabel

import (
	"time"

	"trstctl.com/trstctl/internal/branding"
)

type Installation struct {
	Store    *MemStore
	Resolver *Resolver
}

func InstallInMemory() *Installation {
	store := NewMemStore()
	resolver := NewResolver(store, time.Minute)
	branding.SetSource(resolver)
	return &Installation{Store: store, Resolver: resolver}
}
