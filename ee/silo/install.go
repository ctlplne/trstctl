package silo

import (
	"time"

	"trstctl.com/trstctl/internal/tenancy"
)

type Installation struct {
	Registry *MemRegistry
	Router   *Router
}

func InstallInMemory() *Installation {
	registry := NewMemRegistry()
	router := NewRouter(registry, time.Minute)
	tenancy.SetRouter(router)
	return &Installation{Registry: registry, Router: router}
}
