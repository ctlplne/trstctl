package server

import (
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
)

// ManagedKeyServiceFactory is supplied by the tagged EE attach seam when the
// Enterprise BYOK feature is licensed and configured. Core owns the API option
// contract; EE owns the managed-key implementation.
type ManagedKeyServiceFactory func(ManagedKeyServiceDeps) (api.ManagedKeyService, error)

// ManagedKeyServiceDeps are the core spine dependencies the licensed managed-key
// service consumes without importing server internals.
type ManagedKeyServiceDeps struct {
	Log             *events.Log
	Idempotency     *orchestrator.Idempotency
	ApprovalChecker api.ApprovalChecker
}
