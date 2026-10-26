// SPDX-License-Identifier: BUSL-1.1

package editionseam

import (
	"context"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/store"
)

// AuditRetentionWorker is supervised by core; its archival policy and execution
// are supplied only by the licensed composition root.
type AuditRetentionWorker interface {
	RunOnce(context.Context) (audit.Summary, error)
}

// AuditAnchorWorker is supervised by core: on its cadence it timestamps each
// tenant's full audit chain that grew since its last anchor and appends the
// anchor to that tenant's audit log (A147). Its policy and execution are
// supplied only by the licensed composition root.
type AuditAnchorWorker interface {
	RunOnce(context.Context) (AuditAnchorSummary, error)
	Interval() time.Duration
}

// AuditAnchorSummary is what one anchoring pass did.
type AuditAnchorSummary struct {
	TenantsAnchored  int
	TenantsUnchanged int
}

// AuditTenants enumerates the tenants whose audit chains are anchored.
type AuditTenants interface {
	ListTenants(context.Context) ([]store.Tenant, error)
}

type AuditCheckpoints interface {
	audit.CheckpointSource
	audit.CheckpointSink
	WithAuditRetentionScope(context.Context, string, func(context.Context) error) error
}

type AuditComplianceDeps struct {
	Audit       *audit.Service
	Log         *events.Log
	Signer      *jose.SigningKey
	Checkpoints AuditCheckpoints
	Timestamper auditanchor.Timestamper
	Retention   time.Duration
	ArchiveDir  string
	// ArchiveStore, when set, takes the archive segments instead of ArchiveDir.
	ArchiveStore objectstore.Store
	// AnchorInterval is the continuous anchoring cadence; zero turns it off.
	AnchorInterval time.Duration
	Tenants        AuditTenants
}

type AuditComplianceRuntime struct {
	Anchor    api.AuditAnchorFunc
	Retention AuditRetentionWorker
	Anchoring AuditAnchorWorker
}

type AuditComplianceFactory func(AuditComplianceDeps) AuditComplianceRuntime
