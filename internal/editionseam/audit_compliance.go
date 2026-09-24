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
)

// AuditRetentionWorker is supervised by core; its archival policy and execution
// are supplied only by the licensed composition root.
type AuditRetentionWorker interface {
	RunOnce(context.Context) (audit.Summary, error)
}

type AuditCheckpoints interface {
	audit.CheckpointSource
	audit.CheckpointSink
}

type AuditComplianceDeps struct {
	Audit       *audit.Service
	Log         *events.Log
	Signer      *jose.SigningKey
	Checkpoints AuditCheckpoints
	Timestamper auditanchor.Timestamper
	Retention   time.Duration
	ArchiveDir  string
}

type AuditComplianceRuntime struct {
	Anchor    api.AuditAnchorFunc
	Retention AuditRetentionWorker
}

type AuditComplianceFactory func(AuditComplianceDeps) AuditComplianceRuntime
