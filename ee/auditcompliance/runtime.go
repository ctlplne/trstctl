// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package auditcompliance owns licensed audit anchoring and retention execution.
// Core retains history, signed export, checkpoint recovery and offline verification.
package auditcompliance

import (
	"context"

	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/editionseam"
)

// Build is attached once for FeatureAuditCompliance. It resolves the served TSA
// lazily through the supplied capability, preserving protocol startup ordering.
func Build(d editionseam.AuditComplianceDeps) editionseam.AuditComplianceRuntime {
	runtime := editionseam.AuditComplianceRuntime{
		Anchor: func(ctx context.Context, head string) (auditanchor.Anchor, error) {
			return auditanchor.AnchorHead(ctx, d.Timestamper, head)
		},
	}
	if d.Audit != nil && d.Log != nil && d.Signer != nil && d.Checkpoints != nil && d.Retention > 0 && d.ArchiveDir != "" {
		runtime.Retention = NewRetentionWorker(d.Audit, d.Log, DirArchiver{Dir: d.ArchiveDir}, d.Checkpoints, d.Retention, d.Signer)
	}
	return runtime
}
