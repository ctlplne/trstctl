// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package auditcompliance owns licensed audit anchoring and retention execution.
// Core retains history, signed export, checkpoint recovery and offline verification.
package auditcompliance

import (
	"context"

	"trstctl.com/trstctl/internal/audit"
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
	if d.Audit != nil && d.Log != nil && d.Signer != nil && d.Checkpoints != nil && d.Retention > 0 {
		if archiver := archiverFor(d); archiver != nil {
			runtime.Retention = NewRetentionWorker(d.Audit, d.Log, archiver, d.Checkpoints, d.Retention, d.Signer)
		}
	}
	return runtime
}

// archiverFor picks the configured archive target: the object store when the
// deployment archives there, else the archive directory, else none (retention
// then does not run).
func archiverFor(d editionseam.AuditComplianceDeps) Archiver {
	switch {
	case d.ArchiveStore != nil:
		svc := d.Audit
		return ObjectArchiver{Store: d.ArchiveStore, Verify: func(signed string) (audit.Bundle, error) {
			return audit.VerifyRetentionBundle(signed, svc.VerificationKeys())
		}}
	case d.ArchiveDir != "":
		return DirArchiver{Dir: d.ArchiveDir}
	}
	return nil
}
