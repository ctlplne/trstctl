// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"trstctl.com/trstctl/internal/audit"
)

// RecordAuditArchiveDownload appends the audit fact that a tenant's archived
// segment is being released to it (A234). The caller releases the bytes only
// after this append succeeds, so a download cannot go unrecorded. The event's
// actor is the authenticated caller.
func (o *Orchestrator) RecordAuditArchiveDownload(ctx context.Context, tenantID string, download audit.ArchiveDownloaded) error {
	if strings.TrimSpace(download.SegmentID) == "" || len(download.SHA256) != 64 || download.FirstRecord <= 0 || download.LastRecord < download.FirstRecord {
		return errors.New("orchestrator: an archive download record needs the segment, digest and record range")
	}
	payload, err := json.Marshal(download)
	if err != nil {
		return err
	}
	_, err = o.emitVersioned(ctx, audit.EventTypeArchiveDownloaded, tenantID, audit.ArchiveDownloadedSchemaVersion, payload)
	return err
}
