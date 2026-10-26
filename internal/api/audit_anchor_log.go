// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/store"
)

// AuditAnchorLogReader reads a tenant's whole anchor log (A148).
type AuditAnchorLogReader interface {
	AuditAnchorLog(ctx context.Context, tenantID string) ([]store.AuditAnchor, error)
}

// anchorLogFrom reads the export's anchor_log_from: the tree size of an
// anchor log head the auditor kept from an earlier export.
func anchorLogFrom(r *http.Request) (int, error) {
	raw := r.URL.Query().Get("anchor_log_from")
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 0, errStatus(http.StatusBadRequest, "anchor_log_from must be a positive anchor log size")
	}
	return n, nil
}

// auditAnchorLogProof proves the anchor records an export holds against the
// tenant's anchor log. It returns nil when the deployment keeps no anchor log
// or the tenant has no anchors.
func (a *API) auditAnchorLogProof(ctx context.Context, tenantID string, records []auditchain.Record, fromSize int) (*auditanchor.AnchorLogProof, error) {
	reader, ok := a.auditAnchorReader.(AuditAnchorLogReader)
	if !ok || reader == nil || a.audit == nil {
		if fromSize > 0 {
			return nil, errStatus(http.StatusBadRequest, "this deployment keeps no audit anchor log")
		}
		return nil, nil
	}
	rows, err := reader.AuditAnchorLog(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	entries := make([]auditanchor.AnchorLogEntry, 0, len(rows))
	for _, row := range rows {
		entries = append(entries, auditanchor.AnchorLogEntry{
			EventID: row.EventID, ThroughSequence: row.ThroughSequence, ChainHead: row.ChainHead, TokenSHA256: row.TokenSHA256,
		})
	}
	proof, err := auditanchor.BuildAnchorLogProof(tenantID, entries, records, fromSize, time.Now(), a.audit)
	if errors.Is(err, auditanchor.ErrAnchorLogFrom) {
		return nil, errStatus(http.StatusBadRequest, "anchor_log_from is larger than this tenant's anchor log")
	}
	return proof, err
}
