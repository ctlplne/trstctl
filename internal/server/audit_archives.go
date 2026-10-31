// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"log/slog"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditarchive"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
)

// auditArchiveService serves a tenant its own archived audit segments (A234)
// through the core reader, and appends the audit fact of every release before
// the bytes leave. Archive download is a core audit/export right: no license
// gate, no import from ee/.
type auditArchiveService struct {
	reader auditarchive.Reader
	orch   *orchestrator.Orchestrator
}

// auditArchiveAPIOption serves the routes when the deployment has an audit log
// and a configured archive location.
func (s *Server) auditArchiveAPIOption(d Deps, orch *orchestrator.Orchestrator) api.Option {
	if d.Log == nil || orch == nil || s.audit == nil || (d.AuditArchiveDir == "" && d.ArchiveObjectStore == nil) {
		return api.WithAuditArchives(nil)
	}
	return api.WithAuditArchives(&auditArchiveService{
		reader: auditarchive.Reader{Log: d.Log, Keys: s.audit.VerificationKeys, Dir: d.AuditArchiveDir, Objects: d.ArchiveObjectStore},
		orch:   orch,
	})
}

func (s *auditArchiveService) ListSegments(ctx context.Context, tenantID string) ([]api.AuditArchiveSegment, error) {
	segments, err := s.reader.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]api.AuditArchiveSegment, 0, len(segments))
	for _, segment := range segments {
		out = append(out, api.AuditArchiveSegment{ID: segment.ID, FirstRecord: segment.FirstRecord, LastRecord: segment.LastRecord,
			BoundarySequence: segment.BoundarySequence, ChainHead: segment.ChainHead, ArchivedAt: segment.ArchivedAt})
	}
	return out, nil
}

func (s *auditArchiveService) Download(ctx context.Context, tenantID, segmentID string) (api.AuditArchiveDownload, error) {
	release, err := s.reader.Read(ctx, tenantID, segmentID)
	switch {
	case errors.Is(err, auditarchive.ErrNotFound):
		return api.AuditArchiveDownload{}, api.ErrAuditArchiveNotFound
	case errors.Is(err, auditarchive.ErrUnavailable):
		slog.WarnContext(ctx, "audit archive: segment not served to its tenant", "segment", segmentID, "error", err)
		return api.AuditArchiveDownload{}, api.ErrAuditArchiveUnavailable
	case err != nil:
		return api.AuditArchiveDownload{}, err
	}
	digest := crypto.SHA256Hex([]byte(release.Signed))
	// Audit before release: a failed append means nothing is served.
	if err := s.orch.RecordAuditArchiveDownload(ctx, tenantID, audit.ArchiveDownloaded{
		SegmentID: segmentID, SHA256: digest, FirstRecord: release.FirstRecord, LastRecord: release.LastRecord,
	}); err != nil {
		return api.AuditArchiveDownload{}, err
	}
	return api.AuditArchiveDownload{
		SegmentID: segmentID, Format: "jws", Bundle: release.Signed, SHA256: digest,
		FirstRecord: release.FirstRecord, LastRecord: release.LastRecord, PrevHash: release.Bundle.PrevHash, ChainHead: release.Bundle.ChainHead,
	}, nil
}
