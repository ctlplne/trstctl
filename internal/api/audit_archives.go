// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
)

// A234: a tenant downloads its own signed audit archive segments. The route is
// separately permissioned (audit:archive.read), rate limited per tenant and
// audited: every released segment leaves an audit.archive.downloaded event
// appended BEFORE the bytes leave. A segment is addressed only by its opaque
// ID (the audit.archived event that recorded it); its storage locator never
// enters a request or a response. The bytes returned are exactly the signed
// retention segment, which verifies offline with the published audit keys.
// Deployment-wide archives stay custodian-only.

const (
	auditArchiveDownloadBucket   = "audit-archive-download"
	auditArchiveDownloadCapacity = 6.0
	auditArchiveDownloadRefill   = 6.0 / 60.0 // tokens per second: six a minute
)

var (
	// ErrAuditArchiveNotFound is a segment ID that is not one of the caller
	// tenant's archived segments (404, never revealing another tenant's).
	ErrAuditArchiveNotFound = errors.New("audit archive segment not found")
	// ErrAuditArchiveUnavailable is a segment whose stored bytes cannot be
	// served from the configured archive: moved, missing, legacy or not a
	// single-tenant segment of this tenant (409; a custodian fetches it).
	ErrAuditArchiveUnavailable = errors.New("audit archive segment is not available for tenant download")
)

// AuditArchiveSegment describes one archived segment without its locator.
// FirstRecord is 0 for a segment that directly follows a legacy segment, whose
// start the log does not carry; the downloaded bundle names it.
type AuditArchiveSegment struct {
	ID               string    `json:"id"`
	FirstRecord      int       `json:"first_record"`
	LastRecord       int       `json:"last_record"`
	BoundarySequence uint64    `json:"boundary_sequence"`
	ChainHead        string    `json:"chain_head"`
	ArchivedAt       time.Time `json:"archived_at"`
}

// AuditArchiveSegmentList is the tenant's archived segments, oldest first.
type AuditArchiveSegmentList struct {
	Items []AuditArchiveSegment `json:"items"`
}

// AuditArchiveDownload is one released segment.
type AuditArchiveDownload struct {
	SegmentID   string `json:"segment_id"`
	Format      string `json:"format"`
	Bundle      string `json:"bundle"`
	SHA256      string `json:"sha256"`
	FirstRecord int    `json:"first_record"`
	LastRecord  int    `json:"last_record"`
	PrevHash    string `json:"prev_hash"`
	ChainHead   string `json:"chain_head"`
}

// AuditArchiveService lists and releases a tenant's archived segments. The
// server implements it over the event log, the configured archive storage,
// the audit verification keys and the orchestrator's audit append.
type AuditArchiveService interface {
	ListSegments(ctx context.Context, tenantID string) ([]AuditArchiveSegment, error)
	Download(ctx context.Context, tenantID, segmentID string) (AuditArchiveDownload, error)
}

// WithAuditArchives serves the tenant archive download routes.
func WithAuditArchives(svc AuditArchiveService) Option {
	return func(c *config) { c.auditArchives = svc }
}

func (a *API) listAuditArchives(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.auditArchives == nil {
		a.writeProblem(w, problem.New(http.StatusNotFound, "audit archive download is not served by this deployment"))
		return
	}
	items, err := a.auditArchives.ListSegments(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if items == nil {
		items = []AuditArchiveSegment{}
	}
	a.writeJSON(w, http.StatusOK, AuditArchiveSegmentList{Items: items})
}

func (a *API) downloadAuditArchive(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.auditArchives == nil {
		a.writeProblem(w, problem.New(http.StatusNotFound, "audit archive download is not served by this deployment"))
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if !validAuditArchiveSegmentID(id) {
		a.writeError(w, errWithStatus(http.StatusNotFound, ErrAuditArchiveNotFound))
		return
	}
	if a.store != nil {
		allowed, retryAfter, err := a.store.RateLimitTake(r.Context(), tenantID, auditArchiveDownloadBucket, auditArchiveDownloadCapacity, auditArchiveDownloadRefill)
		if err != nil {
			a.writeError(w, err)
			return
		}
		if !allowed {
			seconds := int(retryAfter.Seconds()) + 1
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			a.writeProblem(w, problem.New(http.StatusTooManyRequests, "audit archive downloads are limited per tenant; retry after the Retry-After interval"))
			return
		}
	}
	download, err := a.auditArchives.Download(r.Context(), tenantID, id)
	switch {
	case errors.Is(err, ErrAuditArchiveNotFound):
		a.writeError(w, errWithStatus(http.StatusNotFound, err))
		return
	case errors.Is(err, ErrAuditArchiveUnavailable):
		a.writeError(w, errWithStatus(http.StatusConflict, err))
		return
	case err != nil:
		a.writeError(w, err)
		return
	}
	if r.URL.Query().Get("format") == "jws" {
		// The exact signed segment, ready for `trstctl audit verify --format retention-jws`.
		w.Header().Set("Content-Type", "application/jose")
		w.Header().Set("X-Trstctl-Segment-SHA256", download.SHA256)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(download.Bundle))
		return
	}
	a.writeJSON(w, http.StatusOK, download)
}

// validAuditArchiveSegmentID accepts only the retention worker's event ID
// shape, so no path, URL or object name can reach a lookup.
func validAuditArchiveSegmentID(id string) bool {
	const prefix = "audit-archive-"
	if !strings.HasPrefix(id, prefix) || len(id) != len(prefix)+64 {
		return false
	}
	for _, c := range id[len(prefix):] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
