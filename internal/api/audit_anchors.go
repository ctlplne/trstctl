// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// AuditAnchoringRuntime is the continuous anchoring worker's state as the
// server sees it: "anchoring", "failing", "off" or "unlicensed".
type AuditAnchoringRuntime struct {
	State     string
	Detail    string
	Cadence   time.Duration
	LastRunAt time.Time
}

// AuditAnchorReader reads a tenant's projected anchor series.
type AuditAnchorReader interface {
	ListAuditAnchors(ctx context.Context, tenantID string, limit int) ([]store.AuditAnchor, error)
	CountAuditAnchors(ctx context.Context, tenantID string) (int64, error)
}

// WithAuditAnchoring serves the continuous audit anchoring status (A147).
func WithAuditAnchoring(runtime func() AuditAnchoringRuntime, reader AuditAnchorReader) Option {
	return func(c *config) { c.auditAnchoringRuntime, c.auditAnchorReader = runtime, reader }
}

// AuditChainAnchor is one timestamp over the tenant's full audit chain.
type AuditChainAnchor struct {
	ThroughSequence uint64    `json:"through_sequence"`
	ChainHead       string    `json:"chain_head"`
	AnchoredAt      time.Time `json:"anchored_at"`
	TokenSerial     uint64    `json:"token_serial"`
	TokenSHA256     string    `json:"token_sha256"`
}

// AuditAnchoringStatus reports continuous anchoring for the caller's tenant.
type AuditAnchoringStatus struct {
	State          string             `json:"state"`
	Detail         string             `json:"detail,omitempty"`
	CadenceSeconds int64              `json:"cadence_seconds"`
	LastRunAt      *time.Time         `json:"last_run_at,omitempty"`
	AnchorCount    int64              `json:"anchor_count"`
	LastAnchoredAt *time.Time         `json:"last_anchored_at,omitempty"`
	Anchors        []AuditChainAnchor `json:"anchors"`
	Verification   string             `json:"verification"`
}

const auditAnchorVerification = "Each anchor is an audit.anchored record in this tenant's audit log. Export an unbroken run of records " +
	"(no content filter) and verify it offline with `trstctl audit verify --tsa-root <root> --anchor-cadence <cadence>`: " +
	"every anchor's head must be reproduced by the export's chain, no record may enter the chain after an anchor it predates, " +
	"and every record must be covered by an anchor within the cadence."

func auditAnchorParams() []param {
	return []param{{name: "limit", typ: "integer", desc: "most recent anchors to return (default 50, maximum 500)"}}
}

func (a *API) getAuditAnchoring(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 500 {
			a.writeError(w, errStatus(http.StatusBadRequest, "limit must be between 1 and 500"))
			return
		}
		limit = n
	}
	runtime := AuditAnchoringRuntime{State: "unlicensed", Detail: "Continuous audit anchoring is part of Enterprise audit compliance."}
	if a.auditAnchoringRuntime != nil {
		runtime = a.auditAnchoringRuntime()
	}
	status := AuditAnchoringStatus{
		State: runtime.State, Detail: runtime.Detail, CadenceSeconds: int64(runtime.Cadence / time.Second),
		Anchors: []AuditChainAnchor{}, Verification: auditAnchorVerification,
	}
	if !runtime.LastRunAt.IsZero() {
		at := runtime.LastRunAt.UTC()
		status.LastRunAt = &at
	}
	if a.auditAnchorReader != nil {
		count, err := a.auditAnchorReader.CountAuditAnchors(r.Context(), tenantID)
		if err != nil {
			a.writeError(w, err)
			return
		}
		anchors, err := a.auditAnchorReader.ListAuditAnchors(r.Context(), tenantID, limit)
		if err != nil {
			a.writeError(w, err)
			return
		}
		status.AnchorCount = count
		for _, anchor := range anchors {
			status.Anchors = append(status.Anchors, AuditChainAnchor{
				ThroughSequence: anchor.ThroughSequence, ChainHead: anchor.ChainHead, AnchoredAt: anchor.AnchoredAt.UTC(),
				TokenSerial: anchor.TokenSerial, TokenSHA256: anchor.TokenSHA256,
			})
		}
		if len(status.Anchors) > 0 {
			at := status.Anchors[0].AnchoredAt
			status.LastAnchoredAt = &at
		}
	}
	a.writeJSON(w, http.StatusOK, status)
}
