// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/auditchain"
)

func (a *API) auditVerificationKeys(w http.ResponseWriter, r *http.Request) {
	if a.audit == nil {
		a.writeProblem(w, problem.New(http.StatusInternalServerError, "audit log is not configured"))
		return
	}
	raw, err := a.audit.PublicVerificationJWKS()
	if err != nil {
		a.writeError(w, err)
		return
	}
	// RawMessage preserves the standard JWK Set wire shape. Wrapping it would
	// make stock JOSE tools and the offline CLI reject an otherwise valid set.
	a.writeJSON(w, http.StatusOK, json.RawMessage(raw))
}

// auditQueryParams describes the audit query string for the OpenAPI document.
//
// It lives beside the audit handlers rather than in the route table, because it
// describes THIS workflow's inputs and the handlers are what have to honour
// them. Keeping the two together is also what stops the served surface file
// growing without bound as workflows are added — the served-file budget is a
// guard against exactly that.
func auditQueryParams() []param {
	return []param{
		{name: "tool", typ: "string", desc: "canonical tool: discover, certificates, workloads_machines, secrets, software_trust, operations, or platform_integrations; intersects other filters before the result limit"},
		{name: "type", typ: "string", desc: "comma-separated event types to include"},
		{name: "feature_id", typ: "string", desc: "catalog feature id (e.g. F6); returns only events the feature's mutating actions emit"},
		{name: "action", typ: "string", desc: "catalog action (e.g. revoke); returns only events that action emits, optionally scoped by feature_id"},
		{name: "since", typ: "string", desc: "RFC3339 inclusive lower time bound"},
		{name: "until", typ: "string", desc: "RFC3339 inclusive upper time bound"},
		{name: "as_of", typ: "integer", desc: "point-in-time: only tenant-local audit events with sequence <= this"},
		{name: "q", typ: "string", desc: "case-insensitive substring match on event type, privacy-filtered actor subject or role, or event data"},
		{name: "limit", typ: "integer", desc: "maximum records to return"},
		{name: "format", typ: "string", desc: "export encoding: jws (default, signed bundle), ndjson, csv, splunk-hec, sentinel"},
	}
}

// auditQueryFromRequest builds an audit query from the request's tenant
// (authoritative, from the principal) and its query parameters.
func (a *API) auditQueryFromRequest(r *http.Request, tenantID string) (audit.Query, error) {
	q := audit.Query{
		TenantID:  tenantID,
		Tool:      strings.TrimSpace(r.URL.Query().Get("tool")),
		Contains:  r.URL.Query().Get("q"),
		FeatureID: strings.TrimSpace(r.URL.Query().Get("feature_id")),
		Action:    strings.TrimSpace(r.URL.Query().Get("action")),
	}
	if err := audit.ValidateTool(q.Tool); err != nil {
		if errors.Is(err, audit.ErrUnknownTool) {
			return audit.Query{}, errStatus(http.StatusBadRequest, err.Error())
		}
		return audit.Query{}, err
	}
	if t := r.URL.Query().Get("type"); t != "" {
		for _, name := range strings.Split(t, ",") {
			if name = strings.TrimSpace(name); name != "" {
				q.Types = append(q.Types, name)
			}
		}
	}
	if s := r.URL.Query().Get("since"); s != "" {
		ts, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return audit.Query{}, errStatus(http.StatusBadRequest, "since must be RFC3339")
		}
		q.Since = ts
	}
	if s := r.URL.Query().Get("until"); s != "" {
		ts, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return audit.Query{}, errStatus(http.StatusBadRequest, "until must be RFC3339")
		}
		q.Until = ts
	}
	if s := r.URL.Query().Get("as_of"); s != "" {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return audit.Query{}, errStatus(http.StatusBadRequest, "as_of must be a sequence number")
		}
		q.AsOfSequence = n
	}
	if s := r.URL.Query().Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			return audit.Query{}, errStatus(http.StatusBadRequest, "limit must be a positive integer")
		}
		q.Limit = n
	}
	return q, nil
}

func (a *API) searchAudit(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.audit == nil {
		a.writeProblem(w, problem.New(http.StatusInternalServerError, "audit log is not configured"))
		return
	}
	q, err := a.auditQueryFromRequest(r, tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	records, err := a.audit.Search(r.Context(), q)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"events": records, "count": len(records)})
}

func (a *API) exportAudit(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.audit == nil {
		a.writeProblem(w, problem.New(http.StatusInternalServerError, "audit log is not configured"))
		return
	}
	q, err := a.auditQueryFromRequest(r, tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	format, err := auditanchor.ParseFormat(r.URL.Query().Get("format"))
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}

	if format == auditanchor.FormatJWS {
		signed, bundle, err := a.audit.ExportWithBundle(r.Context(), q)
		if err != nil {
			a.writeError(w, err)
			return
		}
		anchor, anchorErr := auditanchor.AnchorHead(r.Context(), a.auditTimestamper, bundle.ChainHead)
		if anchorErr != nil && anchor.Detail == "" {
			anchor.Detail = "this export could not be externally anchored"
		}
		a.writeJSON(w, http.StatusOK, auditanchor.EvidenceEnvelope{
			SchemaVersion: auditanchor.EvidenceEnvelopeSchemaVersion,
			Format:        format, Bundle: signed, ChainHead: bundle.ChainHead, Anchor: anchor,
		})
		return
	}

	// Record streams are read once. The chain head and anchor are computed from
	// those exact rows, so the final in-file trailer cannot attest a neighboring
	// generation observed by a second query.
	recs, prevHash, err := a.audit.SearchWithSeed(r.Context(), q)
	if err != nil {
		a.writeError(w, err)
		return
	}
	// The archived prefix is part of the proof. Re-sealing from genesis here
	// would emit a trailer naming one seed and rows hashed from another.
	head := auditchain.SealFrom(prevHash, recs)
	// Best effort, and honest about it: an export from a deployment with no TSA
	// is unanchored, says so in its own payload, and is still worth having.
	// Failing the export instead would leave an operator with nothing.
	anchor, anchorErr := auditanchor.AnchorHead(r.Context(), a.auditTimestamper, head)
	if anchorErr != nil && anchor.Detail == "" {
		anchor.Detail = "this export could not be externally anchored"
	}

	w.Header().Set("Content-Type", format.ContentType())
	w.Header().Set("X-Trstctl-Audit-Chain-Head", head)
	w.Header().Set("X-Trstctl-Audit-Anchor", string(anchor.Kind))
	w.WriteHeader(http.StatusOK)
	// A write failure here cannot become a problem response — the status line
	// and headers are already sent. It does not need to: the trailer IS the
	// completeness signal. Every JSON stream format ends with a chain_trailer
	// line, so a consumer that reaches EOF without one knows its download was
	// truncated, and knows it from the file itself rather than from a status
	// code it no longer has access to.
	_ = auditanchor.WriteRecords(w, format, recs, prevHash, head, anchor)
}
