// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/switchkit"
)

// Switching kit (A265). Another certificate-management product's export —
// described by its format, never by a product — is previewed into a mapping
// report that gives every row exactly one outcome, then applied against the
// digest of what was reviewed. Applying records the import and its rows; the
// leader records the certificates and owners in bounded batches. Imported
// certificates are the other product's to renew: none becomes a renewal
// candidate here.

const (
	// switchingImportBodyLimit fits the largest export as a JSON string, whose
	// escapes can almost double it.
	switchingImportBodyLimit = 2*switchkit.MaxBytes + 1<<20
	// switchingPreviewItems bounds the rows a preview lists; the counts always
	// cover every row, and an applied import lists every row.
	switchingPreviewItems = 2000
)

func (a *API) switchingImportRoutes() []route {
	idPath := []param{pathUUID("id")}
	return []route{
		{method: "POST", path: "/api/v1/switching/imports/preview", opID: "previewSwitchingImport", summary: "Map another certificate-management product's export (CSV or JSON, with a column map) without changing state: every row's outcome, the folders, owners and application groups it carries, and the digest an import applies", handler: a.previewSwitchingImport, reqSchema: "SwitchingImportRequest", resSchema: "SwitchingImportPreview", successCode: "200", readOnly: true, perm: authz.CertsWrite},
		{method: "POST", path: "/api/v1/switching/imports", opID: "applySwitchingImport", summary: "Apply a previewed export: record the import and every row's outcome, then record its certificates (watch-only) and owners; a changed export or inventory refuses the stale digest", handler: a.applySwitchingImport, reqSchema: "SwitchingImportRequest", resSchema: "SwitchingImport", successCode: "201", mutation: true, perm: authz.CertsWrite},
		{method: "GET", path: "/api/v1/switching/imports", opID: "listSwitchingImports", summary: "List switching imports, newest first, with their counts and progress", handler: a.listSwitchingImports, query: []param{{name: "limit", typ: "integer", desc: "maximum imports (1-100, default 20)"}}, resSchema: "SwitchingImportList", successCode: "200", perm: authz.CertsRead},
		{method: "GET", path: "/api/v1/switching/imports/{id}", opID: "getSwitchingImport", summary: "Get one switching import: its counts, gaps and progress", handler: a.getSwitchingImport, pathParams: idPath, resSchema: "SwitchingImport", successCode: "200", perm: authz.CertsRead},
		{method: "POST", path: "/api/v1/switching/imports/{id}/watch", opID: "watchSwitchingImport", summary: "Start a watch round of a completed import: read what every imported certificate's endpoints serve, from the control plane under its egress rules (private ranges only through the CIDRs granted here), and flag each row matched, serves_other, unreachable or no_endpoint; the round repeats daily", handler: a.watchSwitchingImport, pathParams: idPath, reqSchema: "SwitchingWatchRequest", reqOptional: true, resSchema: "SwitchingImport", successCode: "200", mutation: true, perm: authz.CertsWrite},
		{method: "GET", path: "/api/v1/switching/imports/{id}/rows", opID: "listSwitchingImportRows", summary: "Page an import's rows in export order: each row's outcome, reason, gaps and the certificate and owner it became", handler: a.listSwitchingImportRows, pathParams: idPath, query: []param{{name: "outcome", typ: "string", desc: "only rows with this outcome (mapped, mapped_with_gaps, duplicate, unparseable, expired)"}, {name: "watch_status", typ: "string", desc: "only rows whose last watch round found this (matched, serves_other, unreachable, no_endpoint, serves_trstctl, renewed_by_other_product)"}, {name: "after", typ: "integer", desc: "rows after this row number (a CSV row's number is the line it starts on, the header being line 1; a JSON row's is its position from 1)"}, {name: "limit", typ: "integer", desc: "maximum rows (1-1000, default 200)"}}, resSchema: "SwitchingImportRowList", successCode: "200", perm: authz.CertsRead},
	}
}

type switchingImportRequest struct {
	Name          string            `json:"name"`
	Export        string            `json:"export"`
	ColumnMap     map[string]string `json:"column_map,omitempty"`
	PreviewDigest string            `json:"preview_digest,omitempty"`
}

type switchingImportPreview struct {
	Format         string                   `json:"format"`
	Rows           int                      `json:"rows"`
	Counts         map[string]int           `json:"counts"`
	GapCounts      map[string]int           `json:"gap_counts"`
	Known          int                      `json:"known"`
	Items          []switchkit.Mapped       `json:"items"`
	ItemsTruncated bool                     `json:"items_truncated"`
	Folders        []switchkit.FolderPolicy `json:"folders"`
	Owners         []switchkit.OwnerMatch   `json:"owners"`
	Applications   []string                 `json:"applications"`
	Digest         string                   `json:"digest"`
}

type switchingImportView struct {
	ID            string             `json:"id"`
	Name          string             `json:"name"`
	Format        string             `json:"format"`
	PreviewDigest string             `json:"preview_digest"`
	Status        string             `json:"status"`
	RowsTotal     int                `json:"rows_total"`
	RowsRecorded  int                `json:"rows_recorded"`
	RowsApplied   int                `json:"rows_applied"`
	Counts        map[string]int     `json:"counts"`
	GapCounts     map[string]int     `json:"gap_counts"`
	CreatedBy     string             `json:"created_by"`
	CreatedAt     time.Time          `json:"created_at"`
	CompletedAt   *time.Time         `json:"completed_at,omitempty"`
	Watch         switchingWatchView `json:"watch"`
}

// switchingWatchView is an import's endpoint watch: its round, the rows the
// round has not observed yet, the egress it was granted and what it found.
type switchingWatchView struct {
	Round                int            `json:"round"`
	Pending              int            `json:"pending"`
	AllowPrivateEndpoint bool           `json:"allow_private_endpoint"`
	PrivateEgressCIDRs   []string       `json:"private_egress_cidrs"`
	RequestedAt          *time.Time     `json:"requested_at,omitempty"`
	RequestedBy          string         `json:"requested_by,omitempty"`
	Counts               map[string]int `json:"counts"`
}

type switchingWatchRequest struct {
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs"`
}

type switchingImportRowView struct {
	Row           int        `json:"row_number"`
	Outcome       string     `json:"outcome"`
	Gaps          []string   `json:"gaps"`
	Reason        string     `json:"reason,omitempty"`
	DuplicateOf   *int       `json:"duplicate_of,omitempty"`
	Fingerprint   string     `json:"fingerprint_sha256,omitempty"`
	CommonName    string     `json:"common_name,omitempty"`
	SANs          []string   `json:"sans"`
	KeyAlgorithm  string     `json:"key_algorithm,omitempty"`
	Serial        string     `json:"serial,omitempty"`
	Issuer        string     `json:"issuer,omitempty"`
	NotAfter      *time.Time `json:"not_after,omitempty"`
	Folder        string     `json:"folder,omitempty"`
	Profile       string     `json:"profile,omitempty"`
	Application   string     `json:"application,omitempty"`
	OwnerEmail    string     `json:"owner_email,omitempty"`
	Endpoints     []string   `json:"endpoints"`
	HasPEM        bool       `json:"has_pem"`
	CertificateID string     `json:"certificate_id,omitempty"`
	OwnerID       string     `json:"owner_id,omitempty"`
	Linked        bool       `json:"linked"`
	AppliedAt     *time.Time `json:"applied_at,omitempty"`
	WatchStatus   string     `json:"watch_status,omitempty"`
	WatchEndpoint string     `json:"watch_endpoint,omitempty"`
	ServedFP      string     `json:"served_fingerprint_sha256,omitempty"`
	WatchDetail   string     `json:"watch_detail,omitempty"`
	WatchedAt     *time.Time `json:"watched_at,omitempty"`
}

func switchingImportResponse(imp store.SwitchingImport, watchCounts map[string]int) switchingImportView {
	cidrs := imp.WatchPrivateCIDRs
	if cidrs == nil {
		cidrs = []string{}
	}
	if watchCounts == nil {
		watchCounts = map[string]int{}
	}
	return switchingImportView{ID: imp.ID, Name: imp.Name, Format: imp.Format, PreviewDigest: imp.PreviewDigest, Status: imp.Status,
		RowsTotal: imp.RowsTotal, RowsRecorded: imp.RowsRecorded, RowsApplied: imp.RowsApplied, Counts: imp.Counts,
		GapCounts: imp.GapCounts, CreatedBy: imp.CreatedBy, CreatedAt: imp.CreatedAt, CompletedAt: imp.CompletedAt,
		Watch: switchingWatchView{Round: imp.WatchRound, Pending: imp.WatchPending, AllowPrivateEndpoint: imp.WatchAllowPrivate,
			PrivateEgressCIDRs: cidrs, RequestedAt: imp.WatchRequestedAt, RequestedBy: imp.WatchRequestedBy, Counts: watchCounts}}
}

// switchingImportDetail is one import with its watch counts.
func (a *API) switchingImportDetail(ctx context.Context, tenantID, id string) (switchingImportView, error) {
	imp, err := a.store.GetSwitchingImport(ctx, tenantID, id)
	if err != nil {
		return switchingImportView{}, switchingImportNotFound(err)
	}
	counts, err := a.store.SwitchingWatchCounts(ctx, tenantID, id)
	if err != nil {
		return switchingImportView{}, err
	}
	return switchingImportResponse(imp, counts), nil
}

// switchingReport parses and maps an export against the tenant's owners and
// inventory as they are now.
func (a *API) switchingReport(ctx context.Context, tenantID string, req switchingImportRequest) (switchkit.Report, error) {
	if strings.TrimSpace(req.Export) == "" {
		return switchkit.Report{}, errStatus(http.StatusBadRequest, "export is required: the CSV or JSON text of the export")
	}
	if len(req.Export) > switchkit.MaxBytes {
		return switchkit.Report{}, errStatus(http.StatusRequestEntityTooLarge,
			fmt.Sprintf("an export is at most %d bytes; split it and import each part", switchkit.MaxBytes))
	}
	rows, err := switchkit.Parse([]byte(req.Export), req.ColumnMap)
	if err != nil {
		return switchkit.Report{}, errWithStatus(http.StatusBadRequest, err)
	}
	owners, err := a.store.ListOwners(ctx, tenantID)
	if err != nil {
		return switchkit.Report{}, err
	}
	existing := switchkit.ExistingOwners{}
	for _, owner := range owners {
		if owner.Email != "" {
			existing[switchkit.OwnerKey(owner.Email, owner.ApplicationID)] = owner.ID
		}
	}
	report := switchkit.Map(rows, existing, time.Now().UTC())
	fingerprints := make([]string, 0, len(report.Items))
	for _, m := range report.Items {
		if m.Outcome == switchkit.OutcomeMapped || m.Outcome == switchkit.OutcomeMappedWithGaps {
			fingerprints = append(fingerprints, m.Fingerprint)
		}
	}
	inventory, err := a.store.CertificatesByFingerprint(ctx, tenantID, fingerprints)
	if err != nil {
		return switchkit.Report{}, err
	}
	known := make(map[string]string, len(inventory))
	for fp, c := range inventory {
		known[fp] = c.ID
	}
	report.MarkKnown(known)
	return report, nil
}

func (a *API) previewSwitchingImport(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	var req switchingImportRequest
	if err := decodeJSONWithLimit(r, &req, switchingImportBodyLimit); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	report, err := a.switchingReport(r.Context(), tenantID, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	view := switchingImportPreview{Format: report.Format, Rows: report.Rows, Counts: report.Counts, GapCounts: report.GapCounts,
		Known: report.Known, Items: []switchkit.Mapped{}, Folders: report.Folders, Owners: report.Owners,
		Applications: report.Applications, Digest: report.Digest}
	if view.Folders == nil {
		view.Folders = []switchkit.FolderPolicy{}
	}
	if view.Owners == nil {
		view.Owners = []switchkit.OwnerMatch{}
	}
	if view.Applications == nil {
		view.Applications = []string{}
	}
	// The rows worth reading before applying: every row not plainly mapped,
	// and every row already in the inventory.
	for _, m := range report.Items {
		if m.Outcome == switchkit.OutcomeMapped && m.KnownCertificateID == "" {
			continue
		}
		if len(view.Items) == switchingPreviewItems {
			view.ItemsTruncated = true
			break
		}
		view.Items = append(view.Items, m)
	}
	a.writeJSON(w, http.StatusOK, view)
}

//trstctl:mutation
func (a *API) applySwitchingImport(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Idempotency-Key")
	a.mutateWithBodyLimit(w, r, key, switchingImportBodyLimit, func(ctx context.Context, tenantID string) (int, any, error) {
		var req switchingImportRequest
		if err := decodeJSONWithLimit(r, &req, switchingImportBodyLimit); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" || len(req.Name) > 200 {
			return 0, nil, errStatus(http.StatusBadRequest, "name is required (at most 200 characters)")
		}
		if req.PreviewDigest == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "preview_digest is required: preview the export, review it, then apply that digest")
		}
		report, err := a.switchingReport(ctx, tenantID, req)
		if err != nil {
			return 0, nil, err
		}
		if report.Digest != req.PreviewDigest {
			return 0, nil, errStatus(http.StatusConflict,
				"the export, its column map, the owners or the inventory changed since the preview; preview again and apply the new digest")
		}
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		id := orchestrator.SwitchingImportID(tenantID, key+"\x00"+report.Digest)
		rows := make([]store.SwitchingImportRow, 0, len(report.Items))
		for _, m := range report.Items {
			row := store.SwitchingImportRow{Row: m.Row, Outcome: m.Outcome, Gaps: m.Gaps, Reason: m.Reason, Fingerprint: m.Fingerprint,
				CommonName: m.CommonName, SANs: m.SANs, KeyAlgorithm: m.KeyAlgorithm, Serial: m.Serial, Issuer: m.Issuer,
				Folder: m.Folder, Application: m.Application, OwnerEmail: m.OwnerEmail, Endpoints: m.Endpoints, CertificateDER: m.DER}
			if m.SANs == nil {
				row.SANs = []string{}
			}
			if m.Gaps == nil {
				row.Gaps = []string{}
			}
			if m.Endpoints == nil {
				row.Endpoints = []string{}
			}
			if m.DuplicateOf != 0 {
				first := m.DuplicateOf
				row.DuplicateOf = &first
			}
			if !m.NotAfter.IsZero() {
				notAfter := m.NotAfter
				row.NotAfter = &notAfter
			}
			if m.Folder != "" {
				row.Profile = switchkit.ProfileName(m.Folder)
			}
			rows = append(rows, row)
		}
		if err := a.orch.StartSwitchingImport(ctx, tenantID, projections.SwitchingImportStarted{
			ID: id, Name: req.Name, Format: report.Format, PreviewDigest: report.Digest, RowsTotal: report.Rows,
			Counts: report.Counts, GapCounts: report.GapCounts, CreatedBy: subject,
		}, rows); err != nil {
			return 0, nil, err
		}
		view, err := a.switchingImportDetail(ctx, tenantID, id)
		return http.StatusCreated, view, err
	})
}

//trstctl:mutation
func (a *API) watchSwitchingImport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var req switchingWatchRequest
		if r.ContentLength != 0 {
			if err := decodeJSON(r, &req); err != nil {
				return 0, nil, errWithStatus(http.StatusBadRequest, err)
			}
		}
		req.PrivateEgressCIDRs = cleanAPIStringList(req.PrivateEgressCIDRs)
		if req.AllowPrivateEndpoint {
			if len(req.PrivateEgressCIDRs) == 0 {
				return 0, nil, errStatus(http.StatusBadRequest, "allow_private_endpoint needs private_egress_cidrs: the private ranges the watch may reach")
			}
			if err := validatePrivateEgressCIDRs(req.PrivateEgressCIDRs); err != nil {
				return 0, nil, errWithStatus(http.StatusBadRequest, err)
			}
		} else if len(req.PrivateEgressCIDRs) > 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "private_egress_cidrs apply only with allow_private_endpoint")
		}
		imp, err := a.store.GetSwitchingImport(ctx, tenantID, id)
		if err != nil {
			return 0, nil, switchingImportNotFound(err)
		}
		if imp.Status != "completed" {
			return 0, nil, errStatus(http.StatusConflict, "the import is still being applied; watch it once it completes")
		}
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		if err := a.orch.RequestSwitchingWatch(ctx, tenantID, projections.SwitchingWatchRequested{ImportID: id, Round: imp.WatchRound + 1,
			AllowPrivateEndpoint: req.AllowPrivateEndpoint, PrivateEgressCIDRs: req.PrivateEgressCIDRs, RequestedBy: subject}); err != nil {
			return 0, nil, err
		}
		view, err := a.switchingImportDetail(ctx, tenantID, id)
		return http.StatusOK, view, err
	})
}

// switchingQueryInt reads an optional integer query parameter within [lo, hi].
func switchingQueryInt(r *http.Request, name string, def, lo, hi int) (int, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < lo || n > hi {
		return 0, errStatus(http.StatusBadRequest, fmt.Sprintf("%s must be an integer between %d and %d", name, lo, hi))
	}
	return n, nil
}

func switchingImportNotFound(err error) error {
	if errors.Is(err, store.ErrSwitchingImportNotFound) {
		return errStatus(http.StatusNotFound, "switching import not found")
	}
	return err
}

func (a *API) listSwitchingImports(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, err := switchingQueryInt(r, "limit", 20, 1, 100)
	if err != nil {
		a.writeError(w, err)
		return
	}
	imports, err := a.store.ListSwitchingImports(r.Context(), tenantID, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]switchingImportView, 0, len(imports))
	for _, imp := range imports {
		counts, err := a.store.SwitchingWatchCounts(r.Context(), tenantID, imp.ID)
		if err != nil {
			a.writeError(w, err)
			return
		}
		items = append(items, switchingImportResponse(imp, counts))
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *API) getSwitchingImport(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	view, err := a.switchingImportDetail(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, view)
}

var switchingOutcomes = map[string]bool{switchkit.OutcomeMapped: true, switchkit.OutcomeMappedWithGaps: true,
	switchkit.OutcomeDuplicate: true, switchkit.OutcomeUnparseable: true, switchkit.OutcomeExpired: true}

var switchingWatchStatuses = map[string]bool{store.SwitchingWatchMatched: true, store.SwitchingWatchServesOther: true,
	store.SwitchingWatchUnreachable: true, store.SwitchingWatchNoEndpoint: true, store.SwitchingWatchServesTrstctl: true,
	store.SwitchingWatchRenewedByOtherProduct: true}

func (a *API) listSwitchingImportRows(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	id := r.PathValue("id")
	if _, err := a.store.GetSwitchingImport(r.Context(), tenantID, id); err != nil {
		a.writeError(w, switchingImportNotFound(err))
		return
	}
	outcome := r.URL.Query().Get("outcome")
	if outcome != "" && !switchingOutcomes[outcome] {
		a.writeError(w, errStatus(http.StatusBadRequest, "outcome must be one of mapped, mapped_with_gaps, duplicate, unparseable, expired"))
		return
	}
	watchStatus := r.URL.Query().Get("watch_status")
	if watchStatus != "" && !switchingWatchStatuses[watchStatus] {
		a.writeError(w, errStatus(http.StatusBadRequest,
			"watch_status must be one of matched, serves_other, unreachable, no_endpoint, serves_trstctl, renewed_by_other_product"))
		return
	}
	after, err := switchingQueryInt(r, "after", 0, 0, math.MaxInt32)
	if err != nil {
		a.writeError(w, err)
		return
	}
	limit, err := switchingQueryInt(r, "limit", 200, 1, 1000)
	if err != nil {
		a.writeError(w, err)
		return
	}
	rows, err := a.store.ListSwitchingImportRows(r.Context(), tenantID, id, outcome, watchStatus, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]switchingImportRowView, 0, len(rows))
	for _, row := range rows {
		gaps := row.Gaps
		if gaps == nil {
			gaps = []string{}
		}
		endpoints, sans := row.Endpoints, row.SANs
		if endpoints == nil {
			endpoints = []string{}
		}
		if sans == nil {
			sans = []string{}
		}
		items = append(items, switchingImportRowView{Row: row.Row, Outcome: row.Outcome, Gaps: gaps, Reason: row.Reason,
			DuplicateOf: row.DuplicateOf, Fingerprint: row.Fingerprint, CommonName: row.CommonName, SANs: sans,
			KeyAlgorithm: row.KeyAlgorithm, Serial: row.Serial, Issuer: row.Issuer, NotAfter: row.NotAfter, Folder: row.Folder,
			Profile: row.Profile, Application: row.Application, OwnerEmail: row.OwnerEmail, Endpoints: endpoints,
			HasPEM: len(row.CertificateDER) > 0, CertificateID: row.CertificateID, OwnerID: row.OwnerID,
			Linked: row.Linked, AppliedAt: row.AppliedAt, WatchStatus: row.WatchStatus, WatchEndpoint: row.WatchEndpoint,
			ServedFP: row.ServedFingerprint, WatchDetail: row.WatchDetail, WatchedAt: row.WatchedAt})
	}
	next := ""
	if len(rows) == limit {
		next = strconv.Itoa(rows[len(rows)-1].Row)
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_after": next})
}

func switchingImportSchemas() map[string]*Schema {
	str := func() *Schema { return &Schema{Type: "string"} }
	integer := func() *Schema { return &Schema{Type: "integer"} }
	boolean := func() *Schema { return &Schema{Type: "boolean"} }
	ts := func() *Schema { return &Schema{Type: "string", Format: "date-time"} }
	list := func(item *Schema) *Schema { return &Schema{Type: "array", Items: item} }
	object := func(props map[string]*Schema, required ...string) *Schema {
		return &Schema{Type: "object", Properties: props, Required: required}
	}
	counts := &Schema{Type: "object", AdditionalProperties: integer()}
	outcome := &Schema{Type: "string", Enum: []string{"mapped", "mapped_with_gaps", "duplicate", "unparseable", "expired"}}
	mapped := object(map[string]*Schema{"row": integer(), "outcome": outcome, "gaps": list(str()), "reason": str(),
		"duplicate_of": integer(), "fingerprint_sha256": str(), "common_name": str(), "sans": list(str()), "serial": str(),
		"issuer": str(), "not_after": ts(), "key_algorithm": str(), "folder": str(), "application": str(), "owner_email": str(),
		"owner_name": str(), "owner_id": str(), "endpoints": list(str()), "renewal_window_days": integer(), "has_pem": boolean(),
		"known_certificate_id": str()}, "row", "outcome", "has_pem")
	folder := object(map[string]*Schema{"folder": str(), "profile": str(), "rows": integer(), "renewal_window_days": integer(),
		"key_algorithm": str(), "conflicts": list(str())}, "folder", "profile", "rows")
	owner := object(map[string]*Schema{"email": str(), "name": str(), "application": str(), "owner_id": str(), "create": boolean(),
		"rows": integer()}, "email", "create", "rows")
	watchStatus := &Schema{Type: "string", Enum: []string{"matched", "serves_other", "unreachable", "no_endpoint", "serves_trstctl",
		"renewed_by_other_product"}}
	watch := object(map[string]*Schema{"round": integer(), "pending": integer(), "allow_private_endpoint": boolean(),
		"private_egress_cidrs": list(str()), "requested_at": ts(), "requested_by": str(), "counts": counts},
		"round", "pending", "allow_private_endpoint", "private_egress_cidrs", "counts")
	imp := object(map[string]*Schema{"id": str(), "name": str(), "format": str(), "preview_digest": str(),
		"status": {Type: "string", Enum: []string{"recording", "completed"}}, "rows_total": integer(), "rows_recorded": integer(),
		"rows_applied": integer(), "counts": counts, "gap_counts": counts, "created_by": str(), "created_at": ts(), "completed_at": ts(),
		"watch": watch},
		"id", "name", "format", "preview_digest", "status", "rows_total", "rows_recorded", "rows_applied", "counts", "gap_counts",
		"created_by", "created_at", "watch")
	row := object(map[string]*Schema{"row_number": integer(), "outcome": outcome, "gaps": list(str()), "reason": str(),
		"duplicate_of": integer(), "fingerprint_sha256": str(), "common_name": str(), "serial": str(), "issuer": str(),
		"not_after": ts(), "folder": str(), "profile": str(), "application": str(), "owner_email": str(), "endpoints": list(str()),
		"sans": list(str()), "key_algorithm": str(), "has_pem": boolean(), "certificate_id": str(), "owner_id": str(),
		"linked": boolean(), "applied_at": ts(), "watch_status": watchStatus, "watch_endpoint": str(),
		"served_fingerprint_sha256": str(), "watch_detail": str(), "watched_at": ts()},
		"row_number", "outcome", "gaps", "sans", "endpoints", "has_pem", "linked")
	return map[string]*Schema{
		"SwitchingImportRequest": object(map[string]*Schema{"name": str(), "export": str(),
			"column_map": {Type: "object", AdditionalProperties: str()}, "preview_digest": str()}, "export"),
		"SwitchingImportPreview": object(map[string]*Schema{"format": str(), "rows": integer(), "counts": counts, "gap_counts": counts,
			"known": integer(), "items": list(mapped), "items_truncated": boolean(), "folders": list(folder), "owners": list(owner),
			"applications": list(str()), "digest": str()},
			"format", "rows", "counts", "gap_counts", "known", "items", "items_truncated", "folders", "owners", "applications", "digest"),
		"SwitchingImport": imp,
		"SwitchingWatchRequest": object(map[string]*Schema{"allow_private_endpoint": boolean(),
			"private_egress_cidrs": list(str())}),
		"SwitchingImportList":    object(map[string]*Schema{"items": list(imp)}, "items"),
		"SwitchingImportRowList": object(map[string]*Schema{"items": list(row), "next_after": str()}, "items", "next_after"),
	}
}
