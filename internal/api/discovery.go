package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/discovery"
	"trstctl.com/trstctl/internal/discovery/compromise"
	"trstctl.com/trstctl/internal/discovery/k8stls"
	"trstctl.com/trstctl/internal/discovery/nhi"
	"trstctl.com/trstctl/internal/discovery/nhibehavior"
	"trstctl.com/trstctl/internal/discovery/oauthgrant"
	"trstctl.com/trstctl/internal/discovery/serviceaccount"
	"trstctl.com/trstctl/internal/store"
)

type discoverySourceRequest struct {
	Kind   string          `json:"kind"`
	Name   string          `json:"name"`
	Config json.RawMessage `json:"config"`
}

type discoverySourceResponse struct {
	ID        string          `json:"id"`
	TenantID  string          `json:"tenant_id"`
	Kind      string          `json:"kind"`
	Name      string          `json:"name"`
	Config    json.RawMessage `json:"config"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type discoveryScheduleRequest struct {
	SourceID        string `json:"source_id"`
	Name            string `json:"name"`
	IntervalSeconds int    `json:"interval_seconds"`
	Enabled         *bool  `json:"enabled"`
}

type discoveryScheduleResponse struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	SourceID        string    `json:"source_id"`
	Name            string    `json:"name"`
	IntervalSeconds int       `json:"interval_seconds"`
	Enabled         bool      `json:"enabled"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type discoveryRunRequest struct {
	SourceID   string `json:"source_id"`
	ScheduleID string `json:"schedule_id"`
	DryRun     bool   `json:"dry_run"`
}

type discoveryRunResponse struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	SourceID    string     `json:"source_id"`
	ScheduleID  *string    `json:"schedule_id"`
	Status      string     `json:"status"`
	DryRun      bool       `json:"dry_run"`
	RequestedBy string     `json:"requested_by"`
	Targets     int        `json:"targets"`
	Discovered  int        `json:"discovered"`
	Failed      int        `json:"failed"`
	Rejected    int        `json:"rejected"`
	Error       string     `json:"error"`
	StartedAt   *time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

type discoveryFindingResponse struct {
	ID                string          `json:"id"`
	TenantID          string          `json:"tenant_id"`
	RunID             string          `json:"run_id"`
	SourceID          string          `json:"source_id"`
	Kind              string          `json:"kind"`
	Ref               string          `json:"ref"`
	Provenance        string          `json:"provenance"`
	Fingerprint       string          `json:"fingerprint"`
	RiskScore         int             `json:"risk_score"`
	Metadata          json.RawMessage `json:"metadata"`
	DiscoveredAt      time.Time       `json:"discovered_at"`
	TriageStatus      string          `json:"triage_status"`
	ManagedIdentityID *string         `json:"managed_identity_id,omitempty"`
	TriageActor       string          `json:"triage_actor,omitempty"`
	TriageReason      string          `json:"triage_reason,omitempty"`
	TriagedAt         *time.Time      `json:"triaged_at,omitempty"`
}

type discoveryFindingTriageRequest struct {
	ManagedIdentityID string `json:"managed_identity_id,omitempty"`
	Reason            string `json:"reason,omitempty"`
}

//trstctl:mutation
func (a *API) createDiscoverySource(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req discoverySourceRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		cfg, err := validateDiscoverySourceRequest(req)
		if err != nil {
			return 0, nil, err
		}
		src, err := a.orch.UpsertDiscoverySource(ctx, tenantID, store.DiscoverySource{
			Kind: strings.TrimSpace(req.Kind), Name: strings.TrimSpace(req.Name), Config: cfg,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toDiscoverySourceResponse(src), nil
	})
}

func (a *API) listDiscoverySources(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	rows, err := a.store.ListDiscoverySourcesPage(r.Context(), tenantID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]discoverySourceResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toDiscoverySourceResponse(row))
	}
	next := ""
	if len(rows) == limit {
		next = encodeCursor(rows[len(rows)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

//trstctl:mutation
func (a *API) createDiscoverySchedule(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req discoveryScheduleRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if req.SourceID == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "source_id is required")
		}
		if strings.TrimSpace(req.Name) == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "name is required")
		}
		if req.IntervalSeconds <= 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "interval_seconds must be greater than zero")
		}
		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		sched, err := a.orch.UpsertDiscoverySchedule(ctx, tenantID, store.DiscoverySchedule{
			SourceID: req.SourceID, Name: req.Name, IntervalSeconds: req.IntervalSeconds, Enabled: enabled,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toDiscoveryScheduleResponse(sched), nil
	})
}

func (a *API) listDiscoverySchedules(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	rows, err := a.store.ListDiscoverySchedulesPage(r.Context(), tenantID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]discoveryScheduleResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toDiscoveryScheduleResponse(row))
	}
	next := ""
	if len(rows) == limit {
		next = encodeCursor(rows[len(rows)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

//trstctl:mutation
func (a *API) startDiscoveryRun(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req discoveryRunRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if req.SourceID == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "source_id is required")
		}
		var scheduleID *string
		if req.ScheduleID != "" {
			scheduleID = &req.ScheduleID
		}
		// Per-feature telemetry (COVER-009): time the served discovery-run enqueue and
		// record a non-sensitive feature/action/outcome signal (no source/tenant labels).
		start := time.Now()
		run, err := a.orch.QueueDiscoveryRun(ctx, tenantID, store.DiscoveryRun{
			SourceID: req.SourceID, ScheduleID: scheduleID, DryRun: req.DryRun,
		})
		a.observeFeature("discovery", "start_run", start, err)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toDiscoveryRunResponse(run), nil
	})
}

func (a *API) getDiscoveryRun(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	run, err := a.store.GetDiscoveryRun(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toDiscoveryRunResponse(run))
}

func (a *API) listDiscoveryRuns(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	rows, err := a.store.ListDiscoveryRunsPage(r.Context(), tenantID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]discoveryRunResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toDiscoveryRunResponse(row))
	}
	next := ""
	if len(rows) == limit {
		next = encodeCursor(rows[len(rows)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

func (a *API) listDiscoveryFindings(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	rows, err := a.store.ListDiscoveryFindingsPage(r.Context(), tenantID, r.URL.Query().Get("run_id"), after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]discoveryFindingResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, toDiscoveryFindingResponse(row))
	}
	next := ""
	if len(rows) == limit {
		next = encodeCursor(rows[len(rows)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}

//trstctl:mutation
func (a *API) claimDiscoveryFinding(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req discoveryFindingTriageRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		var managedID *string
		if strings.TrimSpace(req.ManagedIdentityID) != "" {
			id := strings.TrimSpace(req.ManagedIdentityID)
			managedID = &id
		}
		f, err := a.orch.ClaimDiscoveryFinding(ctx, tenantID, r.PathValue("id"), managedID, req.Reason)
		if err != nil {
			return 0, nil, discoveryTriageError(err)
		}
		return http.StatusOK, toDiscoveryFindingResponse(f), nil
	})
}

//trstctl:mutation
func (a *API) dismissDiscoveryFinding(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req discoveryFindingTriageRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		f, err := a.orch.DismissDiscoveryFinding(ctx, tenantID, r.PathValue("id"), req.Reason)
		if err != nil {
			return 0, nil, discoveryTriageError(err)
		}
		return http.StatusOK, toDiscoveryFindingResponse(f), nil
	})
}

func discoveryTriageError(err error) error {
	if errors.Is(err, discovery.ErrInvalidTriageTransition) {
		return errStatus(http.StatusConflict, err.Error())
	}
	if store.IsNotFound(err) {
		return errStatus(http.StatusNotFound, "discovery finding not found")
	}
	return err
}

func validateDiscoverySourceRequest(req discoverySourceRequest) (json.RawMessage, error) {
	req.Kind = strings.TrimSpace(req.Kind)
	req.Name = strings.TrimSpace(req.Name)
	if req.Kind == "" {
		return nil, errStatus(http.StatusBadRequest, "kind is required")
	}
	if req.Name == "" {
		return nil, errStatus(http.StatusBadRequest, "name is required")
	}
	switch req.Kind {
	case "network", "ssh", "cloud_certificate", "cloud_secret", "ct_log", "drift", "secret_store", "api_key", "agent", "manual", nhi.SourceKind, oauthgrant.SourceKind, serviceaccount.SourceKind, nhibehavior.SourceKind, compromise.SourceKind, k8stls.SourceKind:
	default:
		return nil, errStatus(http.StatusBadRequest, "kind must be one of network, ssh, cloud_certificate, cloud_secret, ct_log, drift, secret_store, api_key, agent, manual, nhi_cross_surface, oauth_grant, service_account, nhi_behavior, credential_compromise, k8s_ingress_gateway")
	}
	cfg := req.Config
	if len(cfg) == 0 {
		cfg = json.RawMessage(`{}`)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(cfg, &obj); err != nil || obj == nil {
		return nil, errStatus(http.StatusBadRequest, "config must be a JSON object")
	}
	if containsInlineSecret(obj) {
		return nil, errStatus(http.StatusBadRequest, "config may contain credential references, not inline secret values")
	}
	if req.Kind == nhi.SourceKind {
		if err := nhi.ValidateConfig(cfg); err != nil {
			return nil, errStatus(http.StatusBadRequest, err.Error())
		}
	}
	if req.Kind == oauthgrant.SourceKind {
		if err := oauthgrant.ValidateConfig(cfg); err != nil {
			return nil, errStatus(http.StatusBadRequest, err.Error())
		}
	}
	if req.Kind == serviceaccount.SourceKind {
		if err := serviceaccount.ValidateConfig(cfg); err != nil {
			return nil, errStatus(http.StatusBadRequest, err.Error())
		}
	}
	if req.Kind == nhibehavior.SourceKind {
		if err := nhibehavior.ValidateConfig(cfg); err != nil {
			return nil, errStatus(http.StatusBadRequest, err.Error())
		}
	}
	if req.Kind == compromise.SourceKind {
		if err := compromise.ValidateConfig(cfg); err != nil {
			return nil, errStatus(http.StatusBadRequest, err.Error())
		}
	}
	if req.Kind == k8stls.SourceKind {
		if err := k8stls.ValidateConfig(cfg); err != nil {
			return nil, errStatus(http.StatusBadRequest, err.Error())
		}
	}
	return append(json.RawMessage(nil), cfg...), nil
}

func containsInlineSecret(v any) bool {
	switch x := v.(type) {
	case map[string]json.RawMessage:
		for key, raw := range x {
			if inlineSecretKey(key) {
				return true
			}
			var nested any
			if err := json.Unmarshal(raw, &nested); err == nil && containsInlineSecret(nested) {
				return true
			}
		}
	case map[string]any:
		for key, val := range x {
			if inlineSecretKey(key) || containsInlineSecret(val) {
				return true
			}
		}
	case []any:
		for _, val := range x {
			if containsInlineSecret(val) {
				return true
			}
		}
	}
	return false
}

func inlineSecretKey(key string) bool {
	k := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	if strings.Contains(k, "ref") || strings.Contains(k, "name") || strings.Contains(k, "id") {
		return false
	}
	if strings.Contains(k, "secret") || strings.Contains(k, "password") || strings.Contains(k, "passphrase") || strings.Contains(k, "token") {
		return true
	}
	switch k {
	case "password", "passphrase", "secret", "token", "private_key", "privatekey", "credential", "value":
		return true
	default:
		return strings.HasSuffix(k, "_secret") || strings.HasSuffix(k, "_token")
	}
}

func toDiscoverySourceResponse(src store.DiscoverySource) discoverySourceResponse {
	cfg := src.Config
	if len(cfg) == 0 {
		cfg = json.RawMessage(`{}`)
	}
	return discoverySourceResponse{
		ID: src.ID, TenantID: src.TenantID, Kind: src.Kind, Name: src.Name,
		Config: cfg, CreatedAt: src.CreatedAt, UpdatedAt: src.UpdatedAt,
	}
}

func toDiscoveryScheduleResponse(s store.DiscoverySchedule) discoveryScheduleResponse {
	return discoveryScheduleResponse{
		ID: s.ID, TenantID: s.TenantID, SourceID: s.SourceID, Name: s.Name,
		IntervalSeconds: s.IntervalSeconds, Enabled: s.Enabled,
		CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
}

func toDiscoveryRunResponse(run store.DiscoveryRun) discoveryRunResponse {
	return discoveryRunResponse{
		ID: run.ID, TenantID: run.TenantID, SourceID: run.SourceID, ScheduleID: run.ScheduleID,
		Status: run.Status, DryRun: run.DryRun, RequestedBy: run.RequestedBy,
		Targets: run.Targets, Discovered: run.Discovered, Failed: run.Failed, Rejected: run.Rejected,
		Error: run.Error, StartedAt: run.StartedAt, CompletedAt: run.CompletedAt, CreatedAt: run.CreatedAt,
	}
}

func toDiscoveryFindingResponse(f store.DiscoveryFinding) discoveryFindingResponse {
	meta := f.Metadata
	if len(meta) == 0 {
		meta = json.RawMessage(`{}`)
	}
	return discoveryFindingResponse{
		ID: f.ID, TenantID: f.TenantID, RunID: f.RunID, SourceID: f.SourceID,
		Kind: f.Kind, Ref: f.Ref, Provenance: f.Provenance, Fingerprint: f.Fingerprint,
		RiskScore: f.RiskScore, Metadata: meta, DiscoveredAt: f.DiscoveredAt,
		TriageStatus: f.TriageStatus, ManagedIdentityID: f.ManagedIdentityID,
		TriageActor: f.TriageActor, TriageReason: f.TriageReason, TriagedAt: f.TriagedAt,
	}
}
