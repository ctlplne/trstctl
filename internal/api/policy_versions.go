package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	guuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/policy"
)

const (
	policyVersionAuthoredEventType   = "policy.version.authored"
	policyVersionActivatedEventType  = "policy.version.activated"
	policyVersionRolledBackEventType = "policy.version.rolled_back"
	policyVersionBootID              = "boot-lifecycle"
)

type policyVersionCreateRequest struct {
	ID           string   `json:"id,omitempty"`
	Kind         string   `json:"kind,omitempty"`
	Module       string   `json:"module"`
	Description  string   `json:"description,omitempty"`
	ChangeRef    string   `json:"change_ref,omitempty"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}

type policyVersionActionRequest struct {
	Reason       string   `json:"reason"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}

type policyVersionAuthoredEvent struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	Module       string   `json:"module"`
	ModuleSHA256 string   `json:"module_sha256"`
	Package      string   `json:"package"`
	Query        string   `json:"query"`
	Description  string   `json:"description,omitempty"`
	ChangeRef    string   `json:"change_ref,omitempty"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
	Author       string   `json:"author,omitempty"`
}

type policyVersionActivatedEvent struct {
	ID                   string   `json:"id"`
	Kind                 string   `json:"kind"`
	Reason               string   `json:"reason"`
	EvidenceRefs         []string `json:"evidence_refs,omitempty"`
	ActivatedBy          string   `json:"activated_by,omitempty"`
	PreviousID           string   `json:"previous_id,omitempty"`
	PreviousModule       string   `json:"previous_module,omitempty"`
	PreviousModuleSHA256 string   `json:"previous_module_sha256,omitempty"`
	PreviousPackage      string   `json:"previous_package,omitempty"`
	PreviousQuery        string   `json:"previous_query,omitempty"`
}

type policyVersionRolledBackEvent struct {
	ID                     string   `json:"id"`
	Kind                   string   `json:"kind"`
	Reason                 string   `json:"reason"`
	EvidenceRefs           []string `json:"evidence_refs,omitempty"`
	RolledBackBy           string   `json:"rolled_back_by,omitempty"`
	RollbackToID           string   `json:"rollback_to_id"`
	RollbackToModule       string   `json:"rollback_to_module"`
	RollbackToModuleSHA256 string   `json:"rollback_to_module_sha256"`
	RollbackToPackage      string   `json:"rollback_to_package"`
	RollbackToQuery        string   `json:"rollback_to_query"`
}

type policyVersionResponse struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id"`
	Kind           string     `json:"kind"`
	Module         string     `json:"module,omitempty"`
	ModuleSHA256   string     `json:"module_sha256"`
	Package        string     `json:"package"`
	Query          string     `json:"query"`
	Description    string     `json:"description,omitempty"`
	ChangeRef      string     `json:"change_ref,omitempty"`
	EvidenceRefs   []string   `json:"evidence_refs"`
	Status         string     `json:"status"`
	Active         bool       `json:"active"`
	CreatedBy      string     `json:"created_by,omitempty"`
	ActivatedBy    string     `json:"activated_by,omitempty"`
	CreatedAt      *time.Time `json:"created_at,omitempty"`
	ActivatedAt    *time.Time `json:"activated_at,omitempty"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
	RolledBackAt   *time.Time `json:"rolled_back_at,omitempty"`
	RollbackFromID string     `json:"rollback_from_id,omitempty"`
	RollbackToID   string     `json:"rollback_to_id,omitempty"`
	AuditEvent     string     `json:"audit_event,omitempty"`
	IdempotencyKey string     `json:"idempotency_key,omitempty"`

	previousID     string
	previousModule string
	previousInfo   policy.ModuleInfo
}

type policyVersionListResponse struct {
	Items  []policyVersionResponse  `json:"items"`
	Active *policyVersionResponse   `json:"active,omitempty"`
	Counts policyVersionListSummary `json:"counts"`
}

type policyVersionListSummary struct {
	Total      int `json:"total"`
	Active     int `json:"active"`
	Draft      int `json:"draft"`
	Inactive   int `json:"inactive"`
	RolledBack int `json:"rolled_back"`
}

type policyVersionState struct {
	items        map[string]*policyVersionResponse
	order        []string
	activeByKind map[string]string
}

type liveLifecyclePolicy interface {
	PrepareModule(module string) (*policy.Engine, policy.ModuleInfo, string, error)
	InstallPrepared(eng *policy.Engine, info policy.ModuleInfo, module string)
	ActiveModule() (string, policy.ModuleInfo)
}

//trstctl:mutation
func (a *API) createPolicyVersion(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		live, ok := a.liveLifecyclePolicy()
		if !ok {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "live lifecycle policy activation is not configured")
		}
		var req policyVersionCreateRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		kind, err := normalizePolicyVersionKind(req.Kind)
		if err != nil {
			return 0, nil, err
		}
		id, err := normalizePolicyVersionID(req.ID)
		if err != nil {
			return 0, nil, err
		}
		req.Module = strings.TrimSpace(req.Module)
		if req.Module == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "module is required")
		}
		refs, err := normalizePolicyEvidenceRefs(req.EvidenceRefs)
		if err != nil {
			return 0, nil, err
		}
		state, err := a.policyVersions(ctx, tenantID)
		if err != nil {
			return 0, nil, err
		}
		if _, exists := state.items[id]; exists {
			return 0, nil, errStatus(http.StatusConflict, "policy version already exists")
		}
		_, info, module, err := live.PrepareModule(req.Module)
		if err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		author := ""
		if actor, ok := events.ActorFromContext(ctx); ok {
			author = actor.Subject
		}
		payload, err := json.Marshal(policyVersionAuthoredEvent{
			ID: id, Kind: string(kind), Module: module, ModuleSHA256: info.ModuleSHA256,
			Package: info.Package, Query: info.Query, Description: trimPolicyText(req.Description, 500),
			ChangeRef: trimPolicyText(req.ChangeRef, 260), EvidenceRefs: refs, Author: author,
		})
		if err != nil {
			return 0, nil, err
		}
		ev, err := a.appendPolicyVersionEvent(ctx, tenantID, policyVersionAuthoredEventType, payload)
		if err != nil {
			return 0, nil, err
		}
		resp := policyVersionResponse{
			ID: id, TenantID: tenantID, Kind: string(kind), Module: module,
			ModuleSHA256: info.ModuleSHA256, Package: info.Package, Query: info.Query,
			Description: trimPolicyText(req.Description, 500), ChangeRef: trimPolicyText(req.ChangeRef, 260),
			EvidenceRefs: refs, Status: "draft", CreatedBy: author, CreatedAt: &ev.Time,
			UpdatedAt: &ev.Time, AuditEvent: policyVersionAuthoredEventType, IdempotencyKey: idempotencyKey,
		}
		return http.StatusCreated, resp, nil
	})
}

func (a *API) listPolicyVersions(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	state, err := a.policyVersions(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]policyVersionResponse, 0, len(state.order))
	for _, id := range state.order {
		if rec := state.items[id]; rec != nil {
			items = append(items, policyVersionPublic(*rec))
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		return policyVersionSortTime(items[i]).Before(policyVersionSortTime(items[j]))
	})
	summary := policyVersionListSummary{Total: len(items)}
	var active *policyVersionResponse
	for i := range items {
		switch items[i].Status {
		case "active":
			summary.Active++
		case "draft":
			summary.Draft++
		case "inactive":
			summary.Inactive++
		case "rolled_back":
			summary.RolledBack++
		}
		if items[i].Active {
			copy := items[i]
			active = &copy
		}
	}
	a.writeJSON(w, http.StatusOK, policyVersionListResponse{Items: items, Active: active, Counts: summary})
}

//trstctl:mutation
func (a *API) activatePolicyVersion(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := strings.TrimSpace(r.PathValue("id"))
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		live, ok := a.liveLifecyclePolicy()
		if !ok {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "live lifecycle policy activation is not configured")
		}
		req, err := decodePolicyVersionActionRequest(r, "activation reason is required")
		if err != nil {
			return 0, nil, err
		}
		state, err := a.policyVersions(ctx, tenantID)
		if err != nil {
			return 0, nil, err
		}
		rec := state.items[id]
		if rec == nil {
			return 0, nil, errStatus(http.StatusNotFound, "policy version not found")
		}
		if rec.Kind != string(policy.DryRunKindLifecycle) {
			return 0, nil, errStatus(http.StatusBadRequest, "only lifecycle policy versions can be activated")
		}
		eng, info, module, err := live.PrepareModule(rec.Module)
		if err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		previousModule, previousInfo := live.ActiveModule()
		previousID := state.activeByKind[rec.Kind]
		if previousID == "" {
			previousID = policyVersionBootID
		}
		actor := ""
		if evActor, ok := events.ActorFromContext(ctx); ok {
			actor = evActor.Subject
		}
		payload, err := json.Marshal(policyVersionActivatedEvent{
			ID: id, Kind: rec.Kind, Reason: req.Reason, EvidenceRefs: req.EvidenceRefs, ActivatedBy: actor,
			PreviousID: previousID, PreviousModule: previousModule, PreviousModuleSHA256: previousInfo.ModuleSHA256,
			PreviousPackage: previousInfo.Package, PreviousQuery: previousInfo.Query,
		})
		if err != nil {
			return 0, nil, err
		}
		ev, err := a.appendPolicyVersionEvent(ctx, tenantID, policyVersionActivatedEventType, payload)
		if err != nil {
			return 0, nil, err
		}
		live.InstallPrepared(eng, info, module)
		out := policyVersionPublic(*rec)
		out.Module = module
		out.ModuleSHA256 = info.ModuleSHA256
		out.Package = info.Package
		out.Query = info.Query
		out.Status = "active"
		out.Active = true
		out.ActivatedBy = actor
		out.ActivatedAt = &ev.Time
		out.UpdatedAt = &ev.Time
		out.AuditEvent = policyVersionActivatedEventType
		out.IdempotencyKey = idempotencyKey
		return http.StatusOK, out, nil
	})
}

//trstctl:mutation
func (a *API) rollbackPolicyVersion(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := strings.TrimSpace(r.PathValue("id"))
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		live, ok := a.liveLifecyclePolicy()
		if !ok {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "live lifecycle policy activation is not configured")
		}
		req, err := decodePolicyVersionActionRequest(r, "rollback reason is required")
		if err != nil {
			return 0, nil, err
		}
		state, err := a.policyVersions(ctx, tenantID)
		if err != nil {
			return 0, nil, err
		}
		rec := state.items[id]
		if rec == nil {
			return 0, nil, errStatus(http.StatusNotFound, "policy version not found")
		}
		if !rec.Active || rec.Status != "active" {
			return 0, nil, errStatus(http.StatusConflict, "only the active policy version can be rolled back")
		}
		if strings.TrimSpace(rec.previousModule) == "" {
			return 0, nil, errStatus(http.StatusConflict, "active policy version has no rollback target")
		}
		eng, info, module, err := live.PrepareModule(rec.previousModule)
		if err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, "rollback target no longer compiles: "+err.Error())
		}
		rollbackToID := guuid.NewString()
		actor := ""
		if evActor, ok := events.ActorFromContext(ctx); ok {
			actor = evActor.Subject
		}
		payload, err := json.Marshal(policyVersionRolledBackEvent{
			ID: id, Kind: rec.Kind, Reason: req.Reason, EvidenceRefs: req.EvidenceRefs, RolledBackBy: actor,
			RollbackToID: rollbackToID, RollbackToModule: module, RollbackToModuleSHA256: info.ModuleSHA256,
			RollbackToPackage: info.Package, RollbackToQuery: info.Query,
		})
		if err != nil {
			return 0, nil, err
		}
		ev, err := a.appendPolicyVersionEvent(ctx, tenantID, policyVersionRolledBackEventType, payload)
		if err != nil {
			return 0, nil, err
		}
		live.InstallPrepared(eng, info, module)
		out := policyVersionPublic(*rec)
		out.Status = "rolled_back"
		out.Active = false
		out.RollbackFromID = id
		out.RollbackToID = rollbackToID
		out.RolledBackAt = &ev.Time
		out.UpdatedAt = &ev.Time
		out.AuditEvent = policyVersionRolledBackEventType
		out.IdempotencyKey = idempotencyKey
		return http.StatusOK, out, nil
	})
}

func (a *API) liveLifecyclePolicy() (liveLifecyclePolicy, bool) {
	live, ok := a.gate.Policy.(liveLifecyclePolicy)
	return live, ok
}

func (a *API) appendPolicyVersionEvent(ctx context.Context, tenantID, eventType string, payload []byte) (events.Event, error) {
	if a.log == nil {
		return events.Event{}, errStatus(http.StatusServiceUnavailable, "policy version event log is not configured")
	}
	return a.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: payload})
}

func (a *API) policyVersions(ctx context.Context, tenantID string) (*policyVersionState, error) {
	if a.log == nil {
		return nil, errStatus(http.StatusServiceUnavailable, "policy version event log is not configured")
	}
	state := &policyVersionState{items: map[string]*policyVersionResponse{}, activeByKind: map[string]string{}}
	err := a.log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.TenantID != tenantID {
			return nil
		}
		switch ev.Type {
		case policyVersionAuthoredEventType:
			var pl policyVersionAuthoredEvent
			if err := json.Unmarshal(ev.Data, &pl); err != nil {
				return fmt.Errorf("policy version authored event: %w", err)
			}
			if pl.ID == "" || pl.Kind == "" || pl.ModuleSHA256 == "" {
				return fmt.Errorf("policy version authored event is missing id, kind, or module hash")
			}
			createdAt := ev.Time
			rec := &policyVersionResponse{
				ID: pl.ID, TenantID: ev.TenantID, Kind: pl.Kind, Module: pl.Module,
				ModuleSHA256: pl.ModuleSHA256, Package: pl.Package, Query: pl.Query,
				Description: pl.Description, ChangeRef: pl.ChangeRef, EvidenceRefs: cloneStrings(pl.EvidenceRefs),
				Status: "draft", CreatedBy: pl.Author, CreatedAt: &createdAt, UpdatedAt: &createdAt,
			}
			if _, exists := state.items[pl.ID]; !exists {
				state.order = append(state.order, pl.ID)
			}
			state.items[pl.ID] = rec
		case policyVersionActivatedEventType:
			var pl policyVersionActivatedEvent
			if err := json.Unmarshal(ev.Data, &pl); err != nil {
				return fmt.Errorf("policy version activated event: %w", err)
			}
			rec := state.items[pl.ID]
			if rec == nil {
				return fmt.Errorf("policy version activation references unknown version %q", pl.ID)
			}
			if activeID := state.activeByKind[pl.Kind]; activeID != "" && activeID != rec.ID {
				if active := state.items[activeID]; active != nil && active.Status == "active" {
					active.Status = "inactive"
					active.Active = false
					active.UpdatedAt = timePtr(ev.Time)
				}
			}
			rec.Status = "active"
			rec.Active = true
			rec.ActivatedBy = pl.ActivatedBy
			rec.ActivatedAt = timePtr(ev.Time)
			rec.UpdatedAt = timePtr(ev.Time)
			rec.previousID = pl.PreviousID
			rec.previousModule = pl.PreviousModule
			rec.previousInfo = policy.ModuleInfo{Kind: policy.DryRunKind(pl.Kind), ModuleSHA256: pl.PreviousModuleSHA256, Package: pl.PreviousPackage, Query: pl.PreviousQuery}
			state.activeByKind[pl.Kind] = rec.ID
		case policyVersionRolledBackEventType:
			var pl policyVersionRolledBackEvent
			if err := json.Unmarshal(ev.Data, &pl); err != nil {
				return fmt.Errorf("policy version rolled-back event: %w", err)
			}
			if rec := state.items[pl.ID]; rec != nil {
				rec.Status = "rolled_back"
				rec.Active = false
				rec.RollbackToID = pl.RollbackToID
				rec.RolledBackAt = timePtr(ev.Time)
				rec.UpdatedAt = timePtr(ev.Time)
			}
			if activeID := state.activeByKind[pl.Kind]; activeID != "" && activeID != pl.ID {
				if active := state.items[activeID]; active != nil && active.Status == "active" {
					active.Status = "inactive"
					active.Active = false
					active.UpdatedAt = timePtr(ev.Time)
				}
			}
			target := &policyVersionResponse{
				ID: pl.RollbackToID, TenantID: ev.TenantID, Kind: pl.Kind, Module: pl.RollbackToModule,
				ModuleSHA256: pl.RollbackToModuleSHA256, Package: pl.RollbackToPackage, Query: pl.RollbackToQuery,
				Description: "Rollback target for " + pl.ID, EvidenceRefs: cloneStrings(pl.EvidenceRefs),
				Status: "active", Active: true, CreatedBy: pl.RolledBackBy, ActivatedBy: pl.RolledBackBy,
				CreatedAt: timePtr(ev.Time), ActivatedAt: timePtr(ev.Time), UpdatedAt: timePtr(ev.Time),
				RollbackFromID: pl.ID,
			}
			if _, exists := state.items[target.ID]; !exists {
				state.order = append(state.order, target.ID)
			}
			state.items[target.ID] = target
			state.activeByKind[pl.Kind] = target.ID
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return state, nil
}

func policyVersionPublic(in policyVersionResponse) policyVersionResponse {
	in.previousID = ""
	in.previousModule = ""
	in.previousInfo = policy.ModuleInfo{}
	in.EvidenceRefs = cloneStrings(in.EvidenceRefs)
	return in
}

func decodePolicyVersionActionRequest(r *http.Request, missingReason string) (policyVersionActionRequest, error) {
	var req policyVersionActionRequest
	if err := decodeJSON(r, &req); err != nil {
		return policyVersionActionRequest{}, errWithStatus(http.StatusBadRequest, err)
	}
	req.Reason = trimPolicyText(req.Reason, 500)
	if req.Reason == "" {
		return policyVersionActionRequest{}, errStatus(http.StatusBadRequest, missingReason)
	}
	refs, err := normalizePolicyEvidenceRefs(req.EvidenceRefs)
	if err != nil {
		return policyVersionActionRequest{}, err
	}
	req.EvidenceRefs = refs
	return req, nil
}

func normalizePolicyVersionKind(kind string) (policy.DryRunKind, error) {
	switch policy.DryRunKind(strings.TrimSpace(kind)) {
	case "", policy.DryRunKindLifecycle:
		return policy.DryRunKindLifecycle, nil
	default:
		return "", errStatus(http.StatusBadRequest, "live activation currently supports lifecycle policy versions")
	}
}

func normalizePolicyVersionID(id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return guuid.NewString(), nil
	}
	if _, err := guuid.Parse(id); err != nil {
		return "", errStatus(http.StatusBadRequest, "id must be a UUID")
	}
	return id, nil
}

func normalizePolicyEvidenceRefs(refs []string) ([]string, error) {
	out := make([]string, 0, len(refs))
	seen := map[string]bool{}
	for _, ref := range refs {
		ref = trimPolicyText(ref, 260)
		if ref == "" {
			return nil, errStatus(http.StatusBadRequest, "evidence_refs values must be non-empty strings")
		}
		if !seen[ref] {
			out = append(out, ref)
			seen[ref] = true
		}
	}
	if len(out) > 30 {
		return nil, errStatus(http.StatusBadRequest, "evidence_refs accepts at most 30 values")
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

func trimPolicyText(s string, max int) string {
	s = strings.TrimSpace(s)
	if max > 0 && len(s) > max {
		return s[:max]
	}
	return s
}

func policyVersionSortTime(v policyVersionResponse) time.Time {
	if v.CreatedAt != nil {
		return *v.CreatedAt
	}
	if v.UpdatedAt != nil {
		return *v.UpdatedAt
	}
	return time.Time{}
}

func timePtr(t time.Time) *time.Time {
	out := t
	return &out
}

func cloneStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return append([]string(nil), in...)
}
