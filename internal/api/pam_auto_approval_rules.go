// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/store"
)

// PAMAutoApprovalWindow uses the named time zone's local day and clock. The
// start is inclusive, the end exclusive; overnight windows use two rules.
type PAMAutoApprovalWindow struct {
	Days     []string `json:"days,omitempty"`
	Start    string   `json:"start"`
	End      string   `json:"end"`
	TimeZone string   `json:"time_zone"`
}

// PAMAutoApprovalRule grants one recorded review only when every nonempty
// criterion matches. A rule always has an explicit target scope.
type PAMAutoApprovalRule struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	AppliesTo      []string               `json:"applies_to"`
	TargetTypes    []string               `json:"target_types,omitempty"`
	TargetIDs      []string               `json:"target_ids,omitempty"`
	Folders        []string               `json:"folders,omitempty"`
	RequesterRoles []string               `json:"requester_roles,omitempty"`
	Window         *PAMAutoApprovalWindow `json:"window,omitempty"`
	TicketPattern  string                 `json:"ticket_pattern,omitempty"`
	MaxTTLSeconds  int                    `json:"max_ttl_seconds"`
	Enabled        bool                   `json:"enabled"`
	Revision       int64                  `json:"revision"`
	SavedBy        string                 `json:"saved_by,omitempty"`
	SavedAt        time.Time              `json:"saved_at"`
}

type PAMAutoApprovalRuleService interface {
	SavePAMAutoApprovalRule(context.Context, string, string, PAMAutoApprovalRule) (PAMAutoApprovalRule, error)
	ListPAMAutoApprovalRules(context.Context, string) ([]PAMAutoApprovalRule, error)
	DeletePAMAutoApprovalRule(context.Context, string, string, string, int64) error
}

func (a *API) pamAutoApprovalRuleRoutes() []route {
	id := []param{pathString("id", "rule UUID")}
	return []route{
		{method: "GET", path: "/api/v1/access/auto-approval-rules", opID: "listPAMAutoApprovalRules", summary: "List automatic access reviews in rule ID order", handler: a.listPAMAutoApprovalRules, resSchema: "PAMAutoApprovalRuleList", successCode: "200", perm: authz.AccessRead},
		{method: "PUT", path: "/api/v1/access/auto-approval-rules/{id}", opID: "savePAMAutoApprovalRule", summary: "Save a scoped automatic access review rule at the revision read", handler: a.savePAMAutoApprovalRule, pathParams: id, reqSchema: "PAMAutoApprovalRuleRequest", resSchema: "PAMAutoApprovalRule", successCode: "200", mutation: true, perm: authz.AccessWrite},
		{method: "DELETE", path: "/api/v1/access/auto-approval-rules/{id}", opID: "deletePAMAutoApprovalRule", summary: "Delete an automatic review rule at the revision read", handler: a.deletePAMAutoApprovalRule, pathParams: id, query: []param{{name: "revision", typ: "integer", desc: "the rule revision read"}}, resSchema: "PAMAutoApprovalRuleDeleted", successCode: "200", mutation: true, perm: authz.AccessWrite},
	}
}
func (a *API) autoApprovalRules() (PAMAutoApprovalRuleService, error) {
	svc, ok := a.pam.(PAMAutoApprovalRuleService)
	if a.pam == nil || !ok {
		return nil, ErrPAMUnavailable
	}
	return svc, nil
}
func pamAutoApprovalRuleError(err error) error {
	if errors.Is(err, store.ErrPAMAutoApprovalRuleNotFound) {
		return errStatus(http.StatusNotFound, "automatic approval rule not found")
	}
	return err
}
func (a *API) listPAMAutoApprovalRules(w http.ResponseWriter, r *http.Request) {
	svc, err := a.autoApprovalRules()
	if err != nil {
		a.writePAMError(w, err)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	items, err := svc.ListPAMAutoApprovalRules(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

//trstctl:mutation
func (a *API) savePAMAutoApprovalRule(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.autoApprovalRules()
		if err != nil {
			return 0, nil, err
		}
		var body PAMAutoApprovalRule
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		body.ID = r.PathValue("id")
		saved, err := svc.SavePAMAutoApprovalRule(ctx, tenantID, principal.Subject, body)
		if err != nil {
			return 0, nil, pamAutoApprovalRuleError(err)
		}
		return http.StatusOK, saved, nil
	})
}

//trstctl:mutation
func (a *API) deletePAMAutoApprovalRule(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		svc, err := a.autoApprovalRules()
		if err != nil {
			return 0, nil, err
		}
		revision, err := strconv.ParseInt(r.URL.Query().Get("revision"), 10, 64)
		if err != nil || revision < 1 {
			return 0, nil, errStatus(http.StatusBadRequest, "revision must be the rule revision read")
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if err := svc.DeletePAMAutoApprovalRule(ctx, tenantID, principal.Subject, r.PathValue("id"), revision); err != nil {
			return 0, nil, pamAutoApprovalRuleError(err)
		}
		return http.StatusOK, map[string]any{"id": r.PathValue("id"), "deleted": true}, nil
	})
}
