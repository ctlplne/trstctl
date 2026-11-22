// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
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
	// A rule approves future requests in reviewers' place (CR-001), so
	// changing one is approval authority as well as access configuration.
	authority := []conditionalPermission{{Permission: authz.AccessApprove, When: "every rule change: a rule approves requests in reviewers' place, so its author must be able to approve access; a token minted for its subject by someone else, or an access bundle run, is refused with 403"}}
	return []route{
		{method: "GET", path: "/api/v1/access/auto-approval-rules", opID: "listPAMAutoApprovalRules", summary: "List automatic access reviews in rule ID order", handler: a.listPAMAutoApprovalRules, resSchema: "PAMAutoApprovalRuleList", successCode: "200", perm: authz.AccessRead},
		{method: "PUT", path: "/api/v1/access/auto-approval-rules/{id}", opID: "savePAMAutoApprovalRule", summary: "Save a scoped automatic access review rule at the revision read; needs access:approve too (a rule never approves its author's own requests)", handler: a.savePAMAutoApprovalRule, pathParams: id, reqSchema: "PAMAutoApprovalRuleRequest", resSchema: "PAMAutoApprovalRule", successCode: "200", mutation: true, perm: authz.AccessWrite, alsoRequires: authority},
		{method: "DELETE", path: "/api/v1/access/auto-approval-rules/{id}", opID: "deletePAMAutoApprovalRule", summary: "Delete an automatic review rule at the revision read; needs access:approve too", handler: a.deletePAMAutoApprovalRule, pathParams: id, query: []param{{required: true, name: "revision", typ: "integer", desc: "the rule revision read"}}, resSchema: "PAMAutoApprovalRuleDeleted", successCode: "200", mutation: true, perm: authz.AccessWrite, alsoRequires: authority},
	}
}

// autoApprovalRuleDelegatedRefusal explains why a delegated token cannot change
// a rule (F262).
const autoApprovalRuleDelegatedRefusal = "this API token was minted for its subject by another person, so it cannot change the rules that approve in reviewers' place; use your own sign-in or a token you minted yourself"

// admitAutoApprovalRuleAuthor refuses, as the approval routes refuse a
// delegated vote (F262), a principal that may not approve in reviewers'
// place (CR-001). A rule approves future requests without a reviewer, so
// changing one needs access:approve as well as the route's access:write, as
// granting an access bundle's standing approval does (OD-9); a token one
// person minted for another subject, and an access bundle run, never may.
// The refusal is recorded like the route guard's own. It reports whether the
// change may go on.
func (a *API) admitAutoApprovalRuleAuthor(w http.ResponseWriter, r *http.Request) bool {
	principal, ok := r.Context().Value(principalCtxKey).(authz.Principal)
	if !ok || principal.TenantID == "" || principal.Subject == "" {
		a.writeProblem(w, problemUnauthorized())
		return false
	}
	var detail, reason string
	switch {
	case principal.Delegated:
		detail, reason = autoApprovalRuleDelegatedRefusal, "delegated API token cannot change automatic approval rules"
	case principal.RunID != "":
		detail, reason = "an access bundle run cannot change automatic approval rules", "access bundle run cannot change automatic approval rules"
	case !principal.Can(authz.AccessApprove, authz.Scope{TenantID: principal.TenantID}):
		detail, reason = "an automatic approval rule approves in reviewers' place: changing one needs access:approve as well as access:write", "automatic approval rule changes need access:approve"
	default:
		return true
	}
	w.Header().Set("X-Trstctl-Audit-Status", a.denialAudit.recordReason(r, principal, authz.AccessApprove, reason))
	a.writeProblem(w, problem.New(http.StatusForbidden, detail))
	return false
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
	if !a.admitAutoApprovalRuleAuthor(w, r) {
		return
	}
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
	if !a.admitAutoApprovalRuleAuthor(w, r) {
		return
	}
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
