// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"strconv"

	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/authz"
)

type PAMCommandAction struct {
	accessrules.Decision
	SourceEventID        string `json:"source_event_id"`
	ApprovalRequestID    string `json:"approval_request_id,omitempty"`
	ApprovalIntentDigest string `json:"approval_intent_digest,omitempty"`
	EffectiveStatus      string `json:"effective_status"`
}
type PAMCommandActionList struct {
	Items      []PAMCommandAction `json:"items"`
	NextCursor string             `json:"next_cursor,omitempty"`
}
type PAMCommandActionService interface {
	ListPAMCommandActions(context.Context, string, string, int, string) ([]PAMCommandAction, string, error)
}

func (a *API) pamCommandRuleRoutes() []route {
	return []route{{method: "GET", path: "/api/v1/access/sessions/{id}/actions", opID: "listPAMCommandActions", summary: "List bounded command-rule decisions for a session, without statement text, arguments or credentials", handler: a.listPAMCommandActions, pathParams: []param{pathUUID("id")}, query: []param{{name: "limit", typ: "integer", desc: "page size, 1-100; default 50"}, {name: "cursor", typ: "string", desc: "next_cursor from the previous page"}}, resSchema: "PAMCommandActionList", successCode: "200", perm: authz.AccessRead}}
}

func (a *API) listPAMCommandActions(w http.ResponseWriter, r *http.Request) {
	svc, ok := a.pam.(PAMCommandActionService)
	if a.pam == nil || !ok {
		a.writeError(w, ErrPAMUnavailable)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit := 50
	if value := r.URL.Query().Get("limit"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 100 {
			a.writeError(w, errStatus(http.StatusBadRequest, "limit must be 1-100"))
			return
		}
		limit = n
	}
	cursor := r.URL.Query().Get("cursor")
	if len(cursor) > 256 {
		a.writeError(w, errStatus(http.StatusBadRequest, "cursor is too long"))
		return
	}
	items, next, err := svc.ListPAMCommandActions(r.Context(), tenantID, r.PathValue("id"), limit, cursor)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, PAMCommandActionList{Items: items, NextCursor: next})
}

func pamCommandRuleSchema(frozen bool) *Schema {
	properties := map[string]*Schema{"id": uuid(), "protocol": {Type: "string", Enum: []string{"postgres", "ssh", "mysql", "redis", "mongodb", "clickhouse", "netdevice"}}, "operations": {Type: "array", Items: &Schema{Type: "string", Enum: accessrules.AllOperationNames()}, Description: "Protocol-specific public selectors: uppercase SQL operations, lowercase direct SSH program names, or lowercase network device command verbs (an abbreviation names every verb it starts). Arguments and quoted nested commands are excluded"}, "effect": {Type: "string", Enum: []string{"block", "require_approval", "alert"}}}
	properties["required_approvals"] = &Schema{Type: "integer", Description: "require_approval only: 1-3 distinct humans; requester cannot approve"}
	properties["review_ttl_seconds"] = &Schema{Type: "integer", Description: "require_approval only: 5-45 seconds; session expiry can shorten this deadline"}
	properties["severity"] = &Schema{Type: "string", Enum: []string{"warning", "critical"}, Description: "alert only (A275): the matching command runs once its decision is durable and raises a risk alert of this severity, linking the session's recording"}
	required := []string{"id", "protocol", "operations", "effect"}
	if !frozen {
		properties["name"] = str()
		properties["enabled"] = &Schema{Type: "boolean"}
		required = append(required, "name", "enabled")
	}
	return object(properties, required...)
}

func pamCommandPolicySchema() *Schema {
	return object(map[string]*Schema{"version": {Type: "integer", Description: "frozen command policy format, currently 1"}, "template_id": uuid(), "template_revision": {Type: "integer"}, "rules": {Type: "array", Items: ref("PAMFrozenCommandRule")}}, "version", "template_id", "template_revision", "rules")
}

func pamCommandActionSchema() *Schema {
	return object(map[string]*Schema{
		"id": uuid(), "session_id": uuid(), "job_id": {Type: "integer"}, "attempt": {Type: "integer"}, "protocol": str(),
		"connection_id": uuid(), "ordinal": {Type: "integer"}, "phase": str(), "rule_ids": {Type: "array", Items: uuid()},
		"operations":       {Type: "array", Items: &Schema{Type: "string", Enum: accessrules.AllOperationNames()}},
		"effective_status": {Type: "string", Enum: []string{"blocked", "pending", "authorized", "denied", "expired", "canceled", "alerted", "review_deadline_elapsed"}, Description: "Current view of the recorded decision; an elapsed pending deadline never grants authority and does not invent a terminal event"},
		"message_digest":   str(), "policy_digest": str(), "status": {Type: "string", Enum: []string{"blocked", "pending", "authorized", "denied", "expired", "canceled", "alerted"}}, "reason": {Type: "string", Enum: []string{"matched_rule", "matched_alert_rule", "unsupported_control", "uninspectable", "review_required", "review_approved", "review_denied", "review_expired", "client_canceled", "session_ended"}},
		"decided_at": {Type: "string", Format: "date-time", Description: "time of the durable gateway decision; authorized does not claim target execution"}, "observed_at": {Type: "string", Format: "date-time"}, "review_expires_at": {Type: "string", Format: "date-time"}, "source_event_id": uuid(),
		"approval_request_id": uuid(), "approval_intent_digest": str(),
	}, "id", "session_id", "job_id", "attempt", "protocol", "connection_id", "ordinal", "phase", "rule_ids", "message_digest", "policy_digest", "operations", "effective_status", "status", "reason", "decided_at", "observed_at", "source_event_id")
}
