// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	googleuuid "github.com/google/uuid"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/cloudentitlements/change"
	"trstctl.com/trstctl/internal/store"
)

type CloudMachineChangeRequest struct {
	FindingID            string `json:"finding_id"`
	Action               string `json:"action"`
	AccessKeyID          string `json:"access_key_id,omitempty"`
	EvaluationIndex      int    `json:"evaluation_index,omitempty"`
	WriterSessionFileRef string `json:"writer_session_file_ref"`
	Reason               string `json:"reason"`
	RequiredApprovals    int    `json:"required_approvals,omitempty"`
}
type CloudMachineChangeService interface {
	ProposeCloudMachineChange(context.Context, string, string, string, CloudMachineChangeRequest) (change.Record, error)
	ExecuteCloudMachineChange(context.Context, string, string, string) (change.Record, error)
}

func WithCloudMachineChanges(service CloudMachineChangeService) Option {
	return func(c *config) { c.cloudChanges = service }
}
func (a *API) cloudMachineChangeRoutes() []route {
	return []route{
		{method: "POST", path: "/api/v1/cloud-entitlements/changes", opID: "proposeCloudMachineChange", summary: "Propose one exact reviewed cloud machine change", handler: a.proposeCloudMachineChange, reqSchema: "CloudMachineChangeRequest", resSchema: "CloudMachineChange", successCode: "201", mutation: true, perm: authz.AccessWrite},
		{method: "GET", path: "/api/v1/cloud-entitlements/changes", opID: "listCloudMachineChanges", summary: "List captured cloud machine change intents and native results", handler: a.listCloudMachineChanges, resSchema: "CloudMachineChangeList", query: []param{{name: "limit", typ: "integer"}, {name: "cursor"}, {name: "finding_id"}}, successCode: "200", perm: authz.AccessRead},
		{method: "GET", path: "/api/v1/cloud-entitlements/changes/{id}", opID: "getCloudMachineChange", summary: "Read one cloud machine change and its native postcondition", handler: a.getCloudMachineChange, resSchema: "CloudMachineChange", successCode: "200", perm: authz.AccessRead},
		{method: "POST", path: "/api/v1/cloud-entitlements/changes/{id}/execute", opID: "executeCloudMachineChange", summary: "Consume exact human approval and queue the captured cloud intent", handler: a.executeCloudMachineChange, resSchema: "CloudMachineChange", successCode: "202", mutation: true, perm: authz.AccessWrite},
	}
}

//trstctl:mutation
func (a *API) proposeCloudMachineChange(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, key, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.cloudChanges == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "cloud machine changes are not configured")
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		if !principal.Can(authz.DiscoveryRead, authz.Scope{TenantID: tenantID}) {
			return 0, nil, errStatus(http.StatusForbidden, "cloud change proposals also require discovery:read")
		}
		var req CloudMachineChangeRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if _, err := googleuuid.Parse(req.FindingID); err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, "finding_id must be a UUID")
		}
		if req.Action != change.RevokeKey && req.Action != change.TightenPolicy {
			return 0, nil, errStatus(http.StatusBadRequest, "action must be revoke_key or tighten_policy")
		}
		if !strings.HasPrefix(req.WriterSessionFileRef, "env:") {
			return 0, nil, errStatus(http.StatusBadRequest, "writer_session_file_ref must be an operator-approved env reference")
		}
		if err := a.requireOutboundEnvCredentialRefAllowed(req.WriterSessionFileRef, "writer_session_file_ref"); err != nil {
			return 0, nil, err
		}
		req.Reason = strings.TrimSpace(req.Reason)
		if len(req.Reason) == 0 || len(req.Reason) > 500 {
			return 0, nil, errStatus(http.StatusBadRequest, "reason must contain 1 to 500 bytes")
		}
		if sourceFinding, err := a.store.GetDiscoveryFinding(ctx, tenantID, req.FindingID); err != nil {
			return 0, nil, err
		} else if source, err := a.store.GetDiscoverySource(ctx, tenantID, sourceFinding.SourceID); err != nil {
			return 0, nil, err
		} else {
			private, err := discoveryPrivateEgressRequested(source.Config)
			if err != nil {
				return 0, nil, err
			}
			if private {
				if err := a.requirePrivateEgressPermission(ctx, tenantID); err != nil {
					return 0, nil, err
				}
			}
		}
		if req.RequiredApprovals == 0 {
			req.RequiredApprovals = 2
		}
		if req.RequiredApprovals < 1 || req.RequiredApprovals > 5 {
			return 0, nil, errStatus(http.StatusBadRequest, "required_approvals must be between 1 and 5")
		}
		id := googleuuid.NewSHA1(googleuuid.NameSpaceOID, []byte("cloud-change-request\x00"+tenantID+"\x00"+key)).String()
		result, err := a.cloudChanges.ProposeCloudMachineChange(ctx, tenantID, id, principal.Subject, req)
		if err != nil {
			return 0, nil, cloudChangeError(err)
		}
		return http.StatusCreated, result, nil
	})
}
func (a *API) listCloudMachineChanges(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, errStatusFrom(http.StatusBadRequest, err))
		return
	}
	findingID := r.URL.Query().Get("finding_id")
	if findingID != "" {
		if _, err := googleuuid.Parse(findingID); err != nil {
			a.writeError(w, errStatusFrom(http.StatusBadRequest, err))
			return
		}
	}
	items, err := a.store.ListCloudMachineChangesForFinding(r.Context(), tenantID, findingID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if items == nil {
		items = []change.Record{}
	}
	cursor := ""
	if len(items) == limit {
		cursor = encodeCursor(items[len(items)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: cursor})
}
func (a *API) getCloudMachineChange(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	id, ok := a.discoveryUUIDPathID(w, r)
	if !ok {
		return
	}
	value, err := a.store.GetCloudMachineChange(r.Context(), tenantID, id)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, value)
}

//trstctl:mutation
func (a *API) executeCloudMachineChange(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, key, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.cloudChanges == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "cloud machine changes are not configured")
		}
		if _, err := googleuuid.Parse(r.PathValue("id")); err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, "id must be a UUID")
		}
		principal, _ := ctx.Value(principalCtxKey).(authz.Principal)
		plan, err := a.store.GetCloudMachineChange(ctx, tenantID, r.PathValue("id"))
		if err != nil {
			return 0, nil, err
		}
		if plan.Intent.AllowPrivateEndpoint {
			if err := a.requirePrivateEgressPermission(ctx, tenantID); err != nil {
				return 0, nil, err
			}
		}
		result, err := a.cloudChanges.ExecuteCloudMachineChange(ctx, tenantID, r.PathValue("id"), principal.Subject)
		if err != nil {
			return 0, nil, cloudChangeError(err)
		}
		return http.StatusAccepted, result, nil
	})
}
func cloudChangeError(err error) error {
	switch {
	case errors.Is(err, store.ErrApprovalNotReady), errors.Is(err, store.ErrApprovalExpired), errors.Is(err, store.ErrApprovalSuperseded), errors.Is(err, store.ErrApprovalConsumed):
		return errStatusFrom(http.StatusPreconditionRequired, err)
	case errors.Is(err, store.ErrAccessChangeActorUnauthorized):
		return errStatusFrom(http.StatusForbidden, err)
	case errors.Is(err, store.ErrIdempotencyConflict):
		return errStatusFrom(http.StatusConflict, err)
	case store.IsNotFound(err):
		return err
	default:
		return errStatusFrom(http.StatusUnprocessableEntity, err)
	}
}

func cloudMachineChangeSchemas() map[string]*Schema {
	intent := object(map[string]*Schema{
		"required_approvals": {Type: "integer"}, "action": {Type: "string", Enum: []string{change.RevokeKey, change.TightenPolicy}}, "source_id": uuid(), "finding_id": uuid(), "finding_fingerprint": str(), "source_fingerprint": str(), "principal_arn": str(), "principal_id": str(), "principal_kind": str(), "principal_name": str(), "endpoint": str(), "region": str(), "ca_pem": str(), "allow_private_endpoint": {Type: "boolean"}, "private_egress_cidrs": {Type: "array", Items: str()}, "writer_session_file_ref": str(), "access_key_id": str(), "policy_name": str(), "policy_document": {Type: "string", Format: "byte", Description: "Exact proposed public IAM policy JSON bytes"}, "policy_sha256": str(), "reason": str(),
	}, "action", "source_id", "finding_id", "finding_fingerprint", "source_fingerprint", "principal_arn", "principal_id", "principal_kind", "principal_name", "endpoint", "region", "writer_session_file_ref", "reason", "required_approvals")
	result := object(map[string]*Schema{"effect_uncertain": {Type: "boolean"}, "key_absent": {Type: "boolean"}, "policy_matches": {Type: "boolean"}, "postcondition": str(), "checked_at": timestamp(), "error": str()}, "checked_at")
	record := object(map[string]*Schema{"id": uuid(), "tenant_id": uuid(), "intent": ref("CloudMachineChangeIntent"), "state": {Type: "string", Enum: []string{change.AwaitingApproval, change.Queued, change.Verified, change.Failed}}, "approval_request_id": uuid(), "intent_digest": str(), "requested_by": str(), "created_at": timestamp(), "updated_at": timestamp(), "expires_at": timestamp(), "result": ref("CloudMachineChangeResult")}, "id", "tenant_id", "intent", "state", "approval_request_id", "intent_digest", "requested_by", "created_at", "updated_at", "expires_at")
	request := object(map[string]*Schema{"finding_id": uuid(), "action": {Type: "string", Enum: []string{change.RevokeKey, change.TightenPolicy}}, "access_key_id": str(), "evaluation_index": {Type: "integer"}, "writer_session_file_ref": str(), "reason": str(), "required_approvals": {Type: "integer"}}, "finding_id", "action", "writer_session_file_ref", "reason")
	return map[string]*Schema{"CloudMachineChangeIntent": intent, "CloudMachineChangeResult": result, "CloudMachineChange": record, "CloudMachineChangeRequest": request, "CloudMachineChangeList": object(map[string]*Schema{"items": {Type: "array", Items: ref("CloudMachineChange")}, "next_cursor": str()}, "items", "next_cursor")}
}
