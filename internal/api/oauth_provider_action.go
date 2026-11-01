// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/discovery/oauthgrant"
	"trstctl.com/trstctl/internal/oauthrevoke"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// OAuth provider actions on discovered grants (A170, A171). An operator who
// decides a grant discovery found is abusive revokes it at the identity or
// SaaS provider, or blocks the application there so no one can grant it again.
// Both go through the admin connection the finding's source names; the
// finding records the request and then what the provider confirmed.

// OAuthProviderActionRequest is the operator's reason for the action.
type OAuthProviderActionRequest struct {
	Reason string `json:"reason,omitempty"`
}

type oauthProviderActionResponse struct {
	RequestID string `json:"request_id"`
	FindingID string `json:"finding_id"`
	Action    string `json:"action"`
	Provider  string `json:"provider"`
	AppID     string `json:"app_id"`
	Principal string `json:"principal,omitempty"`
	Status    string `json:"status"`
}

func (a *API) oauthProviderActionRoutes() []route {
	idPath := []param{pathUUID("id")}
	return []route{
		{method: "POST", path: "/api/v1/discovery/findings/{id}/oauth-grant/revoke", opID: "revokeOAuthGrantAtProvider",
			summary: "Revoke at the identity or SaaS provider the OAuth grant a discovery finding names",
			handler: a.revokeOAuthGrantAtProvider, pathParams: idPath, reqSchema: "OAuthProviderActionRequest", reqOptional: true,
			resSchema: "OAuthProviderActionResult", successCode: "202", mutation: true, perm: authz.ConnectorsWrite},
		{method: "POST", path: "/api/v1/discovery/findings/{id}/oauth-grant/block", opID: "blockOAuthAppAtProvider",
			summary: "Block at the identity or SaaS provider the application a discovery finding's OAuth grant names",
			handler: a.blockOAuthAppAtProvider, pathParams: idPath, reqSchema: "OAuthProviderActionRequest", reqOptional: true,
			resSchema: "OAuthProviderActionResult", successCode: "202", mutation: true, perm: authz.ConnectorsWrite},
	}
}

//trstctl:mutation
func (a *API) revokeOAuthGrantAtProvider(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	binding, run, ok := a.oauthProviderAction(w, r, idempotencyKey, orchestrator.OAuthActionRevokeGrant)
	if !ok {
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, binding, run)
}

//trstctl:mutation
func (a *API) blockOAuthAppAtProvider(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	binding, run, ok := a.oauthProviderAction(w, r, idempotencyKey, orchestrator.OAuthActionBlockApp)
	if !ok {
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, binding, run)
}

// oauthProviderAction decodes the request and returns the request binding
// and the durable mutation that queues the action. It writes the error and
// reports false when the request is malformed.
func (a *API) oauthProviderAction(w http.ResponseWriter, r *http.Request, idempotencyKey, action string) (string, func(context.Context, string) (int, any, error), bool) {
	findingID := r.PathValue("id")
	var request OAuthProviderActionRequest
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &request); err != nil {
			a.writeError(w, errWithStatus(http.StatusBadRequest, err))
			return "", nil, false
		}
	}
	request.Reason = strings.TrimSpace(request.Reason)
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	binding, err := json.Marshal(struct {
		Domain    string `json:"domain"`
		Actor     string `json:"actor"`
		FindingID string `json:"finding_id"`
		Action    string `json:"action"`
		Reason    string `json:"reason"`
	}{"trstctl.oauth-provider-action.v1", principal.Subject, findingID, action, request.Reason})
	if err != nil {
		a.writeError(w, err)
		return "", nil, false
	}
	return crypto.SHA256Hex(binding), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errors.New("OAuth provider action orchestrator is unavailable")
		}
		intent, err := a.oauthProviderActionIntent(ctx, tenantID, findingID, action, request.Reason)
		if err != nil {
			return 0, nil, err
		}
		queued, err := a.orch.QueueOAuthProviderAction(ctx, tenantID, crypto.SHA256Hex([]byte(tenantID+"\x00"+idempotencyKey)), principal.Subject, intent)
		if errors.Is(err, store.ErrIdempotencyConflict) {
			return 0, nil, errStatus(http.StatusConflict, "the finding changed after review; read it again")
		}
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, oauthProviderActionResponse{
			RequestID: queued.RequestID, FindingID: queued.FindingID, Action: queued.Action, Provider: queued.Provider,
			AppID: queued.AppID, Principal: queued.Principal, Status: orchestrator.OAuthActionQueued,
		}, nil
	}, true
}

// oauthProviderActionIntent checks the finding names an OAuth grant, its
// source can reach the provider, and the provider can perform the action.
func (a *API) oauthProviderActionIntent(ctx context.Context, tenantID, findingID, action, reason string) (orchestrator.OAuthProviderActionIntent, error) {
	finding, err := a.store.GetDiscoveryFinding(ctx, tenantID, findingID)
	if errors.Is(err, pgx.ErrNoRows) {
		return orchestrator.OAuthProviderActionIntent{}, errStatus(http.StatusNotFound, "no such discovery finding")
	}
	if err != nil {
		return orchestrator.OAuthProviderActionIntent{}, err
	}
	if finding.Kind != oauthgrant.FindingKind && finding.Kind != oauthgrant.AbuseFindingKind {
		return orchestrator.OAuthProviderActionIntent{}, errStatus(http.StatusConflict, "this finding does not name an OAuth grant")
	}
	meta := decodeNHIInventoryMetadata(finding.Metadata)
	provider, appID, user := metadataString(meta, "provider"), metadataString(meta, "app_id"), metadataString(meta, "principal")
	if oauthrevoke.NormalizeProvider(provider) == "" {
		return orchestrator.OAuthProviderActionIntent{}, errStatus(http.StatusConflict, "the grant's provider "+provider+" has no served admin API; act in its own console")
	}
	if action == orchestrator.OAuthActionRevokeGrant && user == "" {
		return orchestrator.OAuthProviderActionIntent{}, errStatus(http.StatusConflict, "the grant names no user to revoke it for; block the application instead")
	}
	if action == orchestrator.OAuthActionBlockApp && !oauthrevoke.CanBlock(provider) {
		return orchestrator.OAuthProviderActionIntent{}, errStatus(http.StatusConflict, "the provider's API cannot block an application; Google Workspace exposes app access control only in its admin console")
	}
	source, err := a.store.GetDiscoverySource(ctx, tenantID, finding.SourceID)
	if err != nil {
		return orchestrator.OAuthProviderActionIntent{}, errStatus(http.StatusConflict, "the discovery source that found this grant is gone")
	}
	if _, found, err := oauthgrant.Connection(source.Config, provider); err != nil || !found {
		return orchestrator.OAuthProviderActionIntent{}, errStatus(http.StatusConflict,
			"the source that found this grant has no admin connection for "+provider+"; add one under providers[] with a token reference")
	}
	return orchestrator.OAuthProviderActionIntent{
		FindingID: finding.ID, SourceID: finding.SourceID, Action: action, Provider: oauthrevoke.NormalizeProvider(provider),
		AppID: appID, Principal: user, Reason: reason,
	}, nil
}
